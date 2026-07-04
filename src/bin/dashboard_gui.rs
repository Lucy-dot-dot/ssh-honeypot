//! Live-activity dashboard for the SSH honeypot.
//!
//! Shows recent connections, auth attempts, live/ended sessions and top
//! IPs / passwords / usernames. Double-clicking an IP opens an IP report,
//! double-clicking a password opens a password report, and double-clicking
//! a session opens a detail window with the associated commands and files.
//!
//! Reports and details are rendered as floating `egui::Window` panels inside
//! the same process so the async state is shared safely.

use chrono::{DateTime, Utc};
use eframe::egui;
use ssh_honeypot::dashboard::{Dashboard, DashboardSnapshot, SessionDetail};
use ssh_honeypot::db::initialize_database_pool;
use ssh_honeypot::report::{ReportFormat, ReportGenerator};
use sqlx::PgPool;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEFAULT_DB_URL: &str = "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot";

const LINK: egui::Color32 = egui::Color32::from_rgb(96, 165, 250);
const GREEN: egui::Color32 = egui::Color32::from_rgb(80, 180, 80);
const RED: egui::Color32 = egui::Color32::from_rgb(220, 70, 70);
const GRAY: egui::Color32 = egui::Color32::GRAY;
const BLUEISH: egui::Color32 = egui::Color32::from_rgb(140, 180, 220);

#[derive(PartialEq, Clone, Copy, Debug)]
enum ReportKind {
    Ip,
    Password,
}

/// Messages sent from background tokio tasks back to the UI thread.
enum AppEvent {
    Connected(PgPool),
    ConnectionFailed(String),
    Snapshot(Result<DashboardSnapshot, String>),
    ReportReady {
        kind: ReportKind,
        query: String,
        text: String,
        isp: Option<String>,
        org: Option<String>,
    },
    ReportFailed {
        kind: ReportKind,
        query: String,
        error: String,
    },
    SessionReady {
        auth_id: String,
        result: Result<SessionDetail, String>,
    },
}

/// UI actions queued while drawing (collected, then applied once drawing is
/// finished, to avoid `&mut self` conflicts with the immutable snapshot reads).
enum Action {
    Connect,
    Refresh,
    OpenReport(ReportKind, String),
    OpenSession {
        auth_id: String,
        ip: String,
        username: String,
        start_time: Option<DateTime<Utc>>,
    },
}

/// A floating sub-window.
enum OpenWindow {
    Report {
        id: u64,
        kind: ReportKind,
        query: String,
        text: String,
        isp: Option<String>,
        org: Option<String>,
        loading: bool,
        open: bool,
    },
    Session {
        id: u64,
        auth_id: String,
        ip: String,
        username: String,
        start_time: Option<DateTime<Utc>>,
        detail: Option<SessionDetail>,
        loading: bool,
        error: Option<String>,
        open: bool,
    },
}

impl OpenWindow {
    fn id(&self) -> u64 {
        match self {
            OpenWindow::Report { id, .. } | OpenWindow::Session { id, .. } => *id,
        }
    }
    fn is_open(&self) -> bool {
        match self {
            OpenWindow::Report { open, .. } | OpenWindow::Session { open, .. } => *open,
        }
    }
    fn set_open(&mut self, value: bool) {
        match self {
            OpenWindow::Report { open, .. } | OpenWindow::Session { open, .. } => *open = value,
        }
    }
}

struct DashboardApp {
    db_url: String,
    pool: Option<PgPool>,
    /// Persistent dashboard helper — kept across refreshes so the top-N
    /// aggregate cache survives and isn't rebuilt on every poll.
    dashboard: Option<Dashboard>,
    connection_status: String,
    is_connecting: bool,

    snapshot: Option<DashboardSnapshot>,
    snapshot_error: Option<String>,
    is_loading_snapshot: bool,

    auto_refresh: bool,
    refresh_interval_secs: f32,
    last_refresh: Option<Instant>,

    open_windows: Vec<OpenWindow>,
    next_window_id: u64,

    runtime: tokio::runtime::Runtime,
    tx: mpsc::Sender<AppEvent>,
    rx: mpsc::Receiver<AppEvent>,
}

impl DashboardApp {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            db_url: DEFAULT_DB_URL.to_string(),
            pool: None,
            dashboard: None,
            connection_status: "Not connected".to_string(),
            is_connecting: false,
            snapshot: None,
            snapshot_error: None,
            is_loading_snapshot: false,
            auto_refresh: true,
            refresh_interval_secs: 10.0,
            last_refresh: None,
            open_windows: Vec::new(),
            next_window_id: 1,
            runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
            tx,
            rx,
        }
    }

    fn connect(&mut self, ctx: &egui::Context) {
        self.is_connecting = true;
        self.pool = None;
        self.dashboard = None;
        self.snapshot = None;
        self.snapshot_error = None;
        self.connection_status = "Connecting…".to_string();

        let ctx = ctx.clone();
        let db_url = self.db_url.clone();
        let tx = self.tx.clone();
        self.runtime.spawn(async move {
            match initialize_database_pool(&db_url, true).await {
                Ok(pool) => {
                    let _ = tx.send(AppEvent::Connected(pool));
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::ConnectionFailed(e.to_string()));
                }
            }
            ctx.request_repaint();
        });
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        let Some(dash) = self.dashboard.clone() else {
            return;
        };
        self.is_loading_snapshot = true;
        self.snapshot_error = None;

        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            let result = dash.snapshot().await.map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::Snapshot(result));
            ctx.request_repaint();
        });
    }

    fn maybe_auto_refresh(&mut self, ctx: &egui::Context) {
        let need_initial = self.pool.is_some() && self.snapshot.is_none() && !self.is_loading_snapshot;
        let need_auto = self.auto_refresh
            && self.pool.is_some()
            && !self.is_loading_snapshot
            && self
                .last_refresh
                .map(|l| l.elapsed().as_secs_f32() >= self.refresh_interval_secs)
                .unwrap_or(false);
        if need_initial || need_auto {
            self.refresh(ctx);
        }
    }

    fn open_report(&mut self, ctx: &egui::Context, kind: ReportKind, query: String) {
        if self.has_report_window(kind, &query) {
            return;
        }
        let id = self.next_window_id;
        self.next_window_id += 1;
        self.open_windows.push(OpenWindow::Report {
            id,
            kind,
            query: query.clone(),
            text: String::new(),
            isp: None,
            org: None,
            loading: true,
            open: true,
        });

        let Some(pool) = self.pool.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            let generator = ReportGenerator::new(pool);
            let (isp, org) = if kind == ReportKind::Ip {
                generator.get_ip_isp_org(&query).await.unwrap_or((None, None))
            } else {
                (None, None)
            };
            let result = match kind {
                ReportKind::Ip => generator.generate_ip_report(&query, &ReportFormat::Text, true).await,
                ReportKind::Password => generator.generate_password_report(&query, &ReportFormat::Text).await,
            };
            match result {
                Ok(text) => {
                    let _ = tx.send(AppEvent::ReportReady {
                        kind,
                        query,
                        text,
                        isp,
                        org,
                    });
                }
                Err(e) => {
                    let _ = tx.send(AppEvent::ReportFailed {
                        kind,
                        query,
                        error: e.to_string(),
                    });
                }
            }
            ctx.request_repaint();
        });
    }

    fn open_session(
        &mut self,
        ctx: &egui::Context,
        auth_id: String,
        ip: String,
        username: String,
        start_time: Option<DateTime<Utc>>,
    ) {
        if self.has_session_window(&auth_id) {
            return;
        }
        let id = self.next_window_id;
        self.next_window_id += 1;
        self.open_windows.push(OpenWindow::Session {
            id,
            auth_id: auth_id.clone(),
            ip,
            username,
            start_time,
            detail: None,
            loading: true,
            error: None,
            open: true,
        });

        let Some(dash) = self.dashboard.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            let result = dash.session_detail(&auth_id).await.map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::SessionReady { auth_id, result });
            ctx.request_repaint();
        });
    }

    fn has_report_window(&self, kind: ReportKind, query: &str) -> bool {
        self.open_windows.iter().any(|w| {
            matches!(
                w,
                OpenWindow::Report { kind: k, query: q, open: true, .. } if *k == kind && q == query
            )
        })
    }

    fn has_session_window(&self, auth_id: &str) -> bool {
        self.open_windows
            .iter()
            .any(|w| matches!(w, OpenWindow::Session { auth_id: a, open: true, .. } if a == auth_id))
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                AppEvent::Connected(pool) => {
                    self.dashboard = Some(Dashboard::new(pool.clone()));
                    self.pool = Some(pool);
                    self.is_connecting = false;
                    self.connection_status = "Connected".to_string();
                    self.snapshot = None;
                    self.snapshot_error = None;
                }
                AppEvent::ConnectionFailed(e) => {
                    self.is_connecting = false;
                    self.connection_status = format!("Failed: {e}");
                }
                AppEvent::Snapshot(Ok(snap)) => {
                    self.snapshot = Some(snap);
                    self.is_loading_snapshot = false;
                    self.snapshot_error = None;
                    self.last_refresh = Some(Instant::now());
                }
                AppEvent::Snapshot(Err(e)) => {
                    self.is_loading_snapshot = false;
                    self.snapshot_error = Some(e);
                }
                AppEvent::ReportReady {
                    kind,
                    query,
                    text,
                    isp,
                    org,
                } => {
                    for w in self.open_windows.iter_mut() {
                        if let OpenWindow::Report {
                            kind: k,
                            query: q,
                            text: t,
                            isp: wi,
                            org: wo,
                            loading,
                            ..
                        } = w
                        {
                            if *k == kind && *q == query {
                                *t = text;
                                *wi = isp;
                                *wo = org;
                                *loading = false;
                                break;
                            }
                        }
                    }
                }
                AppEvent::ReportFailed {
                    kind,
                    query,
                    error,
                } => {
                    for w in self.open_windows.iter_mut() {
                        if let OpenWindow::Report {
                            kind: k,
                            query: q,
                            text: t,
                            loading,
                            ..
                        } = w
                        {
                            if *k == kind && *q == query {
                                *t = format!("Error generating report:\n{error}");
                                *loading = false;
                                break;
                            }
                        }
                    }
                }
                AppEvent::SessionReady { auth_id, result } => {
                    for w in self.open_windows.iter_mut() {
                        if let OpenWindow::Session {
                            auth_id: a,
                            detail,
                            loading,
                            error,
                            ..
                        } = w
                        {
                            if *a == auth_id {
                                *loading = false;
                                match result {
                                    Ok(d) => {
                                        *detail = Some(d);
                                        *error = None;
                                    }
                                    Err(e) => *error = Some(e),
                                }
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

impl eframe::App for DashboardApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_events();
        self.maybe_auto_refresh(&ctx);

        let mut actions: Vec<Action> = Vec::new();

        // --- Connection bar ---------------------------------------------------
        egui::Panel::top("connection_panel").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Database URL:");
                ui.add_sized(
                    [450.0, 20.0],
                    egui::TextEdit::singleline(&mut self.db_url),
                );
                let connect_label = if self.is_connecting {
                    "Connecting…"
                } else {
                    "Connect"
                };
                if ui
                    .add_enabled(!self.is_connecting, egui::Button::new(connect_label))
                    .clicked()
                {
                    actions.push(Action::Connect);
                }
                let status_color = if self.pool.is_some() {
                    GREEN
                } else if self.connection_status.starts_with("Failed") {
                    RED
                } else {
                    GRAY
                };
                ui.colored_label(status_color, &self.connection_status);
            });
            ui.add_space(6.0);
        });

        // --- Control bar ------------------------------------------------------
        egui::Panel::top("control_panel").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let can_refresh = self.pool.is_some() && !self.is_loading_snapshot;
                let refresh_label = if self.is_loading_snapshot {
                    "Refreshing…"
                } else {
                    "Refresh"
                };
                if ui
                    .add_enabled(can_refresh, egui::Button::new(refresh_label))
                    .clicked()
                {
                    actions.push(Action::Refresh);
                }
                ui.checkbox(&mut self.auto_refresh, "Auto-refresh");
                ui.label("every");
                ui.add(
                    egui::DragValue::new(&mut self.refresh_interval_secs)
                        .range(1.0..=300.0)
                        .speed(0.2)
                        .suffix("s"),
                );
                ui.separator();
                match self.snapshot.as_ref().and_then(|s| s.fetched_at) {
                    Some(t) => ui.label(format!("Last update: {}", fmt_ts(t))),
                    None => ui.colored_label(GRAY, "No data yet"),
                };
                match self.snapshot.as_ref().and_then(|s| s.top_fetched_at) {
                    Some(t) => ui.colored_label(
                        GRAY,
                        format!("stats cached since: {}", fmt_ts(t)),
                    ),
                    None => ui.colored_label(GRAY, "stats: not cached"),
                };
                if let Some(e) = &self.snapshot_error {
                    ui.colored_label(RED, e);
                }
                ui.separator();
                ui.label(format!("{} open window(s)", self.open_windows.len()));
                if ui
                    .add_enabled(
                        !self.open_windows.is_empty(),
                        egui::Button::new("Close all"),
                    )
                    .clicked()
                {
                    for w in &mut self.open_windows {
                        w.set_open(false);
                    }
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.colored_label(
                        GRAY,
                        "Tip: double-click an IP / password / session to drill in",
                    );
                });
            });
            ui.add_space(4.0);
        });

        ui.separator();

        // --- Central activity feed -------------------------------------------
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if let Some(snap) = self.snapshot.as_ref() {
                    render_live_sessions(ui, snap, &mut actions);
                    render_recent_auths(ui, snap, &mut actions);
                    render_recent_connections(ui, snap, &mut actions);
                    render_recent_sessions(ui, snap, &mut actions);
                    render_top_lists(ui, snap, &mut actions);
                } else {
                    ui.add_space(10.0);
                    ui.colored_label(
                        GRAY,
                        "Connect to the database to see live activity.",
                    );
                }
            });

        // --- Floating sub-windows --------------------------------------------
        for w in self.open_windows.iter_mut() {
            let id = w.id();
            let mut open = w.is_open();
            match w {
                OpenWindow::Report {
                    kind,
                    query,
                    text,
                    isp,
                    org,
                    loading,
                    ..
                } => {
                    let title = report_title(*kind, query);
                    egui::Window::new(title)
                        .id(egui::Id::new(id))
                        .open(&mut open)
                        .resizable(true)
                        .default_width(560.0)
                        .default_height(440.0)
                        .show(&ctx, |ui| {
                            ui.horizontal(|ui| {
                                if *loading {
                                    ui.spinner();
                                    ui.label("Generating report…");
                                } else {
                                    if let Some(isp) = isp {
                                        ui.colored_label(BLUEISH, format!("ISP: {isp}"));
                                    }
                                    if let Some(org) = org {
                                        ui.label(format!("Org: {org}"));
                                    }
                                }
                            });
                            if !*loading && !text.is_empty() {
                                egui::ScrollArea::vertical()
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::TextEdit::multiline(&mut text.as_str())
                                                .font(egui::TextStyle::Monospace)
                                                .desired_width(f32::INFINITY),
                                        );
                                    });
                            }
                        });
                }
                OpenWindow::Session {
                    ip,
                    username,
                    start_time,
                    detail,
                    loading,
                    error,
                    ..
                } => {
                    egui::Window::new(format!("Session · {ip}"))
                        .id(egui::Id::new(id))
                        .open(&mut open)
                        .resizable(true)
                        .default_width(640.0)
                        .default_height(540.0)
                        .show(&ctx, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(format!("User: {username}"));
                                if let Some(st) = start_time {
                                    ui.label(format!("Started: {}", fmt_ts(*st)));
                                }
                                let r = link_label(ui, ip, "double-click for IP report");
                                if r.double_clicked() {
                                    actions.push(Action::OpenReport(ReportKind::Ip, ip.clone()));
                                }
                            });

                            if *loading {
                                ui.spinner();
                                ui.label("Loading session detail…");
                                return;
                            }
                            if let Some(e) = error {
                                ui.colored_label(RED, format!("Error: {e}"));
                                return;
                            }
                            let Some(d) = detail.as_ref() else {
                                return;
                            };

                            ui.separator();
                            egui::Grid::new("detail_meta")
                                .striped(true)
                                .min_col_width(80.0)
                                .show(ui, |ui| {
                                    ui.label("Auth type");
                                    ui.label(d.auth_type.as_deref().unwrap_or("—"));
                                    ui.end_row();
                                    ui.label("Successful");
                                    success_label(ui, d.successful);
                                    ui.end_row();
                                    ui.label("Password");
                                    ui.label(d.password.as_deref().unwrap_or("—"));
                                    ui.end_row();
                                    ui.label("Country");
                                    ui.label(d.country_code.as_deref().unwrap_or("—"));
                                    ui.end_row();
                                    ui.label("City");
                                    ui.label(d.city.as_deref().unwrap_or("—"));
                                    ui.end_row();
                                    ui.label("ISP");
                                    ui.label(d.isp.as_deref().unwrap_or("—"));
                                    ui.end_row();
                                    ui.label("Auth ID");
                                    ui.label(&d.auth_id);
                                    ui.end_row();
                                });

                            ui.add_space(6.0);
                            ui.strong(format!("Commands ({})", d.commands.len()));
                            if d.commands.is_empty() {
                                ui.colored_label(GRAY, "No commands recorded.");
                            } else {
                                egui::Grid::new("detail_cmds")
                                    .striped(true)
                                    .min_col_width(60.0)
                                    .show(ui, |ui| {
                                        ui.strong("Time");
                                        ui.strong("Command");
                                        ui.end_row();
                                        for c in &d.commands {
                                            ui.label(fmt_ts(c.timestamp));
                                            ui.label(&c.command);
                                            ui.end_row();
                                        }
                                    });
                            }

                            ui.add_space(6.0);
                            ui.strong(format!("Uploaded files ({})", d.files.len()));
                            if d.files.is_empty() {
                                ui.colored_label(GRAY, "No files uploaded.");
                            } else {
                                egui::Grid::new("detail_files")
                                    .striped(true)
                                    .min_col_width(60.0)
                                    .show(ui, |ui| {
                                        ui.strong("Time");
                                        ui.strong("Name");
                                        ui.strong("Size");
                                        ui.strong("MIME");
                                        ui.strong("Entropy");
                                        ui.end_row();
                                        for f in &d.files {
                                            ui.label(fmt_ts(f.timestamp));
                                            ui.label(&f.filename);
                                            ui.label(fmt_size(f.file_size));
                                            ui.label(
                                                f.detected_mime_type
                                                    .as_deref()
                                                    .or(f.claimed_mime_type.as_deref())
                                                    .unwrap_or("—"),
                                            );
                                            ui.label(
                                                f.file_entropy
                                                    .map(|e| format!("{e:.2}"))
                                                    .unwrap_or_else(|| "—".to_string()),
                                            );
                                            ui.end_row();
                                        }
                                    });
                            }
                        });
                }
            }
            w.set_open(open);
        }

        // --- Apply queued actions --------------------------------------------
        for action in actions {
            match action {
                Action::Connect => self.connect(&ctx),
                Action::Refresh => self.refresh(&ctx),
                Action::OpenReport(kind, query) => self.open_report(&ctx, kind, query),
                Action::OpenSession {
                    auth_id,
                    ip,
                    username,
                    start_time,
                } => self.open_session(&ctx, auth_id, ip, username, start_time),
            }
        }

        self.open_windows.retain(|w| w.is_open());

        if self.auto_refresh && self.pool.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

// ---- section renderers --------------------------------------------------

fn render_live_sessions(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    actions: &mut Vec<Action>,
) {
    section_header(ui, &format!("Live Sessions ({})", snap.live_sessions.len()));
    if snap.live_sessions.is_empty() {
        ui.colored_label(GRAY, "No active sessions right now.");
        return;
    }
    egui::Grid::new("live_sessions")
        .striped(true)
        .min_col_width(60.0)
        .show(ui, |ui| {
            for h in ["Started", "IP", "Username", "Auth", "Success", "Running"] {
                ui.strong(h);
            }
            ui.end_row();
            for s in &snap.live_sessions {
                ui.label(fmt_ts(s.start_time));
                let r = link_label(ui, &s.ip, "double-click for session detail");
                if r.double_clicked() {
                    actions.push(Action::OpenSession {
                        auth_id: s.auth_id.clone(),
                        ip: s.ip.clone(),
                        username: s.username.clone(),
                        start_time: Some(s.start_time),
                    });
                }
                ui.label(&s.username);
                ui.label(s.auth_type.as_deref().unwrap_or("—"));
                success_label(ui, s.successful);
                let running = Utc::now()
                    .signed_duration_since(s.start_time)
                    .num_seconds()
                    .max(0);
                ui.label(fmt_duration(Some(running)));
                ui.end_row();
            }
        });
}

fn render_recent_auths(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    actions: &mut Vec<Action>,
) {
    section_header(
        ui,
        &format!("Recent Auth Attempts ({})", snap.recent_auths.len()),
    );
    if snap.recent_auths.is_empty() {
        ui.colored_label(GRAY, "No auth attempts yet.");
        return;
    }
    egui::Grid::new("recent_auths")
        .striped(true)
        .min_col_width(60.0)
        .show(ui, |ui| {
            for h in ["Time", "IP", "Username", "Password", "Auth", "Success"] {
                ui.strong(h);
            }
            ui.end_row();
            for a in &snap.recent_auths {
                ui.label(fmt_ts(a.timestamp));
                let r = link_label(ui, &a.ip, "double-click for IP report");
                if r.double_clicked() {
                    actions.push(Action::OpenReport(ReportKind::Ip, a.ip.clone()));
                }
                ui.label(&a.username);
                match &a.password {
                    Some(p) if !p.is_empty() => {
                        let r = link_label(ui, p, "double-click for password report");
                        if r.double_clicked() {
                            actions.push(Action::OpenReport(ReportKind::Password, p.clone()));
                        }
                    }
                    Some(_) => {
                        ui.label("(empty)");
                    }
                    None => {
                        ui.label("—");
                    }
                }
                ui.label(a.auth_type.as_deref().unwrap_or("—"));
                success_label(ui, a.successful);
                ui.end_row();
            }
        });
}

fn render_recent_connections(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    actions: &mut Vec<Action>,
) {
    section_header(
        ui,
        &format!("Recent Connections ({})", snap.recent_connections.len()),
    );
    if snap.recent_connections.is_empty() {
        ui.colored_label(GRAY, "No connections yet.");
        return;
    }
    egui::Grid::new("recent_conns")
        .striped(true)
        .min_col_width(60.0)
        .show(ui, |ui| {
            for h in ["Time", "IP", "Port", "Local"] {
                ui.strong(h);
            }
            ui.end_row();
            for c in &snap.recent_connections {
                ui.label(fmt_ts(c.timestamp));
                let r = link_label(ui, &c.ip, "double-click for IP report");
                if r.double_clicked() {
                    actions.push(Action::OpenReport(ReportKind::Ip, c.ip.clone()));
                }
                ui.label(c.port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string()));
                ui.label(
                    c.local_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "—".to_string()),
                );
                ui.end_row();
            }
        });
}

fn render_recent_sessions(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    actions: &mut Vec<Action>,
) {
    section_header(
        ui,
        &format!("Recent Sessions ({})", snap.recent_sessions.len()),
    );
    if snap.recent_sessions.is_empty() {
        ui.colored_label(GRAY, "No ended sessions yet.");
        return;
    }
    egui::Grid::new("recent_sessions")
        .striped(true)
        .min_col_width(60.0)
        .show(ui, |ui| {
            for h in ["Started", "Ended", "IP", "Username", "Duration", "Commands"] {
                ui.strong(h);
            }
            ui.end_row();
            for s in &snap.recent_sessions {
                ui.label(fmt_ts(s.start_time));
                ui.label(s.end_time.map(fmt_ts).unwrap_or_else(|| "—".to_string()));
                let r = link_label(ui, &s.ip, "double-click for session detail");
                if r.double_clicked() {
                    actions.push(Action::OpenSession {
                        auth_id: s.auth_id.clone(),
                        ip: s.ip.clone(),
                        username: s.username.clone(),
                        start_time: Some(s.start_time),
                    });
                }
                ui.label(&s.username);
                ui.label(fmt_duration(s.duration_seconds));
                ui.label(format!("{}", s.command_count));
                ui.end_row();
            }
        });
}

fn render_top_lists(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    actions: &mut Vec<Action>,
) {
    section_header(ui, "Top Activity");
    ui.columns(3, |cols| {
        render_top_list(
            &mut cols[0],
            "Top IPs",
            &snap.top_ips,
            actions,
            Some(ReportKind::Ip),
        );
        render_top_list(
            &mut cols[1],
            "Top Passwords",
            &snap.top_passwords,
            actions,
            Some(ReportKind::Password),
        );
        render_top_list(&mut cols[2], "Top Usernames", &snap.top_usernames, actions, None);
    });
}

fn render_top_list(
    ui: &mut egui::Ui,
    title: &str,
    entries: &[ssh_honeypot::dashboard::TopEntry],
    actions: &mut Vec<Action>,
    kind: Option<ReportKind>,
) {
    ui.strong(title);
    if entries.is_empty() {
        ui.colored_label(GRAY, "No data.");
        return;
    }
    egui::Grid::new(title)
        .striped(true)
        .min_col_width(40.0)
        .show(ui, |ui| {
            for e in entries {
                match kind {
                    Some(k) => {
                        let r = link_label(ui, &e.value, "double-click to open report");
                        if r.double_clicked() {
                            actions.push(Action::OpenReport(k, e.value.clone()));
                        }
                    }
                    None => {
                        ui.label(&e.value);
                    }
                }
                ui.label(format!("{}", e.count));
                ui.end_row();
            }
        });
}

// ---- small helpers ------------------------------------------------------

fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(text).strong().size(15.0));
    ui.separator();
}

fn link_label(ui: &mut egui::Ui, text: &str, tip: &str) -> egui::Response {
    ui.add(
        egui::Label::new(egui::RichText::new(text).color(LINK).underline())
            .sense(egui::Sense::click()),
    )
    .on_hover_text(tip)
}

fn success_label(ui: &mut egui::Ui, opt: Option<bool>) {
    match opt {
        Some(true) => {
            ui.colored_label(GREEN, "yes");
        }
        Some(false) => {
            ui.colored_label(RED, "no");
        }
        None => {
            ui.label("—");
        }
    }
}

fn report_title(kind: ReportKind, query: &str) -> String {
    match kind {
        ReportKind::Ip => format!("IP report · {query}"),
        ReportKind::Password => format!("Password report · {query}"),
    }
}

fn fmt_ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn fmt_duration(secs: Option<i64>) -> String {
    let Some(s) = secs else {
        return "—".to_string();
    };
    if s < 0 {
        return "—".to_string();
    }
    let h = s / 3600;
    let m = (s % 3600) / 60;
    let sec = s % 60;
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {sec}s")
    } else {
        format!("{sec}s")
    }
}

fn fmt_size(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.1} KiB", b / KB)
    } else if b < KB * KB * KB {
        format!("{:.1} MiB", b / (KB * KB))
    } else {
        format!("{:.1} GiB", b / (KB * KB * KB))
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SSH Honeypot Dashboard")
            .with_inner_size([1100.0, 780.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SSH Honeypot Dashboard",
        options,
        Box::new(|_cc| Ok(Box::new(DashboardApp::new()))),
    )
}
