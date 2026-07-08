#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
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
use egui::{Key, KeyboardShortcut, Modifiers};
use sqlx::PgPool;
use sqlx::postgres::PgListener;
use common::dashboard::{Dashboard, DashboardSnapshot, ReportedIp, SessionDetail, TopData};
use common::dashboard_config::DashboardConfig;
use common::db::initialize_database_pool;
use common::report::{ReportFormat, ReportGenerator};
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEFAULT_DB_URL: &str = "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot";

const LINK: egui::Color32 = egui::Color32::from_rgb(96, 165, 250);
const GREEN: egui::Color32 = egui::Color32::from_rgb(80, 180, 80);
const RED: egui::Color32 = egui::Color32::from_rgb(220, 70, 70);
const GRAY: egui::Color32 = egui::Color32::GRAY;
const BLUEISH: egui::Color32 = egui::Color32::from_rgb(140, 180, 220);
/// Colour of the "reported" marker drawn in front of flagged IPs.
const ORANGE: egui::Color32 = egui::Color32::from_rgb(235, 150, 40);

/// Postgres LISTEN channels the dashboard subscribes to for near-real-time
/// updates. A DB trigger (migration 012 / 013) fires these on INSERT/UPDATE.
const NOTIFY_CHANNELS: &[&str] = &[
    "auth_new",
    "conn_new",
    "session_change",
    "reported_ip_change",
];
/// Minimum spacing between notify-triggered refreshes, so a burst of events
/// (e.g. a password spray issuing one NOTIFY per attempt) collapses into one
/// refresh per ~second rather than one per row.
const NOTIFY_DEBOUNCE_SECS: f32 = 1.0;

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
    /// Result of the background top-N aggregate refresh.
    TopReady(Result<TopData, String>),
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
    /// A reported-IP write (add / remove / edit notes) failed in the
    /// background. Surfaced as a transient error in the manager window.
    ReportedError(String),
    /// A Postgres LISTEN/NOTIFY arrived on one of NOTIFY_CHANNELS. The payload
    /// names the channel so the UI can show which feed was touched.
    Notify(&'static str),
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
    /// Open the read-only reported-IP details window for an IP.
    OpenReportedDetails {
        ip: String,
    },
    /// Open (or focus) the reported-IP manager window, optionally pre-filling
    /// the "add report" IP field (used by the "Report this IP" button).
    OpenReportedManager {
        prefill_ip: Option<String>,
    },
    /// Flag an IP as reported with the given notes.
    AddReportedIp {
        ip: String,
        notes: String,
    },
    /// Remove the reported-IP flag for an IP.
    RemoveReportedIp {
        ip: String,
    },
    /// Replace the notes stored for an already-reported IP.
    UpdateReportedNotes {
        ip: String,
        notes: String,
    },
    /// Re-fetch the contents of a single floating window (id).
    RefreshWindow(u64),
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
    /// Read-only view of a reported-IP flag (IP + timestamp + notes). Opened by
    /// double-clicking the marker in front of a reported IP. The contents are
    /// read live from the app's reported map every frame, so the window tracks
    /// notify-driven changes without its own background fetch.
    ReportedDetails { id: u64, ip: String, open: bool },
    /// The "Reported IPs" manager: add reports (with notes), edit notes inline,
    /// and remove flags. Singleton — at most one is open at a time.
    ReportedManager {
        id: u64,
        new_ip: String,
        new_notes: String,
        /// Per-IP notes-edit buffers so typing isn't clobbered by notify-driven
        /// list refreshes. Lazily seeded from the DB value.
        notes_edit: HashMap<String, String>,
        open: bool,
    },
}

impl OpenWindow {
    fn id(&self) -> u64 {
        match self {
            OpenWindow::Report { id, .. }
            | OpenWindow::Session { id, .. }
            | OpenWindow::ReportedDetails { id, .. }
            | OpenWindow::ReportedManager { id, .. } => *id,
        }
    }
    fn is_open(&self) -> bool {
        match self {
            OpenWindow::Report { open, .. }
            | OpenWindow::Session { open, .. }
            | OpenWindow::ReportedDetails { open, .. }
            | OpenWindow::ReportedManager { open, .. } => *open,
        }
    }
    fn set_open(&mut self, value: bool) {
        match self {
            OpenWindow::Report { open, .. }
            | OpenWindow::Session { open, .. }
            | OpenWindow::ReportedDetails { open, .. }
            | OpenWindow::ReportedManager { open, .. } => *open = value,
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

    /// True while the expensive top-N aggregates are being (re)computed in the
    /// background. The cheap recent feeds are already shown; the top lists
    /// render a skeleton until this clears.
    top_loading: bool,
    top_error: Option<String>,

    auto_refresh: bool,
    refresh_interval_secs: f32,
    last_refresh: Option<Instant>,

    open_windows: Vec<OpenWindow>,
    next_window_id: u64,
    /// The floating window most recently clicked by the user, used by F5 to
    /// decide which window to refresh. Persists after the pointer leaves, so
    /// F5 refreshes the window you last interacted with (like native OS focus).
    focused_window_id: Option<u64>,

    runtime: tokio::runtime::Runtime,
    tx: mpsc::Sender<AppEvent>,
    rx: mpsc::Receiver<AppEvent>,

    /// Handle to the background LISTEN/NOTIFY task, so it can be cancelled on
    /// reconnect.
    notify_task: Option<tokio::task::JoinHandle<()>>,
    /// Set when a NOTIFY has arrived and a refresh is pending. Cleared once a
    /// refresh is actually kicked off (debounced in maybe_auto_refresh).
    notify_pending: bool,
    /// `(when, channel)` of the most recent NOTIFY, shown in the UI as a
    /// "live" indicator so the user can see real-time updates flowing.
    last_notify: Option<(Instant, &'static str)>,

    /// Dashboard GUI preferences (excluded IPs, geolocation toggle, ...).
    /// Persisted to `dashboard.toml` in the project config directory.
    config: DashboardConfig,
    /// Scratch buffer for the "add excluded IP" text field in the hotbar.
    exclude_ip_input: String,

    /// Reported-IP flags keyed by normalised IP (lowercased, trimmed) for O(1)
    /// lookup while drawing the feed tables. Refreshed from every snapshot so
    /// it tracks NOTIFY-driven changes from other dashboard instances too.
    reported: HashMap<String, ReportedIp>,
    /// Transient error from a reported-IP write (add/remove/edit notes),
    /// shown in the manager window until the next successful refresh.
    reported_error: Option<String>,
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
            top_loading: false,
            top_error: None,
            auto_refresh: true,
            refresh_interval_secs: 10.0,
            last_refresh: None,
            open_windows: Vec::new(),
            next_window_id: 1,
            focused_window_id: None,
            runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
            tx,
            rx,
            notify_task: None,
            notify_pending: false,
            last_notify: None,
            config: DashboardConfig::load(),
            exclude_ip_input: String::new(),
            reported: HashMap::new(),
            reported_error: None,
        }
    }

    fn connect(&mut self, ctx: &egui::Context) {
        // Cancel any previous LISTEN/NOTIFY listener before opening a new one.
        if let Some(handle) = self.notify_task.take() {
            handle.abort();
        }
        self.is_connecting = true;
        self.pool = None;
        self.dashboard = None;
        self.snapshot = None;
        self.snapshot_error = None;
        self.top_loading = false;
        self.top_error = None;
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
        self.top_loading = true;
        self.top_error = None;

        // Fast path: cheap recent/live feeds + whatever top-N data is already
        // cached. Returns in milliseconds so the dashboard repaints instantly.
        let tx = self.tx.clone();
        let ctx_main = ctx.clone();
        let dash_main = dash.clone();
        self.runtime.spawn(async move {
            let result = dash_main.main_snapshot().await.map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::Snapshot(result));
            ctx_main.request_repaint();
        });

        // Slow path: (re)compute the top-N aggregates in the background. On a
        // warm cache this returns near-instantly; on a cold cache it takes a
        // few seconds, during which the top lists show a loading skeleton.
        let tx = self.tx.clone();
        let ctx_top = ctx.clone();
        self.runtime.spawn(async move {
            let result = dash.refresh_top().await.map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::TopReady(result));
            ctx_top.request_repaint();
        });
    }

    fn maybe_auto_refresh(&mut self, ctx: &egui::Context) {
        let need_initial =
            self.pool.is_some() && self.snapshot.is_none() && !self.is_loading_snapshot;
        let need_auto = self.auto_refresh
            && self.pool.is_some()
            && !self.is_loading_snapshot
            && self
                .last_refresh
                .map(|l| l.elapsed().as_secs_f32() >= self.refresh_interval_secs)
                .unwrap_or(false);
        // Real-time path: a NOTIFY arrived. Debounced so a burst of events
        // (e.g. a password spray) collapses into one refresh per ~second.
        let need_notify = self.auto_refresh
            && self.notify_pending
            && self.pool.is_some()
            && !self.is_loading_snapshot
            && self
                .last_refresh
                .map(|l| l.elapsed().as_secs_f32() >= NOTIFY_DEBOUNCE_SECS)
                .unwrap_or(true);
        if need_initial || need_auto || need_notify {
            self.notify_pending = false;
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
        // A freshly opened window becomes the focused one so F5 targets it
        // immediately, before the user has clicked inside it.
        self.focused_window_id = Some(id);
        self.spawn_report(ctx, kind, query);
    }

    /// Kick off the background report generation for the given query, sending
    /// the result back through the event channel.
    fn spawn_report(&self, ctx: &egui::Context, kind: ReportKind, query: String) {
        let Some(pool) = self.pool.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let show_geolocation = self.config.show_geolocation;
        self.runtime.spawn(async move {
            let generator = ReportGenerator::new(pool);
            let (isp, org) = if kind == ReportKind::Ip {
                generator
                    .get_ip_isp_org(&query)
                    .await
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };
            let result = match kind {
                ReportKind::Ip => {
                    generator
                        .generate_ip_report(&query, &ReportFormat::Text, show_geolocation)
                        .await
                }
                ReportKind::Password => {
                    generator
                        .generate_password_report(&query, &ReportFormat::Text)
                        .await
                }
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
        // A freshly opened window becomes the focused one so F5 targets it
        // immediately, before the user has clicked inside it.
        self.focused_window_id = Some(id);
        self.spawn_session(ctx, auth_id);
    }

    /// Kick off the background session detail fetch for the given auth id.
    fn spawn_session(&self, ctx: &egui::Context, auth_id: String) {
        let Some(dash) = self.dashboard.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            let result = dash
                .session_detail(&auth_id)
                .await
                .map_err(|e| e.to_string());
            let _ = tx.send(AppEvent::SessionReady { auth_id, result });
            ctx.request_repaint();
        });
    }

    /// Re-fetch the contents of a single floating window, identified by its
    /// numeric id. Used by the per-window Refresh button and by F5.
    fn refresh_window(&mut self, ctx: &egui::Context, window_id: u64) {
        let Some(idx) = self.open_windows.iter().position(|w| w.id() == window_id) else {
            return;
        };

        // ReportedDetails / ReportedManager read their data live from the
        // snapshot every frame, so a manual refresh is a no-op for them.
        let already_loading = match &self.open_windows[idx] {
            OpenWindow::Report { loading, .. } | OpenWindow::Session { loading, .. } => *loading,
            OpenWindow::ReportedDetails { .. } | OpenWindow::ReportedManager { .. } => return,
        };
        if already_loading {
            return;
        }

        enum Job {
            Report(ReportKind, String),
            Session(String),
        }

        let job = match &self.open_windows[idx] {
            OpenWindow::Report { kind, query, .. } => Job::Report(*kind, query.clone()),
            OpenWindow::Session { auth_id, .. } => Job::Session(auth_id.clone()),
            OpenWindow::ReportedDetails { .. } | OpenWindow::ReportedManager { .. } => return,
        };

        match &mut self.open_windows[idx] {
            OpenWindow::Report { loading, .. } => *loading = true,
            OpenWindow::Session { loading, error, .. } => {
                *loading = true;
                *error = None;
            }
            OpenWindow::ReportedDetails { .. } | OpenWindow::ReportedManager { .. } => return,
        }

        match job {
            Job::Report(kind, query) => self.spawn_report(ctx, kind, query),
            Job::Session(auth_id) => self.spawn_session(ctx, auth_id),
        }
    }

    /// Spawn the background task that LISTENs on the NOTIFY channels and
    /// forwards notifications to the UI thread via the event channel.
    fn start_notify_listener(&mut self, ctx: &egui::Context) {
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        let db_url = self.db_url.clone();
        let handle = self.runtime.spawn(async move {
            run_notify_listener(db_url, tx, ctx).await;
        });
        self.notify_task = Some(handle);
    }

    /// Drop any rows whose IP appears in `config.excluded_ips` from a freshly
    /// arrived snapshot. Done centrally here so every feed (recent / live /
    /// top) is filtered consistently without touching the render functions.
    fn apply_excluded_ips(&self, snap: &mut DashboardSnapshot) {
        if self.config.excluded_ips.is_empty() {
            return;
        }
        snap.recent_connections
            .retain(|c| !self.config.is_excluded(&c.ip));
        snap.recent_auths
            .retain(|a| !self.config.is_excluded(&a.ip));
        snap.live_sessions
            .retain(|s| !self.config.is_excluded(&s.ip));
        snap.recent_sessions
            .retain(|s| !self.config.is_excluded(&s.ip));
        snap.top_ips.retain(|e| !self.config.is_excluded(&e.value));
    }

    // --- reported-IP flag handling --------------------------------------

    /// Open (or focus) the read-only reported-IP details window for `ip`.
    fn open_reported_details(&mut self, _ctx: &egui::Context, ip: String) {
        if self
            .open_windows
            .iter()
            .any(|w| matches!(w, OpenWindow::ReportedDetails { ip: i, open: true, .. } if i == &ip))
        {
            return;
        }
        let id = self.next_window_id;
        self.next_window_id += 1;
        self.open_windows
            .push(OpenWindow::ReportedDetails { id, ip, open: true });
        self.focused_window_id = Some(id);
    }

    /// Open (or focus) the reported-IP manager, optionally pre-filling the
    /// "add report" IP field (used by the per-IP "Report this IP" button).
    fn open_reported_manager(&mut self, _ctx: &egui::Context, prefill_ip: Option<String>) {
        if let Some(OpenWindow::ReportedManager { new_ip, .. }) = self
            .open_windows
            .iter_mut()
            .find(|w| matches!(w, OpenWindow::ReportedManager { open: true, .. }))
        {
            if let Some(ip) = prefill_ip.filter(|s| !s.trim().is_empty()) {
                if new_ip.trim().is_empty() {
                    *new_ip = ip;
                }
            }
            return;
        }
        let id = self.next_window_id;
        self.next_window_id += 1;
        self.open_windows.push(OpenWindow::ReportedManager {
            id,
            new_ip: prefill_ip.unwrap_or_default(),
            new_notes: String::new(),
            notes_edit: HashMap::new(),
            open: true,
        });
        self.focused_window_id = Some(id);
    }

    /// Flag an IP as reported (upsert) with notes. Fire-and-forget; the NOTIFY
    /// trigger refreshes the snapshot, and any DB error comes back as a
    /// [`AppEvent::ReportedError`].
    fn spawn_add_reported(&self, ctx: &egui::Context, ip: String, notes: String) {
        let Some(dash) = self.dashboard.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            if let Err(e) = dash.add_reported_ip(&ip, &notes).await {
                let _ = tx.send(AppEvent::ReportedError(e.to_string()));
            }
            ctx.request_repaint();
        });
    }

    /// Remove the reported-IP flag for `ip`.
    fn spawn_remove_reported(&self, ctx: &egui::Context, ip: String) {
        let Some(dash) = self.dashboard.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            if let Err(e) = dash.remove_reported_ip(&ip).await {
                let _ = tx.send(AppEvent::ReportedError(e.to_string()));
            }
            ctx.request_repaint();
        });
    }

    /// Replace the notes stored for an already-reported IP.
    fn spawn_update_reported_notes(&self, ctx: &egui::Context, ip: String, notes: String) {
        let Some(dash) = self.dashboard.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let ctx = ctx.clone();
        self.runtime.spawn(async move {
            if let Err(e) = dash.update_reported_ip_notes(&ip, &notes).await {
                let _ = tx.send(AppEvent::ReportedError(e.to_string()));
            }
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
        self.open_windows.iter().any(
            |w| matches!(w, OpenWindow::Session { auth_id: a, open: true, .. } if a == auth_id),
        )
    }

    fn poll_events(&mut self, ctx: &egui::Context) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                AppEvent::Connected(pool) => {
                    self.dashboard = Some(Dashboard::new(pool.clone()));
                    self.pool = Some(pool);
                    self.is_connecting = false;
                    self.connection_status = "Connected".to_string();
                    self.snapshot = None;
                    self.snapshot_error = None;
                    self.reported.clear();
                    self.reported_error = None;
                    // Begin listening for real-time row notifications.
                    self.start_notify_listener(ctx);
                }
                AppEvent::ConnectionFailed(e) => {
                    self.is_connecting = false;
                    self.connection_status = format!("Failed: {e}");
                }
                AppEvent::Snapshot(Ok(mut snap)) => {
                    self.apply_excluded_ips(&mut snap);
                    self.reported = build_reported_map(&snap.reported_ips);
                    self.reported_error = None;
                    self.snapshot = Some(snap);
                    self.is_loading_snapshot = false;
                    self.snapshot_error = None;
                    self.last_refresh = Some(Instant::now());
                }
                AppEvent::Snapshot(Err(e)) => {
                    self.is_loading_snapshot = false;
                    self.snapshot_error = Some(e);
                }
                AppEvent::TopReady(Ok(mut top)) => {
                    if !self.config.excluded_ips.is_empty() {
                        top.ips.retain(|e| !self.config.is_excluded(&e.value));
                    }
                    // Merge the freshly computed top-N lists into whatever
                    // snapshot we already have (it may be None if the main
                    // snapshot hasn't landed yet, which is fine).
                    let snap = self.snapshot.get_or_insert_with(DashboardSnapshot::default);
                    snap.top_ips = top.ips;
                    snap.top_passwords = top.passwords;
                    snap.top_usernames = top.usernames;
                    snap.top_fetched_at = top.fetched_at;
                    self.top_loading = false;
                    self.top_error = None;
                }
                AppEvent::TopReady(Err(e)) => {
                    self.top_loading = false;
                    self.top_error = Some(e);
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
                AppEvent::ReportFailed { kind, query, error } => {
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
                AppEvent::Notify(channel) => {
                    // A DB row landed. Flag a pending refresh; maybe_auto_refresh
                    // will coalesce bursts into a single refresh.
                    self.notify_pending = true;
                    self.last_notify = Some((Instant::now(), channel));
                }
                AppEvent::ReportedError(e) => {
                    self.reported_error = Some(e);
                }
            }
        }
    }
}

impl eframe::App for DashboardApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_events(&ctx);
        self.maybe_auto_refresh(&ctx);

        let mut screenshot_to_copy = None;

        ctx.input(|i| {
            for event in &i.events {
                if let egui::Event::Screenshot { image, .. } = event {
                    screenshot_to_copy = Some((**image).clone());
                }
            }
        });

        if let Some(image) = screenshot_to_copy {
            ui.ctx().copy_image(image.clone());
            #[cfg(target_os = "windows")]
            {
                use clipboard_win::{
                    formats::{CF_DIB, RawData},
                    set_clipboard,
                };
                use image::codecs::bmp::BmpEncoder;
                use image::{ExtendedColorType, ImageEncoder};

                let raw_bytes: Vec<u8> = image
                    .pixels
                    .iter()
                    .flat_map(|color| color.to_array())
                    .collect();

                let width = image.size[0] as u32;
                let height = image.size[1] as u32;

                let mut bmp_buffer = Vec::new();
                let encoder = BmpEncoder::new(&mut bmp_buffer);

                // Encode as standard BMP instead of PNG
                if encoder
                    .write_image(&raw_bytes, width, height, ExtendedColorType::Rgba8)
                    .is_ok()
                {
                    println!("Time to copy {} kbytes", bmp_buffer.len() / 1024);

                    // CF_DIB is universally mapped to format ID 8 in the Win32 API.
                    // Slicing [14..] strips the BITMAPFILEHEADER, leaving a perfect DIB payload.
                    if bmp_buffer.len() > 14 {
                        let _ = set_clipboard(RawData(CF_DIB), &bmp_buffer[14..]);
                    }
                }
            }
        }

        let f2_pressed =
            ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(Modifiers::NONE, Key::F2)));

        if f2_pressed {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
        }

        let mut actions: Vec<Action> = Vec::new();

        // --- Hotbar (quick-access settings) --------------------------------
        // Compact always-visible toolbar. Holds the geolocation toggle (the
        // explicitly requested quick-access control) plus an inline editor for
        // excluded IPs so the list is manageable without leaving the GUI.
        egui::Panel::top("hotbar_panel").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.strong("View");
                let mut geo = self.config.show_geolocation;
                if ui.checkbox(&mut geo, "Show geolocation").changed() {
                    self.config.show_geolocation = geo;
                    self.config.save();
                }
                ui.separator();
                ui.label("Exclude IP:");
                let add_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.exclude_ip_input)
                        .desired_width(150.0)
                        .hint_text("e.g. 1.2.3.4"),
                );
                let enter_pressed =
                    add_resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                if (ui.button("+ Add").clicked() || enter_pressed)
                    && !self.exclude_ip_input.trim().is_empty()
                {
                    let ip = self.exclude_ip_input.trim().to_string();
                    if !self
                        .config
                        .excluded_ips
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case(&ip))
                    {
                        self.config.excluded_ips.push(ip);
                        self.config.save();
                        actions.push(Action::Refresh);
                    }
                    self.exclude_ip_input.clear();
                }
            });
            if !self.config.excluded_ips.is_empty() {
                ui.add_space(2.0);
                let mut remove_idxs: Vec<usize> = Vec::new();
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(GRAY, "Hidden:");
                    for (i, ip) in self.config.excluded_ips.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(ip);
                            if ui.small_button("×").clicked() {
                                remove_idxs.push(i);
                            }
                        });
                    }
                });
                if !remove_idxs.is_empty() {
                    for i in remove_idxs.into_iter().rev() {
                        self.config.excluded_ips.remove(i);
                    }
                    self.config.save();
                    actions.push(Action::Refresh);
                }
            }
            ui.add_space(4.0);
        });

        // --- Connection bar ---------------------------------------------------
        egui::Panel::top("connection_panel").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Database URL:");
                ui.add_sized([450.0, 20.0], egui::TextEdit::singleline(&mut self.db_url));
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
                    Some(t) => ui.colored_label(GRAY, format!("stats cached since: {}", fmt_ts(t))),
                    None => ui.colored_label(GRAY, "stats: not cached"),
                };
                if let Some((when, ch)) = self.last_notify {
                    let ago = when.elapsed().as_secs();
                    ui.colored_label(GREEN, format!("live \u{00b7} {ch} {ago}s ago"));
                }
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
                if ui.button("Reported IPs\u{2026}").clicked() {
                    actions.push(Action::OpenReportedManager { prefill_ip: None });
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
                    let n_cols = column_count(ui.available_width());
                    let top_loading = self.top_loading;
                    let top_error = self.top_error.as_deref();
                    // Disjoint immutable borrow of the reported-IP map (separate
                    // field from `self.snapshot`); threaded into every feed row.
                    let reported = &self.reported;
                    let sections = [
                        Section::LiveSessions,
                        Section::RecentAuths,
                        Section::RecentConnections,
                        Section::RecentSessions,
                        Section::TopActivity,
                    ];
                    for row in sections.chunks(n_cols) {
                        ui.columns(n_cols, |cols| {
                            for (i, section) in row.iter().enumerate() {
                                if let Some(col_ui) = cols.get_mut(i) {
                                    render_section(
                                        col_ui,
                                        snap,
                                        reported,
                                        &mut actions,
                                        top_loading,
                                        top_error,
                                        *section,
                                    );
                                }
                            }
                        });
                        ui.add_space(8.0);
                    }
                } else {
                    ui.add_space(10.0);
                    ui.colored_label(GRAY, "Connect to the database to see live activity.");
                }
            });

        // --- Floating sub-windows --------------------------------------------
        // Detect which window the user clicked this frame (if any) so we can
        // latch it as the "focused" window. `layer_id_at` returns the true
        // topmost interactive area under the pointer — robust even when the
        // click lands on a child widget that consumes the interaction. The
        // layer's `id` equals the `egui::Id` we pass to each `Window`.
        let primary_pressed = ctx.input(|i| i.pointer.primary_pressed());
        let clicked_layer = if primary_pressed {
            ctx.input(|i| i.pointer.latest_pos())
                .and_then(|p| ctx.layer_id_at(p))
        } else {
            None
        };
        let mut new_focus: Option<u64> = None;
        // Copied out so the floating-window closures (which only borrow the
        // matched window fields) can read the geolocation preference without
        // aliasing `&mut self.open_windows`.
        let show_geo = self.config.show_geolocation;
        // Copied out of `self` so the floating-window closures (which mutably
        // borrow the matched window fields) can read the reported-IP list and
        // any pending error without aliasing `&mut self.open_windows`.
        let reported_list: Vec<ReportedIp> = self.reported.values().cloned().collect();
        let reported_error = self.reported_error.clone();
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
                                if ui
                                    .add_enabled(!*loading, egui::Button::new("Refresh (F5)"))
                                    .clicked()
                                {
                                    actions.push(Action::RefreshWindow(id));
                                }
                                ui.separator();
                                if *loading {
                                    ui.spinner();
                                    ui.label("Generating report…");
                                } else if show_geo {
                                    if let Some(isp) = isp {
                                        ui.colored_label(BLUEISH, format!("ISP: {isp}"));
                                    }
                                    if let Some(org) = org {
                                        ui.label(format!("Org: {org}"));
                                    }
                                }
                            });
                            // For IP reports, surface the reported-IP flag and
                            // offer quick Report / Unreport actions inline.
                            if *kind == ReportKind::Ip {
                                ui.separator();
                                match reported_list.iter().find(|rep| rep.ip == *query) {
                                    Some(rep) => {
                                        ui.colored_label(
                                            ORANGE,
                                            format!(
                                                "\u{2691} Reported {}",
                                                fmt_ts(rep.reported_at)
                                            ),
                                        );
                                        if ui.small_button("Details").clicked() {
                                            actions.push(Action::OpenReportedDetails {
                                                ip: query.clone(),
                                            });
                                        }
                                        if ui.small_button("Unreport").clicked() {
                                            actions.push(Action::RemoveReportedIp {
                                                ip: query.clone(),
                                            });
                                        }
                                    }
                                    None => {
                                        if ui.button("Report this IP\u{2026}").clicked() {
                                            actions.push(Action::OpenReportedManager {
                                                prefill_ip: Some(query.clone()),
                                            });
                                        }
                                    }
                                }
                                ui.separator();
                            }
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
                        })
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
                    let screen = ctx.content_rect();
                    egui::Window::new(format!("Session · {ip}"))
                        .id(egui::Id::new(id))
                        .open(&mut open)
                        .resizable(true)
                        .default_width(640.0)
                        .default_height(540.0)
                        .constrain_to(screen)
                        .show(&ctx, |ui| {
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(!*loading, egui::Button::new("Refresh (F5)"))
                                    .clicked()
                                {
                                    actions.push(Action::RefreshWindow(id));
                                }
                                ui.separator();
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

                            // Scrollable detail body: scroll both horizontally
                            // and vertically so long attacker-controlled strings
                            // (commands, file names, passwords) can be scrolled
                            // into view instead of wrapping or stretching the
                            // window past the screen. A non-wrapping Label in a
                            // Grid uses TextWrapMode::Extend, which makes the
                            // grid expand to the full text width; the ScrollArea
                            // then provides a horizontal scrollbar for it.
                            egui::ScrollArea::both()
                                .auto_shrink([false, false])
                                .show(ui, |ui| {
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
                                            if show_geo {
                                                ui.label("Country");
                                                ui.label(d.country_code.as_deref().unwrap_or("—"));
                                                ui.end_row();
                                                ui.label("City");
                                                ui.label(d.city.as_deref().unwrap_or("—"));
                                                ui.end_row();
                                                ui.label("ISP");
                                                ui.label(d.isp.as_deref().unwrap_or("—"));
                                                ui.end_row();
                                            }
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
                        })
                }
                OpenWindow::ReportedDetails { ip, .. } => {
                    egui::Window::new(format!("Reported \u{00b7} {ip}"))
                        .id(egui::Id::new(id))
                        .open(&mut open)
                        .resizable(true)
                        .default_width(440.0)
                        .default_height(260.0)
                        .show(&ctx, |ui| {
                            match reported_list.iter().find(|r| r.ip == *ip) {
                                Some(rep) => {
                                    egui::Grid::new("reported_details")
                                        .striped(true)
                                        .min_col_width(90.0)
                                        .show(ui, |ui| {
                                            ui.strong("IP");
                                            ui.label(&rep.ip);
                                            ui.end_row();
                                            ui.strong("Reported at");
                                            ui.label(fmt_ts(rep.reported_at));
                                            ui.end_row();
                                            ui.strong("Notes");
                                            // Read-only: render the notes as a
                                            // disabled multiline text area so long
                                            // notes wrap instead of overflowing.
                                            let notes = rep.notes.clone();
                                            ui.add(
                                                egui::TextEdit::multiline(&mut notes.as_str())
                                                    .desired_width(320.0)
                                                    .interactive(false),
                                            );
                                            ui.end_row();
                                        });
                                }
                                None => {
                                    // The flag was removed (by us or another
                                    // dashboard instance) since the window opened.
                                    ui.colored_label(GRAY, "No longer reported.");
                                }
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui.button("Open IP report").clicked() {
                                    actions.push(Action::OpenReport(ReportKind::Ip, ip.clone()));
                                }
                                if ui.button("Edit in manager").clicked() {
                                    actions.push(Action::OpenReportedManager {
                                        prefill_ip: Some(ip.clone()),
                                    });
                                }
                            });
                        })
                }
                OpenWindow::ReportedManager {
                    new_ip,
                    new_notes,
                    notes_edit,
                    ..
                } => {
                    egui::Window::new(format!("Reported IPs ({})", reported_list.len()))
                        .id(egui::Id::new(id))
                        .open(&mut open)
                        .resizable(true)
                        .default_width(640.0)
                        .default_height(460.0)
                        .show(&ctx, |ui| {
                            if let Some(e) = &reported_error {
                                ui.colored_label(RED, e);
                            }
                            // --- Add form ---------------------------------------------------
                            ui.horizontal(|ui| {
                                ui.strong("IP:");
                                ui.add(egui::TextEdit::singleline(new_ip).desired_width(160.0));
                                ui.strong("Notes:");
                            });
                            ui.add(
                                egui::TextEdit::multiline(new_notes)
                                    .desired_width(560.0)
                                    .desired_rows(2),
                            );
                            ui.horizontal(|ui| {
                                let can_add = !new_ip.trim().is_empty();
                                if ui
                                    .add_enabled(can_add, egui::Button::new("Add report"))
                                    .clicked()
                                {
                                    let ip = new_ip.trim().to_string();
                                    let notes = std::mem::take(new_notes);
                                    new_ip.clear();
                                    actions.push(Action::AddReportedIp { ip, notes });
                                }
                            });
                            ui.separator();
                            // --- Existing flags --------------------------------------------
                            egui::Grid::new("reported_ips_list")
                                .striped(true)
                                .min_col_width(60.0)
                                .show(ui, |ui| {
                                    ui.strong("Reported");
                                    ui.strong("IP");
                                    ui.strong("Notes");
                                    ui.strong("Actions");
                                    ui.end_row();
                                    for r in &reported_list {
                                        ui.label(fmt_ts(r.reported_at));
                                        ui.horizontal(|ui| {
                                            let link_r =
                                                link_label(ui, &r.ip, "double-click for IP report");
                                            if link_r.double_clicked() {
                                                actions.push(Action::OpenReport(
                                                    ReportKind::Ip,
                                                    r.ip.clone(),
                                                ));
                                            }
                                        });
                                        // Keep the notes buffer borrow scoped so the
                                        // "Remove" action below can mutate the map
                                        // without an outstanding alias.
                                        {
                                            let buf = notes_edit
                                                .entry(r.ip.clone())
                                                .or_insert_with(|| r.notes.clone());
                                            ui.add(
                                                egui::TextEdit::multiline(buf)
                                                    .desired_width(220.0)
                                                    .desired_rows(1),
                                            );
                                        }
                                        ui.horizontal(|ui| {
                                            if ui.small_button("Save").clicked() {
                                                if let Some(notes) = notes_edit.get(&r.ip) {
                                                    actions.push(Action::UpdateReportedNotes {
                                                        ip: r.ip.clone(),
                                                        notes: notes.clone(),
                                                    });
                                                }
                                            }
                                            if ui.small_button("Details").clicked() {
                                                actions.push(Action::OpenReportedDetails {
                                                    ip: r.ip.clone(),
                                                });
                                            }
                                            if ui.small_button("Remove").clicked() {
                                                notes_edit.remove(&r.ip);
                                                actions.push(Action::RemoveReportedIp {
                                                    ip: r.ip.clone(),
                                                });
                                            }
                                        });
                                        ui.end_row();
                                    }
                                });
                        })
                }
            };

            // If this window was the topmost area under the pointer when the
            // primary button went down, it becomes the focused window.
            if clicked_layer.is_some_and(|l| l.id == egui::Id::new(id)) {
                new_focus = Some(id);
            }
            w.set_open(open);
        }

        if let Some(id) = new_focus {
            self.focused_window_id = Some(id);
        }

        // F5: refresh the last-interacted ("focused") floating window, or fall
        // back to the main dashboard refresh when none has focus.
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F5)) {
            if let Some(id) = self.focused_window_id {
                actions.push(Action::RefreshWindow(id));
            } else {
                actions.push(Action::Refresh);
            }
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
                Action::RefreshWindow(id) => self.refresh_window(&ctx, id),
                Action::OpenReportedDetails { ip } => self.open_reported_details(&ctx, ip),
                Action::OpenReportedManager { prefill_ip } => {
                    self.open_reported_manager(&ctx, prefill_ip)
                }
                Action::AddReportedIp { ip, notes } => self.spawn_add_reported(&ctx, ip, notes),
                Action::RemoveReportedIp { ip } => self.spawn_remove_reported(&ctx, ip),
                Action::UpdateReportedNotes { ip, notes } => {
                    self.spawn_update_reported_notes(&ctx, ip, notes)
                }
            }
        }

        self.open_windows.retain(|w| w.is_open());

        // Drop focus if the focused window was closed.
        if let Some(fid) = self.focused_window_id {
            if !self.open_windows.iter().any(|w| w.id() == fid) {
                self.focused_window_id = None;
            }
        }

        if self.auto_refresh && self.pool.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
    }
}

// ---- section renderers --------------------------------------------------

/// A dashboard section that can be placed in a responsive column layout.
#[derive(Clone, Copy)]
enum Section {
    LiveSessions,
    RecentAuths,
    RecentConnections,
    RecentSessions,
    TopActivity,
}

fn render_section(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    reported: &HashMap<String, ReportedIp>,
    actions: &mut Vec<Action>,
    top_loading: bool,
    top_error: Option<&str>,
    section: Section,
) {
    match section {
        Section::LiveSessions => render_live_sessions(ui, snap, reported, actions),
        Section::RecentAuths => render_recent_auths(ui, snap, reported, actions),
        Section::RecentConnections => render_recent_connections(ui, snap, reported, actions),
        Section::RecentSessions => render_recent_sessions(ui, snap, reported, actions),
        Section::TopActivity => {
            render_top_lists(ui, snap, reported, actions, top_loading, top_error)
        }
    }
}

/// Pick how many sections sit side-by-side based on the available width,
/// so wide / 4K viewports use horizontal space instead of one tall column.
fn column_count(avail_width: f32) -> usize {
    const MIN_SECTION_WIDTH: f32 = 460.0;
    const MAX_COLUMNS: usize = 3;
    ((avail_width / MIN_SECTION_WIDTH).floor() as usize).clamp(1, MAX_COLUMNS)
}

fn render_live_sessions(
    ui: &mut egui::Ui,
    snap: &DashboardSnapshot,
    reported: &HashMap<String, ReportedIp>,
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
                ui.horizontal(|ui| {
                    reported_marker(ui, &s.ip, reported, actions);
                    let r = link_label(ui, &s.ip, "double-click for session detail");
                    if r.double_clicked() {
                        actions.push(Action::OpenSession {
                            auth_id: s.auth_id.clone(),
                            ip: s.ip.clone(),
                            username: s.username.clone(),
                            start_time: Some(s.start_time),
                        });
                    }
                });
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
    reported: &HashMap<String, ReportedIp>,
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
                ui.horizontal(|ui| {
                    reported_marker(ui, &a.ip, reported, actions);
                    let r = link_label(ui, &a.ip, "double-click for IP report");
                    if r.double_clicked() {
                        actions.push(Action::OpenReport(ReportKind::Ip, a.ip.clone()));
                    }
                });
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
    reported: &HashMap<String, ReportedIp>,
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
                ui.horizontal(|ui| {
                    reported_marker(ui, &c.ip, reported, actions);
                    let r = link_label(ui, &c.ip, "double-click for IP report");
                    if r.double_clicked() {
                        actions.push(Action::OpenReport(ReportKind::Ip, c.ip.clone()));
                    }
                });
                ui.label(
                    c.port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "—".to_string()),
                );
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
    reported: &HashMap<String, ReportedIp>,
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
                ui.horizontal(|ui| {
                    reported_marker(ui, &s.ip, reported, actions);
                    let r = link_label(ui, &s.ip, "double-click for session detail");
                    if r.double_clicked() {
                        actions.push(Action::OpenSession {
                            auth_id: s.auth_id.clone(),
                            ip: s.ip.clone(),
                            username: s.username.clone(),
                            start_time: Some(s.start_time),
                        });
                    }
                });
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
    reported: &HashMap<String, ReportedIp>,
    actions: &mut Vec<Action>,
    loading: bool,
    error: Option<&str>,
) {
    let header = if loading {
        "Top Activity  (loading…)"
    } else {
        "Top Activity"
    };
    section_header(ui, header);
    if let Some(e) = error {
        ui.colored_label(RED, format!("Top stats error: {e}"));
    }
    ui.columns(3, |cols| {
        render_top_list(
            &mut cols[0],
            "Top IPs",
            &snap.top_ips,
            reported,
            actions,
            Some(ReportKind::Ip),
            loading,
        );
        render_top_list(
            &mut cols[1],
            "Top Passwords",
            &snap.top_passwords,
            reported,
            actions,
            Some(ReportKind::Password),
            loading,
        );
        render_top_list(
            &mut cols[2],
            "Top Usernames",
            &snap.top_usernames,
            reported,
            actions,
            None,
            loading,
        );
    });
}

fn render_top_list(
    ui: &mut egui::Ui,
    title: &str,
    entries: &[common::dashboard::TopEntry],
    reported: &HashMap<String, ReportedIp>,
    actions: &mut Vec<Action>,
    kind: Option<ReportKind>,
    loading: bool,
) {
    ui.strong(title);
    if entries.is_empty() {
        if loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.colored_label(GRAY, "Loading…");
            });
        } else {
            ui.colored_label(GRAY, "No data.");
        }
        return;
    }
    egui::Grid::new(title)
        .striped(true)
        .min_col_width(40.0)
        .show(ui, |ui| {
            for e in entries {
                match kind {
                    // Only IP entries can carry a reported flag; the marker is
                    // bundled with the link inside one grid cell.
                    Some(ReportKind::Ip) => {
                        ui.horizontal(|ui| {
                            reported_marker(ui, &e.value, reported, actions);
                            let r = link_label(ui, &e.value, "double-click to open report");
                            if r.double_clicked() {
                                actions.push(Action::OpenReport(ReportKind::Ip, e.value.clone()));
                            }
                        });
                    }
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

/// Normalise an IP string for matching against the reported map: trim and
/// lowercase. Postgres `host(ip)` already drops the CIDR mask, so this only
/// guards against stray whitespace / casing differences at the UI layer.
fn normalize_ip(ip: &str) -> String {
    ip.trim().to_lowercase()
}

/// Build the O(1) reported-IP lookup map from the snapshot list. Keys are
/// normalised so `reported_marker` lookups are case/whitespace insensitive.
fn build_reported_map(list: &[ReportedIp]) -> HashMap<String, ReportedIp> {
    list.iter()
        .map(|r| (normalize_ip(&r.ip), r.clone()))
        .collect()
}

/// Draw the "reported" flag marker in front of an IP row when `ip` is in the
/// reported map. Hovering shows the report timestamp; a double-click opens the
/// read-only reported-IP details window. No-op for IPs that aren't reported,
/// so callers can drop it unconditionally into any IP row.
fn reported_marker(
    ui: &mut egui::Ui,
    ip: &str,
    reported: &HashMap<String, ReportedIp>,
    actions: &mut Vec<Action>,
) {
    let Some(rep) = reported.get(&normalize_ip(ip)) else {
        return;
    };
    let r = ui.add(
        egui::Label::new(egui::RichText::new("\u{2691}").color(ORANGE).strong())
            .sense(egui::Sense::click()),
    );
    let r = r.on_hover_text(format!(
        "Reported {} \u{2014} double-click for details",
        fmt_ts(rep.reported_at)
    ));
    if r.double_clicked() {
        actions.push(Action::OpenReportedDetails { ip: rep.ip.clone() });
    }
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

// ---- LISTEN/NOTIFY listener --------------------------------------------

/// Owns the long-lived `PgListener`. Reconnects with a short backoff whenever
/// the session errors out (network blip, server restart). Aborted externally
/// via the stored `JoinHandle` when the dashboard reconnects to another DB.
async fn run_notify_listener(db_url: String, tx: mpsc::Sender<AppEvent>, ctx: egui::Context) {
    loop {
        match run_listener_session(&db_url, tx.clone(), &ctx).await {
            Ok(()) => {
                // Only returns Ok if the inner infinite loop broke, which it
                // never does; pause defensively before re-looping anyway.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err(e) => {
                log::warn!("LISTEN/NOTIFY session ended: {e}; reconnecting in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// One listener lifetime: connect, subscribe to all channels, then loop on
/// `recv()`. Any error propagates so the caller can reconnect.
async fn run_listener_session(
    db_url: &str,
    tx: mpsc::Sender<AppEvent>,
    ctx: &egui::Context,
) -> Result<(), sqlx::Error> {
    let mut listener = PgListener::connect(db_url).await?;
    for ch in NOTIFY_CHANNELS {
        listener.listen(ch).await?;
    }
    log::info!("Dashboard LISTEN/NOTIFY active on {NOTIFY_CHANNELS:?}");
    loop {
        let notification = listener.recv().await?;
        // Map the borrowed channel name to a 'static str so it can ride the
        // event channel without a lifetime obligation. Unknown channels (e.g.
        // added by future code) are ignored.
        let channel = match notification.channel() {
            "auth_new" => Some("auth_new"),
            "conn_new" => Some("conn_new"),
            "session_change" => Some("session_change"),
            "reported_ip_change" => Some("reported_ip_change"),
            _ => None,
        };
        if let Some(ch) = channel {
            let _ = tx.send(AppEvent::Notify(ch));
            ctx.request_repaint();
        }
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SSH Honeypot Dashboard")
            .with_inner_size([1200.0, 780.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SSH Honeypot Dashboard",
        options,
        Box::new(|_cc| Ok(Box::new(DashboardApp::new()))),
    )
}
