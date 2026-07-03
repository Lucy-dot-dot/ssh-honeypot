use eframe::egui;
use ssh_honeypot::db::initialize_database_pool;
use ssh_honeypot::report::{ReportFormat, ReportGenerator};
use sqlx::PgPool;
use std::sync::mpsc;

const DEFAULT_DB_URL: &str = "postgresql://honeypot:honeypot@localhost:5432/ssh_honeypot";

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SSH Honeypot Report Viewer")
            .with_inner_size([900.0, 700.0]),
        ..Default::default()
    };
    eframe::run_native(
        "SSH Honeypot Report Viewer",
        options,
        Box::new(|_cc| Ok(Box::new(ReportApp::new()))),
    )
}

#[derive(PartialEq, Clone, Copy)]
enum ReportType {
    Ip,
    Password,
}

enum AsyncResult {
    Connected(PgPool),
    ConnectionFailed(String),
    Report {
        text: String,
        isp: Option<String>,
        org: Option<String>,
    },
    ReportFailed(String),
}

struct ReportApp {
    db_url: String,
    pool: Option<PgPool>,
    connection_status: String,
    is_connecting: bool,

    report_type: ReportType,
    query_input: String,
    extended_info: bool,
    report_text: String,
    report_isp: Option<String>,
    report_org: Option<String>,
    is_loading: bool,

    runtime: tokio::runtime::Runtime,
    rx: Option<mpsc::Receiver<AsyncResult>>,
}

impl ReportApp {
    fn new() -> Self {
        Self {
            db_url: DEFAULT_DB_URL.to_string(),
            pool: None,
            connection_status: "Not connected".to_string(),
            is_connecting: false,
            report_type: ReportType::Ip,
            query_input: String::new(),
            extended_info: false,
            report_text: String::new(),
            report_isp: None,
            report_org: None,
            is_loading: false,
            runtime: tokio::runtime::Runtime::new().expect("failed to create tokio runtime"),
            rx: None,
        }
    }

    fn connect(&mut self, ctx: egui::Context) {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.is_connecting = true;
        self.pool = None;
        self.connection_status = "Connecting…".to_string();

        let db_url = self.db_url.clone();
        self.runtime.spawn(async move {
            let result = initialize_database_pool(&db_url, true).await;
            let msg = match result {
                Ok(pool) => AsyncResult::Connected(pool),
                Err(e) => AsyncResult::ConnectionFailed(e.to_string()),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    fn generate_report(&mut self, ctx: egui::Context) {
        let pool = match &self.pool {
            Some(p) => p.clone(),
            None => return,
        };

        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        self.is_loading = true;
        self.report_text = String::new();
        self.report_isp = None;
        self.report_org = None;

        let query = self.query_input.trim().to_string();
        let report_type = self.report_type;
        let extended_info = self.extended_info;

        self.runtime.spawn(async move {
            let generator = ReportGenerator::new(pool);

            let (isp, org) = if report_type == ReportType::Ip {
                generator.get_ip_isp_org(&query).await.unwrap_or((None, None))
            } else {
                (None, None)
            };

            let result = match report_type {
                ReportType::Ip => {
                    generator
                        .generate_ip_report(&query, &ReportFormat::Text, extended_info)
                        .await
                }
                ReportType::Password => {
                    generator.generate_password_report(&query, &ReportFormat::Text).await
                }
            };

            let msg = match result {
                Ok(text) => AsyncResult::Report { text, isp, org },
                Err(e) => AsyncResult::ReportFailed(e.to_string()),
            };
            let _ = tx.send(msg);
            ctx.request_repaint();
        });
    }

    fn poll_receiver(&mut self) {
        let msg = self.rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some(msg) = msg {
            self.rx = None;
            match msg {
                AsyncResult::Connected(pool) => {
                    self.pool = Some(pool);
                    self.is_connecting = false;
                    self.connection_status = "Connected".to_string();
                }
                AsyncResult::ConnectionFailed(e) => {
                    self.is_connecting = false;
                    self.connection_status = format!("Failed: {}", e);
                }
                AsyncResult::Report { text, isp, org } => {
                    self.is_loading = false;
                    self.report_text = text;
                    self.report_isp = isp;
                    self.report_org = org;
                }
                AsyncResult::ReportFailed(e) => {
                    self.is_loading = false;
                    self.report_text = format!("Error generating report:\n{}", e);
                }
            }
        }
    }
}

impl eframe::App for ReportApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_receiver();

        let ctx = ui.ctx().clone();

        egui::Panel::top("connection_panel").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Database URL:");
                ui.add_sized(
                    [450.0, 20.0],
                    egui::TextEdit::singleline(&mut self.db_url),
                );

                let connect_label = if self.is_connecting { "Connecting…" } else { "Connect" };
                if ui
                    .add_enabled(!self.is_connecting, egui::Button::new(connect_label))
                    .clicked()
                {
                    self.connect(ctx.clone());
                }

                let status_color = if self.pool.is_some() {
                    egui::Color32::from_rgb(80, 180, 80)
                } else if self.connection_status.starts_with("Failed") {
                    egui::Color32::from_rgb(220, 60, 60)
                } else {
                    egui::Color32::GRAY
                };
                ui.colored_label(status_color, &self.connection_status);
            });
            ui.add_space(6.0);
        });

        egui::Panel::top("query_panel").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Report type:");
                ui.radio_value(&mut self.report_type, ReportType::Ip, "IP Address");
                ui.radio_value(&mut self.report_type, ReportType::Password, "Password");

                ui.separator();

                ui.add_enabled(
                    self.report_type == ReportType::Ip,
                    egui::Checkbox::new(&mut self.extended_info, "Extended info"),
                );
                if self.report_type == ReportType::Ip {
                    ui.label(
                        egui::RichText::new("(geo / network / threat in text reports)")
                            .small()
                            .color(egui::Color32::DARK_GRAY),
                    );
                }

                ui.separator();

                let hint = match self.report_type {
                    ReportType::Ip => "Enter IP address",
                    ReportType::Password => "Enter password",
                };
                let response = ui.add_sized(
                    [250.0, 20.0],
                    egui::TextEdit::singleline(&mut self.query_input).hint_text(hint),
                );

                let can_generate = self.pool.is_some()
                    && !self.is_loading
                    && !self.query_input.trim().is_empty();
                let gen_label = if self.is_loading { "Loading…" } else { "Generate Report" };

                let submitted = response.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter));

                if ui
                    .add_enabled(can_generate, egui::Button::new(gen_label))
                    .clicked()
                    || (submitted && can_generate)
                {
                    self.generate_report(ctx);
                }

                // ISP / Org badge shown after report is generated
                if self.report_isp.is_some() || self.report_org.is_some() {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(org) = &self.report_org {
                            ui.label(
                                egui::RichText::new(org)
                                    .color(egui::Color32::from_rgb(180, 180, 180))
                                    .size(12.0),
                            );
                            if self.report_isp.is_some() {
                                ui.label(
                                    egui::RichText::new("·")
                                        .color(egui::Color32::GRAY)
                                        .size(12.0),
                                );
                            }
                        }
                        if let Some(isp) = &self.report_isp {
                            ui.label(
                                egui::RichText::new(isp)
                                    .color(egui::Color32::from_rgb(140, 180, 220))
                                    .size(12.0),
                            );
                        }
                    });
                }
            });
            ui.add_space(6.0);
        });

        ui.separator();
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Report Output").strong());
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                if self.report_text.is_empty() {
                    ui.colored_label(
                        egui::Color32::GRAY,
                        "No report generated yet. Connect to the database and click Generate Report.",
                    );
                } else {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.report_text.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    );
                }
            });
    }
}
