//! `ovpn-otp-gui`: the desktop window.
//!
//! Left: the login — user name, password (hidden, with a Show toggle), a
//! Remember box, and a separate, visible box for the authenticator code.
//! Right: what is going on — status, traffic, timeline, log, the management
//! transcript, and the settings.

#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;
use std::time::Duration;

use chrono::Local;
use eframe::egui::{self, Color32, RichText};

use ovpn_otp_core::credentials::{CredentialStore, KeyringStore, Login, Secret};
use ovpn_otp_core::mgmt::LogLevel;
use ovpn_otp_core::runtime::{Recorder, RuntimeDir};
use ovpn_otp_core::session::{validate_code, CodeReason, Direction, Event, SessionHandle};
use ovpn_otp_core::settings::{self, LoadedSettings, Settings};
use ovpn_otp_core::snapshot::{format_bytes, format_duration, Phase, Snapshot};
use ovpn_otp_core::{connect, diagnostics};

fn main() -> eframe::Result {
    let path = settings::settings_path(std::env::args_os().nth(1).map(PathBuf::from).as_deref());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ovpn-otp")
            .with_inner_size([980.0, 640.0])
            .with_min_inner_size([720.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "ovpn-otp",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(path)))),
    )
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Timeline,
    Log,
    Wire,
    Settings,
}

struct Running {
    handle: SessionHandle,
    recorder: Recorder,
    config_path: PathBuf,
}

struct App {
    loaded: LoadedSettings,
    load_error: Option<String>,
    username: String,
    password: String,
    show_password: bool,
    remember: bool,
    had_saved_login: bool,
    code: String,
    focus_code: bool,
    session: Option<Running>,
    snap: Snapshot,
    tab: Tab,
    log_min: LogLevel,
    message: Option<(bool, String)>,
    edit: Settings,
    prefix_text: String,
    extra_text: String,
}

impl App {
    fn new(path: PathBuf) -> App {
        let (loaded, load_error) = match settings::load(&path) {
            Ok(l) => (l, None),
            Err(e) => (
                LoadedSettings {
                    path: path.clone(),
                    settings: Settings::default(),
                },
                Some(e.to_string()),
            ),
        };
        let mut app = App {
            edit: loaded.settings.clone(),
            prefix_text: String::new(),
            extra_text: String::new(),
            loaded,
            load_error,
            username: String::new(),
            password: String::new(),
            show_password: false,
            remember: true,
            had_saved_login: false,
            code: String::new(),
            focus_code: true,
            session: None,
            snap: Snapshot::default(),
            tab: Tab::Timeline,
            log_min: LogLevel::Info,
            message: None,
        };
        app.reset_edit();
        app.load_login();
        if app.load_error.is_some() || app.loaded.profile_text().is_err() {
            app.tab = Tab::Settings;
        }
        app
    }

    fn reset_edit(&mut self) {
        self.edit = self.loaded.settings.clone();
        self.prefix_text = self
            .edit
            .openvpn
            .linux
            .command_prefix
            .as_ref()
            .map(|v| v.join(" "))
            .unwrap_or_else(|| "(default: sudo -n)".into());
        self.extra_text = self.edit.openvpn.extra_options.join("\n");
    }

    fn load_login(&mut self) {
        match KeyringStore.load(&self.loaded.settings.name) {
            Ok(Some(l)) => {
                self.username = l.username;
                self.password = l.password.expose().to_string();
                self.remember = true;
                self.had_saved_login = true;
            }
            Ok(None) => self.had_saved_login = false,
            Err(e) => self.message = Some((true, format!("Cannot read the saved login: {e}"))),
        }
    }

    fn digits(&self) -> u8 {
        self.loaded.settings.code.digits
    }

    fn is_active(&self) -> bool {
        self.session.is_some()
    }

    fn connect(&mut self) {
        self.message = None;
        let code = match validate_code(&self.code, self.digits()) {
            Ok(c) => c,
            Err(e) => {
                self.message = Some((true, e));
                self.focus_code = true;
                return;
            }
        };
        if self.username.trim().is_empty() || self.password.is_empty() {
            self.message = Some((true, "Enter your user name and password.".into()));
            return;
        }
        let login = Login {
            username: self.username.trim().to_string(),
            password: Secret::new(self.password.clone()),
        };
        let name = self.loaded.settings.name.clone();
        if self.remember {
            match KeyringStore.save(&name, &login) {
                Ok(()) => self.had_saved_login = true,
                Err(e) => self.message = Some((true, format!("Could not save the login: {e}"))),
            }
        } else if self.had_saved_login {
            let _ = KeyringStore.delete(&name);
            self.had_saved_login = false;
        }
        let rt = match RuntimeDir::open() {
            Ok(r) => r,
            Err(e) => {
                self.message = Some((true, format!("Cannot create the runtime folder: {e}")));
                return;
            }
        };
        if let Some(live) = rt.live_session() {
            self.message = Some((
                true,
                format!(
                    "Another session is already running (process {}). Disconnect it first.",
                    live.pid
                ),
            ));
            return;
        }
        match connect::prepare(&self.loaded, &rt, login, Some(code)) {
            Ok(prepared) => {
                let recorder = Recorder::new(rt, &name, &self.loaded.path);
                let (handle, config_path) = prepared.start();
                self.snap = Snapshot::default();
                self.code.clear();
                self.session = Some(Running {
                    handle,
                    recorder,
                    config_path,
                });
            }
            Err(e) => self.message = Some((true, e.to_string())),
        }
    }

    fn send_code(&mut self) {
        match validate_code(&self.code, self.digits()) {
            Ok(c) => {
                if let Some(s) = &self.session {
                    s.handle.send_code(&c);
                }
                self.code.clear();
                self.message = None;
            }
            Err(e) => {
                self.message = Some((true, e));
                self.focus_code = true;
            }
        }
    }

    fn disconnect(&mut self) {
        if let Some(s) = &self.session {
            s.handle.disconnect();
        }
    }

    /// Take in session events. Called every frame and while hidden.
    fn pump(&mut self, ctx: &egui::Context) {
        let Some(run) = self.session.as_mut() else {
            return;
        };
        let mut ended = false;
        let mut need_code = false;
        while let Ok(ev) = run.handle.events().try_recv() {
            run.recorder.record(&ev);
            self.snap.apply(&ev);
            match ev {
                Event::NeedCode { .. } => need_code = true,
                Event::Ended { .. } => ended = true,
                _ => {}
            }
        }
        if run.recorder.dir().take_stop_request() {
            run.handle.disconnect();
        }
        // A code from `ovpn-otp code`.
        if let Some(code) = run.recorder.dir().take_code() {
            run.handle.send_code(&code);
        }
        run.recorder.write_status(&self.snap, !ended, ended);
        if need_code {
            self.focus_code = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Critical,
            ));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if ended {
            if let Some(run) = self.session.take() {
                let _ = std::fs::remove_file(&run.config_path);
                run.handle.join();
            }
        }
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn login_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("ovpn-otp");
        let server = self
            .snap
            .server
            .clone()
            .chars()
            .take(40)
            .collect::<String>();
        ui.label(
            RichText::new(format!(
                "Connection \"{}\"{}",
                self.loaded.settings.name,
                if server.is_empty() {
                    String::new()
                } else {
                    format!(" · {server}")
                }
            ))
            .weak(),
        );
        ui.add_space(12.0);
        let active = self.is_active();

        ui.label("User name");
        ui.add_enabled(
            !active,
            egui::TextEdit::singleline(&mut self.username).desired_width(f32::INFINITY),
        );
        ui.add_space(6.0);
        ui.label("Password");
        ui.horizontal(|ui| {
            ui.add_enabled(
                !active,
                egui::TextEdit::singleline(&mut self.password)
                    .password(!self.show_password)
                    .desired_width(ui.available_width() - 60.0),
            );
            ui.toggle_value(&mut self.show_password, "Show");
        });
        ui.add_enabled(
            !active,
            egui::Checkbox::new(&mut self.remember, "Remember user name and password"),
        )
        .on_hover_text(if cfg!(windows) {
            "Kept in Windows Credential Manager, never in a file."
        } else {
            "Kept in your desktop keyring (Secret Service), never in a file."
        });

        ui.add_space(14.0);
        let digits = self.digits();
        let waiting = self.snap.phase == Phase::NeedCode;
        let label = match self.snap.code_reason {
            Some(CodeReason::Reconnect) if waiting => "Reconnecting: enter a new code",
            Some(CodeReason::Rejected) if waiting => "Login rejected: enter a new code",
            Some(CodeReason::Expired) if waiting => "Code too old: enter a new code",
            Some(CodeReason::Retry) if waiting => "The last try failed: enter a new code",
            _ if waiting => "The server is waiting for your code",
            _ => "Authenticator code",
        };
        ui.label(if waiting {
            RichText::new(label)
                .strong()
                .color(Color32::from_rgb(230, 160, 40))
        } else {
            RichText::new(label)
        });
        let can_type = !active || waiting;
        let resp = ui.add_enabled(
            can_type,
            egui::TextEdit::singleline(&mut self.code)
                .font(egui::TextStyle::Heading)
                .char_limit(if digits > 0 { digits as usize } else { 12 })
                .hint_text("123456")
                .desired_width(f32::INFINITY),
        );
        self.code.retain(|c| c.is_ascii_digit());
        if self.focus_code && can_type {
            resp.request_focus();
            self.focus_code = false;
        }
        ui.label(
            RichText::new(format!(
                "{} of {digits} digits · shown as you type, sent after your password",
                self.code.len()
            ))
            .small()
            .weak(),
        );
        let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

        ui.add_space(14.0);
        if !active {
            let go = ui
                .add_sized([ui.available_width(), 32.0], egui::Button::new("Connect"))
                .clicked();
            if go || enter {
                self.connect();
            }
        } else {
            if waiting {
                let go = ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("Send code"))
                    .clicked();
                if go || enter {
                    self.send_code();
                }
                ui.add_space(6.0);
            }
            if ui
                .add_sized(
                    [ui.available_width(), 28.0],
                    egui::Button::new("Disconnect"),
                )
                .clicked()
            {
                self.disconnect();
            }
        }
        if let Some((is_err, msg)) = &self.message {
            ui.add_space(8.0);
            let color = if *is_err {
                Color32::from_rgb(220, 80, 80)
            } else {
                ui.visuals().text_color()
            };
            ui.label(RichText::new(msg).color(color));
        }
        if let Some(e) = &self.load_error {
            ui.add_space(8.0);
            ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 80)));
        }
    }

    fn status_card(&mut self, ui: &mut egui::Ui) {
        let s = &self.snap;
        let now = Local::now();
        let color = match s.phase {
            Phase::Connected => Color32::from_rgb(60, 170, 90),
            Phase::NeedCode | Phase::Reconnecting => Color32::from_rgb(230, 160, 40),
            Phase::Failed => Color32::from_rgb(220, 80, 80),
            Phase::Idle | Phase::Disconnected => ui.visuals().weak_text_color(),
            _ => Color32::from_rgb(80, 140, 220),
        };
        ui.horizontal(|ui| {
            // A painted dot: the default fonts have no "●" glyph.
            let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 6.0, color);
            ui.label(RichText::new(s.phase.label()).size(20.0).strong());
            if !s.state.is_empty() && s.phase.is_active() {
                ui.label(RichText::new(format!("OpenVPN: {} {}", s.state, s.state_detail)).weak());
            }
            if let Some(at) = s.next_retry.filter(|t| *t > now) {
                ui.label(format!("· next try in {}s", (at - now).num_seconds()));
            }
        });
        if let (Some(e), false) = (&s.last_error, s.phase == Phase::Connected) {
            ui.label(RichText::new(e).color(Color32::from_rgb(220, 80, 80)));
        }
        ui.add_space(4.0);
        egui::Grid::new("status")
            .num_columns(4)
            .spacing([24.0, 4.0])
            .show(ui, |ui| {
                let dash = |v: &str| {
                    if v.is_empty() {
                        "-".to_string()
                    } else {
                        v.to_string()
                    }
                };
                ui.label("Server");
                ui.monospace(dash(&s.server));
                ui.label("Tunnel address");
                ui.monospace(dash(&s.local_ip));
                ui.end_row();
                ui.label("Received");
                ui.monospace(format!(
                    "{} · {}/s",
                    format_bytes(s.bytes_in),
                    format_bytes(s.rate_in as u64)
                ));
                ui.label("Sent");
                ui.monospace(format!(
                    "{} · {}/s",
                    format_bytes(s.bytes_out),
                    format_bytes(s.rate_out as u64)
                ));
                ui.end_row();
                ui.label("Connected for");
                ui.monospace(
                    s.connected_since
                        .map(|t| format_duration((now - t).num_seconds()))
                        .unwrap_or_else(|| "-".into()),
                );
                ui.label("Last data received");
                ui.monospace(
                    s.idle_secs(now)
                        .map(|i| format!("{} ago", format_duration(i)))
                        .unwrap_or_else(|| "-".into()),
                );
                ui.end_row();
                ui.label("Reach check");
                match &s.reach {
                    Some(r) => match (r.ok, r.latency_ms) {
                        (true, Some(ms)) => ui.monospace(format!("{} · {ms:.1} ms", r.target)),
                        _ => ui.label(
                            RichText::new(format!(
                                "{} · {}",
                                r.target,
                                r.error.clone().unwrap_or_else(|| "failed".into())
                            ))
                            .monospace()
                            .color(Color32::from_rgb(220, 80, 80)),
                        ),
                    },
                    None => ui.monospace(if self.loaded.settings.check.host.is_empty() {
                        "off (set a host in Settings)".to_string()
                    } else {
                        "-".to_string()
                    }),
                };
                ui.label("DNS");
                ui.monospace(if s.dns.is_empty() {
                    "-".into()
                } else {
                    s.dns.join(", ")
                });
                ui.end_row();
                ui.label("Routes");
                ui.monospace(if s.routes.is_empty() {
                    "-".into()
                } else {
                    s.routes.join(", ")
                });
                ui.label("OpenVPN");
                ui.monospace(
                    s.openvpn_version
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                ui.end_row();
            });
    }

    fn timeline_tab(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                if self.snap.timeline.is_empty() {
                    ui.label(
                        RichText::new(
                            "Nothing yet. Each connection step shows up here with its time.",
                        )
                        .weak(),
                    );
                }
                egui::Grid::new("timeline").striped(true).show(ui, |ui| {
                    for t in &self.snap.timeline {
                        ui.monospace(t.at.format("%H:%M:%S").to_string());
                        ui.monospace(RichText::new(&t.state).strong());
                        ui.label(&t.detail);
                        ui.end_row();
                    }
                });
            });
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Show");
            egui::ComboBox::from_id_salt("level")
                .selected_text(match self.log_min {
                    LogLevel::Debug => "everything",
                    LogLevel::Info => "info and above",
                    LogLevel::Warning => "warnings and errors",
                    _ => "errors only",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.log_min, LogLevel::Debug, "everything");
                    ui.selectable_value(&mut self.log_min, LogLevel::Info, "info and above");
                    ui.selectable_value(
                        &mut self.log_min,
                        LogLevel::Warning,
                        "warnings and errors",
                    );
                    ui.selectable_value(&mut self.log_min, LogLevel::Error, "errors only");
                });
        });
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for l in self.snap.logs.iter().filter(|l| l.level >= self.log_min) {
                    let color = match l.level {
                        LogLevel::Fatal | LogLevel::Error => Color32::from_rgb(220, 80, 80),
                        LogLevel::Warning => Color32::from_rgb(220, 160, 40),
                        LogLevel::Debug => ui.visuals().weak_text_color(),
                        LogLevel::Info => ui.visuals().text_color(),
                    };
                    ui.label(
                        RichText::new(format!(
                            "{} {:<7} {}",
                            l.at.format("%H:%M:%S"),
                            l.source,
                            l.message
                        ))
                        .monospace()
                        .color(color),
                    );
                }
            });
    }

    fn wire_tab(&self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(
                "Every line between this app and OpenVPN's management interface. \
                 Passwords, codes and session tokens are replaced with ********.",
            )
            .weak(),
        );
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for w in &self.snap.wire {
                    let (arrow, color) = match w.dir {
                        Direction::In => ("<-", ui.visuals().text_color()),
                        Direction::Out => ("->", Color32::from_rgb(80, 140, 220)),
                    };
                    ui.label(
                        RichText::new(format!("{} {arrow} {}", w.at.format("%H:%M:%S"), w.text))
                            .monospace()
                            .color(color),
                    );
                }
            });
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let active = self.is_active();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.label(
                RichText::new(format!(
                    "Settings file: {}. Put it in a synced folder or private git repository to share it \
                     between machines; it never holds your password. Set OVPN_OTP_CONFIG to point at it.",
                    self.loaded.path.display()
                ))
                .weak(),
            );
            ui.add_space(6.0);
            let e = &mut self.edit;
            egui::Grid::new("settings").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                ui.label("Connection name");
                ui.text_edit_singleline(&mut e.name)
                    .on_hover_text("The saved login is stored under this name.");
                ui.end_row();
                ui.label("Profile (.ovpn)");
                ui.text_edit_singleline(&mut e.profile.path)
                    .on_hover_text("A relative path is relative to the settings file.");
                ui.end_row();
                ui.label("Server override");
                ui.add(egui::TextEdit::singleline(&mut e.profile.remote).hint_text("host:port, empty = use the profile"));
                ui.end_row();
                ui.label("Private server addresses");
                ui.checkbox(&mut e.profile.allow_private_remotes, "Also try them when the profile has a public one")
                    .on_hover_text("Addresses such as 10.x.x.x or 192.168.x.x only answer inside that network. Off: they are skipped, so a failed try does not wait on them.");
                ui.end_row();
                ui.label("Keep-alive ping (s)");
                ui.add(egui::DragValue::new(&mut e.keepalive.ping).range(0..=3600))
                    .on_hover_text("OpenVPN sends a ping this often. 0 = use the profile's value.");
                ui.end_row();
                ui.label("Restart after silence (s)");
                ui.add(egui::DragValue::new(&mut e.keepalive.ping_restart).range(0..=36000))
                    .on_hover_text("If nothing arrives for this long, OpenVPN restarts the connection. 0 = use the profile's value.");
                ui.end_row();
                ui.label("Reconnect after a drop");
                ui.checkbox(&mut e.keepalive.auto_reconnect, "Reconnect automatically (asks for a new code)");
                ui.end_row();
                ui.label("Wait between tries (s)");
                ui.horizontal(|ui| {
                    ui.add(egui::DragValue::new(&mut e.keepalive.backoff_initial).range(1..=600));
                    ui.label("doubling up to");
                    ui.add(egui::DragValue::new(&mut e.keepalive.backoff_max).range(1..=3600));
                });
                ui.end_row();
                ui.label("Reach check host");
                ui.add(egui::TextEdit::singleline(&mut e.check.host).hint_text("10.0.0.1 or 10.0.0.1:443, empty = off"))
                    .on_hover_text("A host behind the VPN. host:port opens a TCP connection; a bare host uses ping.");
                ui.end_row();
                ui.label("Check every (s)");
                ui.add(egui::DragValue::new(&mut e.check.interval).range(2..=3600));
                ui.end_row();
                ui.label("Code digits");
                ui.add(egui::DragValue::new(&mut e.code.digits).range(0..=12))
                    .on_hover_text("0 accepts any length.");
                ui.end_row();
                let plat = if cfg!(windows) { &mut e.openvpn.windows } else { &mut e.openvpn.linux };
                ui.label("openvpn program");
                ui.add(egui::TextEdit::singleline(&mut plat.path).hint_text("empty = find it"));
                ui.end_row();
                if cfg!(windows) {
                    ui.label("Start OpenVPN via");
                    egui::ComboBox::from_id_salt("launch")
                        .selected_text(if plat.launch.is_empty() { "auto" } else { plat.launch.as_str() })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut plat.launch, String::new(), "auto");
                            ui.selectable_value(&mut plat.launch, "service".into(), "service (no admin rights)");
                            ui.selectable_value(&mut plat.launch, "direct".into(), "direct (needs admin)");
                        });
                    ui.end_row();
                } else {
                    ui.label("Run openvpn with");
                    ui.text_edit_singleline(&mut self.prefix_text)
                        .on_hover_text("A command that gives openvpn network rights, e.g. `sudo -n` or `pkexec`. Leave empty if openvpn already has them.");
                    ui.end_row();
                }
                ui.label("Extra OpenVPN options");
                ui.add(egui::TextEdit::multiline(&mut self.extra_text).desired_rows(2).hint_text("one per line, like: verb 4"));
                ui.end_row();
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.add_enabled(!active, egui::Button::new("Save settings")).clicked() {
                    self.save_settings();
                }
                if ui.button("Undo changes").clicked() {
                    self.reset_edit();
                }
                if ui
                    .add_enabled(self.had_saved_login && !active, egui::Button::new("Forget saved login"))
                    .clicked()
                {
                    let _ = KeyringStore.delete(&self.loaded.settings.name);
                    self.had_saved_login = false;
                    self.password.clear();
                    self.message = Some((false, "Saved login removed.".into()));
                }
            });
            if active {
                ui.label(RichText::new("Disconnect to change settings.").weak());
            }
        });
    }

    fn save_settings(&mut self) {
        let mut s = self.edit.clone();
        if !cfg!(windows) {
            let t = self.prefix_text.trim();
            s.openvpn.linux.command_prefix = if t.starts_with("(default") {
                self.loaded.settings.openvpn.linux.command_prefix.clone()
            } else {
                Some(t.split_whitespace().map(str::to_string).collect())
            };
        }
        s.openvpn.extra_options = self
            .extra_text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        if let Err(e) = ovpn_otp_core::profile::extra_option_lines(&s.openvpn.extra_options) {
            self.message = Some((true, e.to_string()));
            return;
        }
        match settings::save(&self.loaded.path, &s) {
            Ok(()) => {
                let renamed = s.name != self.loaded.settings.name;
                self.loaded.settings = s;
                self.load_error = None;
                self.reset_edit();
                if renamed {
                    self.load_login();
                }
                self.message = Some((false, "Settings saved.".into()));
            }
            Err(e) => self.message = Some((true, e.to_string())),
        }
    }

    fn copy_diagnostics(&mut self, ctx: &egui::Context) {
        let mut text = diagnostics::bundle(
            &self.snap,
            &self.loaded.settings,
            &self.loaded.path.display().to_string(),
            &self.username,
        );
        // The password never reaches the snapshot; remove it anyway if typed.
        if self.password.len() >= 3 {
            text = text.replace(&self.password, "********");
        }
        ctx.copy_text(text);
        self.message = Some((
            false,
            "Diagnostics copied to the clipboard (password and user name removed).".into(),
        ));
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.pump(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        egui::Panel::left("login")
            .resizable(false)
            .exact_size(300.0)
            .show(ui, |ui| self.login_panel(ui));
        egui::Panel::bottom("footer").show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .button("Copy diagnostics")
                    .on_hover_text("A report for troubleshooting, with secrets removed.")
                    .clicked()
                {
                    self.copy_diagnostics(&ctx);
                }
                ui.label(RichText::new(format!("ovpn-otp {}", env!("CARGO_PKG_VERSION"))).weak());
            });
        });
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.status_card(ui);
            ui.separator();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Timeline, "Timeline");
                ui.selectable_value(&mut self.tab, Tab::Log, "Log");
                ui.selectable_value(&mut self.tab, Tab::Wire, "Wire");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
            });
            ui.separator();
            match self.tab {
                Tab::Timeline => self.timeline_tab(ui),
                Tab::Log => self.log_tab(ui),
                Tab::Wire => self.wire_tab(ui),
                Tab::Settings => self.settings_tab(ui),
            }
        });
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Closing the window ends the session cleanly.
        if let Some(mut run) = self.session.take() {
            run.handle.disconnect();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while std::time::Instant::now() < deadline {
                match run.handle.events().recv_timeout(Duration::from_millis(200)) {
                    Ok(ev) => {
                        run.recorder.record(&ev);
                        self.snap.apply(&ev);
                        if matches!(ev, Event::Ended { .. }) {
                            break;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
            run.recorder.write_status(&self.snap, false, true);
            let _ = std::fs::remove_file(&run.config_path);
        }
    }
}
