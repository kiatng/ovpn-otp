//! `ovpn-otp-gui`: the desktop window.
//!
//! One small window with a menu for Connect, Details, Log, Wire and Settings.
//! Connect shows the current connection, the code box and Connect or Disconnect.
//! Each other menu item shows its own view in the window.
//!
//! The window also shows a session that `ovpn-otp connect` started in a
//! terminal, and can give it a code or stop it.

#![cfg_attr(windows, windows_subsystem = "windows")]

// Pictures of the window for the README. Not part of a release build.
#[cfg(feature = "screenshots")]
mod shot;
#[cfg(not(feature = "screenshots"))]
mod shot {
    //! Stands in for `shot.rs` when the `screenshots` feature is off.
    pub struct Shot;

    impl Shot {
        pub fn from_env() -> Option<Shot> {
            None
        }
        pub fn section(&self) -> Option<crate::Section> {
            None
        }
        pub fn login(&self) -> Option<(String, String, String)> {
            None
        }
        pub fn connects(&self) -> bool {
            false
        }
        pub fn tick(&mut self, _ctx: &eframe::egui::Context) {}
    }
}

use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Local;
use eframe::egui::{self, Color32, RichText};

use ovpn_otp_core::credentials::{CredentialStore, KeyringStore, Login, Secret};
use ovpn_otp_core::mgmt::LogLevel;
use ovpn_otp_core::runtime::{Recorder, RuntimeDir, StatusFile, Using};
use ovpn_otp_core::session::{
    validate_code, Direction, Event, Failure, FailureKind, SessionHandle,
};
use ovpn_otp_core::settings::{self, LoadedSettings, Settings};
use ovpn_otp_core::snapshot::{
    format_bytes, format_duration, LogLine, Phase, Snapshot, Tone, WireLine,
};
use ovpn_otp_core::{connect, diagnostics};

/// The window when nothing below the main view is open. The height is then
/// fitted to what is shown.
const START_SIZE: [f32; 2] = [420.0, 290.0];
/// The smallest the window may be made.
const MIN_SIZE: [f32; 2] = [340.0, 220.0];
/// Room for Details, Log, Wire or Settings when one of them is opened.
const SECTION_HEIGHT: f32 = 340.0;
/// The least room such a section needs to be of use.
const SECTION_MIN_HEIGHT: f32 = 160.0;

fn main() -> eframe::Result {
    let requested = std::env::args_os().nth(1).map(PathBuf::from);
    #[cfg(feature = "diagnostic-test")]
    let requested = requested.or_else(|| {
        std::env::current_exe()
            .ok()?
            .parent()
            .map(|dir| dir.join("diagnostic-config.toml"))
            .filter(|p| p.is_file())
    });
    #[cfg(feature = "diagnostic-test")]
    if std::env::var_os(ovpn_otp_core::runtime::RUNTIME_ENV).is_none() {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            std::env::set_var(
                ovpn_otp_core::runtime::RUNTIME_ENV,
                PathBuf::from(local).join("ovpn-otp-test").join("run"),
            );
        }
    }
    let path = settings::settings_path(requested.as_deref());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("ovpn-otp")
            .with_inner_size(START_SIZE)
            .with_min_inner_size(MIN_SIZE),
        ..Default::default()
    };
    eframe::run_native(
        "ovpn-otp",
        options,
        Box::new(move |_cc| Ok(Box::new(App::new(path)))),
    )
}

/// A view other than Connect, selected from the top menu.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Section {
    Details,
    Log,
    Wire,
    Settings,
}

impl Section {
    const ALL: [Section; 4] = [
        Section::Details,
        Section::Log,
        Section::Wire,
        Section::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Section::Details => "Details",
            Section::Log => "Log",
            Section::Wire => "Wire",
            Section::Settings => "Settings",
        }
    }

    /// The section with this name, for a picture of it (see `shot.rs`).
    #[cfg(any(feature = "screenshots", test))]
    fn from_name(name: &str) -> Option<Section> {
        Section::ALL
            .into_iter()
            .find(|s| s.label().eq_ignore_ascii_case(name.trim()))
    }
}

/// A session this window runs itself.
struct Running {
    handle: SessionHandle,
    recorder: Recorder,
    config_path: PathBuf,
}

/// A session that another program runs, such as `ovpn-otp connect` in a
/// terminal. The window shows it, and can give it a code or stop it.
struct Other {
    pid: u32,
    /// Still running. When it has ended, the window keeps showing how.
    live: bool,
}

const GREEN: Color32 = Color32::from_rgb(60, 170, 90);
const BLUE: Color32 = Color32::from_rgb(80, 140, 220);
const AMBER: Color32 = Color32::from_rgb(230, 160, 40);
const RED: Color32 = Color32::from_rgb(220, 80, 80);
const GREY: Color32 = Color32::from_rgb(140, 140, 140);

/// A path cut at the front when it is longer than `max` characters, so that
/// the file name at the end stays in view: `…/vpn/work.ovpn`.
fn end_of_path(path: &str, max: usize) -> String {
    let count = path.chars().count();
    if count <= max || max < 4 {
        return path.to_string();
    }
    let tail: String = path.chars().skip(count - (max - 1)).collect();
    // Start at a folder when one is near, so no name is cut in half.
    let tail = match tail.find(['/', '\\']) {
        Some(i) if i < tail.len() / 2 => &tail[i..],
        _ => tail.as_str(),
    };
    format!("…{tail}")
}

fn tone_color(tone: Tone) -> Color32 {
    match tone {
        Tone::Good => GREEN,
        Tone::Busy => BLUE,
        Tone::Attention => AMBER,
        Tone::Bad => RED,
        Tone::Idle => GREY,
    }
}

struct App {
    update_rx:
        Option<std::sync::mpsc::Receiver<Result<Option<ovpn_otp_core::update::Release>, String>>>,
    update_available: Option<ovpn_otp_core::update::Release>,
    update_installing: bool,
    loaded: LoadedSettings,
    load_error: Option<String>,
    username: String,
    password: String,
    show_password: bool,
    remember: bool,
    had_saved_login: bool,
    /// The user name and password boxes are open although a login is saved.
    edit_login: bool,
    /// Why the login cannot be remembered on this machine, when it cannot.
    store_note: Option<String>,
    code: String,
    focus_code: bool,
    session: Option<Running>,
    other: Option<Other>,
    runtime: Option<RuntimeDir>,
    last_poll: Option<Instant>,
    snap: Snapshot,
    /// The connection, profile, servers and user name in use.
    using: Using,
    section: Option<Section>,
    log_min: LogLevel,
    message: Option<(bool, String)>,
    edit: Settings,
    prefix_text: String,
    extra_text: String,
    verb_edit: u8,
    /// The window height last asked for, so it is asked for once.
    asked_height: Option<f32>,
    shot: Option<shot::Shot>,
    /// Press Connect on the first frame (only for a picture of the window).
    connect_at_start: bool,
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
        let shot = shot::Shot::from_env();
        let mut app = App {
            update_rx: None,
            update_available: None,
            update_installing: false,
            edit: loaded.settings.clone(),
            prefix_text: String::new(),
            extra_text: String::new(),
            verb_edit: 3,
            loaded,
            load_error,
            username: String::new(),
            password: String::new(),
            show_password: false,
            remember: true,
            had_saved_login: false,
            edit_login: false,
            store_note: None,
            code: String::new(),
            focus_code: true,
            session: None,
            other: None,
            runtime: RuntimeDir::open().ok(),
            last_poll: None,
            snap: Snapshot::default(),
            using: Using::default(),
            section: shot.as_ref().and_then(|s| s.section()),
            log_min: LogLevel::Info,
            message: None,
            asked_height: None,
            connect_at_start: shot.as_ref().is_some_and(|s| s.connects()),
            shot,
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(ovpn_otp_core::update::check());
        });
        app.update_rx = Some(rx);
        app.reset_edit();
        app.load_login();
        if let Some((username, password, code)) = app.shot.as_ref().and_then(|s| s.login()) {
            app.username = username;
            app.password = password;
            app.code = code;
        }
        app.refresh_using();
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
        self.verb_edit = self.edit.openvpn.verb.unwrap_or(3);
    }

    fn load_login(&mut self) {
        self.store_note = None;
        match KeyringStore.load(&self.loaded.settings.name) {
            Ok(Some(l)) => {
                self.username = l.username;
                self.password = l.password.expose().to_string();
                self.remember = true;
                self.had_saved_login = true;
            }
            Ok(None) => self.had_saved_login = false,
            Err(e) => {
                // No credential store on this machine: the login can be
                // typed, but not kept.
                self.had_saved_login = false;
                self.remember = false;
                self.store_note = Some(format!(
                    "The login cannot be remembered on this machine ({e})."
                ));
            }
        }
        self.edit_login = false;
    }

    /// Work out again what a connect would use, after the settings or the
    /// user name changed.
    fn refresh_using(&mut self) {
        if !self.is_active() {
            self.using = connect::describe(&self.loaded, &self.username);
        }
    }

    fn digits(&self) -> u8 {
        self.loaded.settings.code.digits
    }

    /// A session is running: one of this window, or one from the command line.
    fn is_active(&self) -> bool {
        self.session.is_some() || self.other.as_ref().is_some_and(|o| o.live)
    }

    fn connect(&mut self) {
        if self.update_installing {
            return;
        }
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
            self.edit_login = true;
            return;
        }
        let login = Login {
            username: self.username.trim().to_string(),
            password: Secret::new(self.password.clone()),
        };
        let name = self.loaded.settings.name.clone();
        if self.remember {
            match KeyringStore.save(&name, &login) {
                Ok(()) => {
                    self.had_saved_login = true;
                    self.edit_login = false;
                }
                Err(e) => {
                    self.remember = false;
                    self.store_note = Some(format!(
                        "The login cannot be remembered on this machine ({e})."
                    ));
                }
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
                self.using = prepared.using.clone();
                let recorder = Recorder::new(rt, prepared.using.clone());
                let (handle, config_path) = prepared.start();
                self.snap = Snapshot::default();
                self.other = None;
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
        let code = match validate_code(&self.code, self.digits()) {
            Ok(c) => c,
            Err(e) => {
                self.message = Some((true, e));
                self.focus_code = true;
                return;
            }
        };
        self.message = None;
        if let Some(s) = &self.session {
            s.handle.send_code(&code);
        } else if let Some(rt) = &self.runtime {
            // The session of another program takes the code from a file.
            if let Err(e) = rt.submit_code(&code) {
                self.message = Some((true, format!("Could not hand over the code: {e}")));
            }
        }
        self.code.clear();
    }

    fn disconnect(&mut self) {
        if let Some(s) = &self.session {
            s.handle.disconnect();
        } else if let Some(rt) = &self.runtime {
            if let Err(e) = rt.request_stop() {
                self.message = Some((true, format!("Could not ask the session to stop: {e}")));
            }
        }
    }

    /// Take in session events. Called every frame and while hidden.
    fn pump(&mut self, ctx: &egui::Context) {
        ctx.request_repaint_after(Duration::from_millis(500));
        if self.session.is_none() {
            self.watch_other(ctx);
            return;
        }
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
            self.ask_for_code(ctx);
        }
        if ended {
            if let Some(run) = self.session.take() {
                let _ = std::fs::remove_file(&run.config_path);
                run.handle.join();
            }
            self.focus_code = true;
        }
    }

    /// Bring the window to the front: the server waits for a code.
    fn ask_for_code(&mut self, ctx: &egui::Context) {
        self.focus_code = true;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Critical,
        ));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Look, twice a second, for a session that another program runs, and
    /// show it.
    fn watch_other(&mut self, ctx: &egui::Context) {
        if self
            .last_poll
            .is_some_and(|t| t.elapsed() < Duration::from_millis(450))
        {
            return;
        }
        self.last_poll = Some(Instant::now());
        let Some(rt) = self.runtime.clone() else {
            return;
        };
        match rt.live_session() {
            Some(st) => {
                let waited = self.snap.phase == Phase::NeedCode;
                self.show_other(&rt, &st);
                self.other = Some(Other {
                    pid: st.pid,
                    live: true,
                });
                if self.snap.phase == Phase::NeedCode && !waited {
                    self.ask_for_code(ctx);
                }
            }
            None => {
                let Some(other) = self.other.as_mut().filter(|o| o.live) else {
                    return;
                };
                // It ended: the last status it wrote says how.
                other.live = false;
                let pid = other.pid;
                match rt.read_status().filter(|s| s.pid == pid) {
                    Some(st) => {
                        self.show_other(&rt, &st);
                        if self.snap.phase.is_active() {
                            // It went away without saying how it ended.
                            self.snap.apply(&Event::Ended {
                                reason: ovpn_otp_core::session::EndReason::Failed(Failure::new(
                                    FailureKind::Failed,
                                    format!(
                                        "The session ended without cleaning up (process {pid} is gone)."
                                    ),
                                )),
                            });
                        }
                    }
                    None => self.snap = Snapshot::default(),
                }
                self.refresh_using();
                self.focus_code = true;
            }
        }
    }

    /// Show the session of another program: its state, what it uses, and its log.
    fn show_other(&mut self, rt: &RuntimeDir, st: &StatusFile) {
        self.snap = st.snapshot.clone();
        self.using = st.using();
        // The log is in its own file; read it only when it is looked at.
        if self.section.is_some() {
            for record in rt.read_log() {
                match record.dir {
                    Some(dir) => self.snap.wire.push_back(WireLine {
                        at: record.at,
                        dir,
                        text: record.message,
                    }),
                    None => self.snap.logs.push_back(LogLine {
                        at: record.at,
                        level: record.level,
                        source: record.source,
                        message: record.message,
                    }),
                }
            }
        }
    }

    // ------------------------------------------------------------ main view

    /// The state in colour and words: Connected, Connecting…, Disconnected, Failed.
    fn banner(&self, ui: &mut egui::Ui) {
        let headline = self.snap.headline(Local::now());
        let color = tone_color(headline.tone);
        egui::Frame::new()
            .fill(color.gamma_multiply(0.16))
            .stroke(egui::Stroke::new(1.0, color))
            .corner_radius(6.0)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    // A painted dot: the default fonts have no "●" glyph.
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(14.0, 18.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 6.0, color);
                    ui.label(RichText::new(&headline.title).size(18.0).strong());
                });
                if !headline.detail.is_empty() {
                    // A long reason is cut here; the full message is in Log.
                    let short: String = headline.detail.chars().take(170).collect();
                    let cut = short.len() < headline.detail.len();
                    ui.add(
                        egui::Label::new(if cut {
                            format!("{short}… (more under Log)")
                        } else {
                            short
                        })
                        .wrap(),
                    );
                }
                if let Some(other) = self.other.as_ref().filter(|o| o.live) {
                    ui.label(
                        RichText::new(format!(
                            "Started from the command line (process {}).",
                            other.pid
                        ))
                        .small()
                        .weak(),
                    );
                }
            });
    }

    /// Which connection, server, profile and user name are in use.
    fn using_rows(&mut self, ui: &mut egui::Ui) {
        let active = self.is_active();
        let editing = !active && (!self.had_saved_login || self.edit_login);
        let using = self.using.clone();
        let value = |ui: &mut egui::Ui, text: &str| {
            ui.add(egui::Label::new(RichText::new(text).monospace()).truncate())
                .on_hover_text(text);
        };
        egui::Grid::new("using")
            .num_columns(2)
            .spacing([10.0, 3.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Connection").weak());
                value(ui, &using.name);
                ui.end_row();

                ui.label(RichText::new("Server").weak());
                let servers = using.servers.join(", ");
                if servers.is_empty() {
                    ui.label(RichText::new("not known yet").color(AMBER));
                } else {
                    value(ui, &servers);
                }
                ui.end_row();

                // The address OpenVPN is talking to, when the profile names
                // the server another way (by name, or more than one).
                let now_at = &self.snap.server;
                if active
                    && !now_at.is_empty()
                    && !using.servers.iter().any(|s| s.starts_with(now_at.as_str()))
                {
                    ui.label(RichText::new("Address").weak());
                    value(ui, now_at);
                    ui.end_row();
                }

                ui.label(RichText::new("Profile").weak());
                let label = if using.profile.is_empty() {
                    "Choose a profile"
                } else {
                    &using.profile
                };
                let shortened = end_of_path(label, (ui.available_width() / 7.5) as usize);
                let text = RichText::new(shortened).monospace();
                let text = if active { text } else { text.underline() };
                let response = ui
                    .add_enabled(
                        !active,
                        egui::Label::new(text)
                            .truncate()
                            .sense(egui::Sense::click()),
                    )
                    .on_hover_text(label);
                let response = if active {
                    response
                } else {
                    response.on_hover_cursor(egui::CursorIcon::PointingHand)
                };
                if response.clicked() {
                    let mut dialog =
                        rfd::FileDialog::new().add_filter("OpenVPN profile", &["ovpn"]);
                    if let Some(dir) = self
                        .loaded
                        .profile_path()
                        .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
                        .filter(|p| p.is_dir())
                    {
                        dialog = dialog.set_directory(dir);
                    }
                    if let Some(path) = dialog.pick_file() {
                        self.change_profile(path);
                    }
                }
                ui.end_row();

                ui.label(RichText::new("User").weak());
                if editing {
                    let changed = ui
                        .add(
                            egui::TextEdit::singleline(&mut self.username)
                                .hint_text("user name")
                                .desired_width(f32::INFINITY),
                        )
                        .changed();
                    if changed {
                        self.using.username = self.username.trim().to_string();
                    }
                } else {
                    let text = RichText::new(&using.username).monospace();
                    let text = if active { text } else { text.underline() };
                    let response = ui
                        .add_enabled(
                            !active,
                            egui::Label::new(text)
                                .truncate()
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_text(&using.username);
                    let response = if active {
                        response
                    } else {
                        response.on_hover_cursor(egui::CursorIcon::PointingHand)
                    };
                    if response.clicked() {
                        self.edit_login = true;
                    }
                }
                ui.end_row();

                if editing {
                    ui.label(RichText::new("Password").weak());
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.password)
                                .password(!self.show_password)
                                .hint_text("password")
                                .desired_width(ui.available_width() - 52.0),
                        );
                        ui.toggle_value(&mut self.show_password, "Show");
                    });
                    ui.end_row();

                    ui.label("");
                    ui.horizontal(|ui| {
                        let can_remember = self.store_note.is_none();
                        ui.add_enabled(
                            can_remember,
                            egui::Checkbox::new(&mut self.remember, "Remember"),
                        )
                        .on_hover_text(if cfg!(windows) {
                            "Kept in Windows Credential Manager, never in a file."
                        } else {
                            "Kept in your desktop keyring (Secret Service), never in a file."
                        })
                        .on_disabled_hover_text(self.store_note.clone().unwrap_or_default());
                        if self.had_saved_login && ui.small_button("Cancel").clicked() {
                            self.load_login();
                            self.refresh_using();
                        }
                    });
                    ui.end_row();
                }

                ui.label(RichText::new("Authenticator").weak());
                self.code_row(ui);
                ui.end_row();
                let waiting = active && self.snap.phase == Phase::NeedCode;
                if !active && !waiting {
                    ui.label("");
                    ui.label(
                        RichText::new(format!(
                            "Code from your authenticator app: {} of {} digits",
                            self.code.len(),
                            self.digits()
                        ))
                        .small()
                        .weak(),
                    );
                    ui.end_row();
                }
            });
    }

    /// The code box with Connect, Send code or Disconnect next to it.
    fn code_row(&mut self, ui: &mut egui::Ui) {
        let active = self.is_active();
        let digits = self.digits();
        let waiting = active && self.snap.phase == Phase::NeedCode;
        let can_type = !active || waiting;
        let mut enter = false;
        ui.horizontal(|ui| {
            let resp = ui.add_enabled(
                can_type,
                egui::TextEdit::singleline(&mut self.code)
                    .font(egui::TextStyle::Heading)
                    .char_limit(if digits > 0 { digits as usize } else { 12 })
                    .hint_text("code")
                    .desired_width(110.0),
            );
            self.code.retain(|c| c.is_ascii_digit());
            if self.focus_code && can_type {
                resp.request_focus();
                self.focus_code = false;
            }
            enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let button = |text: &str| egui::Button::new(text).min_size(egui::vec2(96.0, 28.0));
            if !active {
                if ui.add(button("Connect")).clicked() || enter {
                    self.connect();
                }
            } else {
                if waiting && (ui.add(button("Send code")).clicked() || enter) {
                    self.send_code();
                }
                if ui.add(button("Disconnect")).clicked() {
                    self.disconnect();
                }
            }
        });
    }

    /// Everything that is always shown. Gives back how tall it is, measured
    /// from the top of the window, also when the window is too small for it.
    fn main_view(&mut self, ui: &mut egui::Ui) -> f32 {
        egui::MenuBar::new().ui(ui, |ui| {
            if ui
                .selectable_label(self.section.is_none(), "Connect")
                .clicked()
            {
                self.section = None;
                self.asked_height = None;
                self.focus_code = true;
            }
            for section in Section::ALL {
                if ui
                    .selectable_label(self.section == Some(section), section.label())
                    .clicked()
                {
                    self.section = Some(section);
                    self.asked_height = None;
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("ovpn-otp {}", env!("CARGO_PKG_VERSION")))
                        .small()
                        .weak(),
                );
            });
        });
        ui.separator();
        ui.add_space(6.0);
        if self.section.is_none() {
            self.banner(ui);
            ui.add_space(6.0);
            self.using_rows(ui);
        }
        if let Some(release) = self.update_available.clone() {
            ui.horizontal(|ui| {
                ui.label(format!("Version {} is available.", release.version));
                let active = self.is_active();
                if ui
                    .add_enabled(
                        !active && !self.update_installing,
                        egui::Button::new("Update and restart"),
                    )
                    .clicked()
                {
                    self.update_installing = true;
                    let (tx, rx) = std::sync::mpsc::channel();
                    self.update_rx = Some(rx);
                    std::thread::spawn(move || {
                        let _ = tx.send(ovpn_otp_core::update::install(&release).map(|_| None));
                    });
                }
                if active {
                    ui.label("Disconnect to update.");
                }
                if self.update_installing {
                    ui.label("Updating…");
                }
            });
        }
        if let Some((is_err, msg)) = &self.message {
            let color = if *is_err {
                RED
            } else {
                ui.visuals().text_color()
            };
            ui.label(RichText::new(msg).color(color));
        }
        if let Some(e) = &self.load_error {
            ui.label(RichText::new(e).color(RED));
        }
        ui.add_space(4.0);
        ui.min_rect().bottom() + 2.0
    }

    /// Keep the window as tall as what it shows: just the main view, or the
    /// main view with room for the open section.
    fn fit_window(&mut self, ctx: &egui::Context, main_height: f32) {
        let size = ctx.viewport_rect().size();
        let want = match self.section {
            None => main_height.ceil(),
            // Grow for a section; a window the user made taller stays.
            Some(_) if size.y < main_height + SECTION_MIN_HEIGHT => {
                (main_height + SECTION_HEIGHT).ceil()
            }
            Some(_) => return,
        };
        if (size.y - want).abs() <= 1.0 || self.asked_height == Some(want) {
            return;
        }
        // Asked once for each height, so a desktop that refuses is left alone.
        self.asked_height = Some(want);
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(size.x, want)));
    }

    // ------------------------------------------------------------- sections

    fn details_section(&mut self, ui: &mut egui::Ui) {
        let s = &self.snap;
        let now = Local::now();
        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                let dash = |v: &str| {
                    if v.is_empty() {
                        "-".to_string()
                    } else {
                        v.to_string()
                    }
                };
                egui::Grid::new("status")
                    .num_columns(2)
                    .spacing([14.0, 3.0])
                    .show(ui, |ui| {
                        let row = |ui: &mut egui::Ui, label: &str, value: String| {
                            ui.label(RichText::new(label).weak());
                            ui.monospace(value);
                            ui.end_row();
                        };
                        row(
                            ui,
                            "Received",
                            format!(
                                "{} · {}/s",
                                format_bytes(s.bytes_in),
                                format_bytes(s.rate_in as u64)
                            ),
                        );
                        row(
                            ui,
                            "Sent",
                            format!(
                                "{} · {}/s",
                                format_bytes(s.bytes_out),
                                format_bytes(s.rate_out as u64)
                            ),
                        );
                        row(
                            ui,
                            "Last data received",
                            s.idle_secs(now)
                                .map(|i| format!("{} ago", format_duration(i)))
                                .unwrap_or_else(|| "-".into()),
                        );
                        row(
                            ui,
                            "Reach check",
                            match &s.reach {
                                Some(r) => match (r.ok, r.latency_ms) {
                                    (true, Some(ms)) => format!("{} · {ms:.1} ms", r.target),
                                    _ => format!(
                                        "{} · {}",
                                        r.target,
                                        r.error.clone().unwrap_or_else(|| "failed".into())
                                    ),
                                },
                                None if self.loaded.settings.check.host.is_empty() => {
                                    "off (set a host under Settings)".to_string()
                                }
                                None => "-".to_string(),
                            },
                        );
                        row(ui, "Routes", dash(&s.routes.join(", ")));
                        row(ui, "DNS", dash(&s.dns.join(", ")));
                        row(
                            ui,
                            "OpenVPN",
                            dash(
                                &s.openvpn_version
                                    .split_whitespace()
                                    .take(2)
                                    .collect::<Vec<_>>()
                                    .join(" "),
                            ),
                        );
                    });
            });
    }

    fn log_section(&mut self, ui: &mut egui::Ui) {
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
        egui::ScrollArea::both()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for l in self.snap.logs.iter().filter(|l| l.level >= self.log_min) {
                    let color = match l.level {
                        LogLevel::Fatal | LogLevel::Error => RED,
                        LogLevel::Warning => AMBER,
                        LogLevel::Debug => ui.visuals().weak_text_color(),
                        LogLevel::Info => ui.visuals().text_color(),
                    };
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "{} {:<7} {}",
                                l.at.format("%H:%M:%S"),
                                l.source,
                                l.message
                            ))
                            .monospace()
                            .color(color),
                        )
                        .extend(),
                    );
                }
            });
    }

    fn wire_section(&self, ui: &mut egui::Ui) {
        ui.label(
            RichText::new(
                "Show the messages between us and the OpenVPN app. We use OpenVPN as the intermediary to connect to the remote server. Passwords and codes are masked.",
            )
            .small()
            .weak(),
        );
        egui::ScrollArea::both()
            .stick_to_bottom(true)
            .auto_shrink(false)
            .show(ui, |ui| {
                for w in &self.snap.wire {
                    let (arrow, color) = match w.dir {
                        Direction::In => ("<-", ui.visuals().text_color()),
                        Direction::Out => ("->", BLUE),
                    };
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "{} {arrow} {}",
                                w.at.format("%H:%M:%S"),
                                w.text
                            ))
                            .monospace()
                            .color(color),
                        )
                        .extend(),
                    );
                }
            });
    }

    fn settings_section(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let active = self.is_active();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.label(
                RichText::new(format!(
                    "Settings file: {}. It never holds your password.",
                    self.loaded.path.display()
                ))
                .small()
                .weak(),
            );
            ui.add_space(4.0);
            let e = &mut self.edit;
            egui::Grid::new("settings").num_columns(2).spacing([12.0, 5.0]).show(ui, |ui| {
                ui.label("Connection name");
                ui.text_edit_singleline(&mut e.name)
                    .on_hover_text("The saved login is stored under this name.");
                ui.end_row();
                ui.label("Profile (.ovpn)");
                let profile = end_of_path(&e.profile.path, (ui.available_width() / 7.5) as usize);
                ui.add(egui::Label::new(profile).truncate())
                    .on_hover_text(format!("{}\nChoose a different profile on Connect.", e.profile.path));
                ui.end_row();
                ui.label("Use another server");
                ui.add(egui::TextEdit::singleline(&mut e.profile.remote).hint_text("host:port, empty = use the profile"));
                ui.end_row();
                ui.label("Private server addresses");
                ui.checkbox(&mut e.profile.allow_private_remotes, "Try them too")
                    .on_hover_text("Addresses such as 10.x.x.x or 192.168.x.x only answer inside that network. Off: they are skipped when the profile has a public address, so a failed try does not wait on them.");
                ui.end_row();
                ui.label("Give up a connect after (s)");
                ui.add(egui::DragValue::new(&mut e.connect.timeout).range(0..=3600))
                    .on_hover_text("A try that makes no progress for this many seconds ends with the reason. 0 = wait as long as OpenVPN does.");
                ui.end_row();
                ui.label("Keep-alive ping (s)");
                ui.add(egui::DragValue::new(&mut e.keepalive.ping).range(0..=3600))
                    .on_hover_text("OpenVPN sends a ping this often. 0 = use the value in the profile.");
                ui.end_row();
                ui.label("Restart after silence (s)");
                ui.add(egui::DragValue::new(&mut e.keepalive.ping_restart).range(0..=36000))
                    .on_hover_text("If nothing arrives for this long, OpenVPN restarts the connection. 0 = use the value in the profile.");
                ui.end_row();
                ui.label("After a drop");
                ui.checkbox(&mut e.keepalive.auto_reconnect, "Reconnect (asks for a new code)");
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
                ui.label("Digits in a code");
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
                        .on_hover_text("A command that gives openvpn network rights, such as `sudo -n` or `pkexec`. Leave empty if openvpn already has them.");
                    ui.end_row();
                }
                ui.label("OpenVPN log detail");
                ui.add(egui::DragValue::new(&mut self.verb_edit).range(0..=11))
                    .on_hover_text("How much OpenVPN writes to the log: 3 is the usual, 4 and up for troubleshooting.");
                ui.end_row();
                ui.label("Extra OpenVPN options");
                ui.add(egui::TextEdit::multiline(&mut self.extra_text).desired_rows(2).hint_text("one per line, like: mute 10"));
                ui.end_row();
            });
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
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
                if ui
                    .button("Copy diagnostics")
                    .on_hover_text("A report for troubleshooting, with the password and user name removed.")
                    .clicked()
                {
                    self.copy_diagnostics(ctx);
                }
            });
            if active {
                ui.label(RichText::new("Disconnect to change settings.").weak());
            }
        });
    }

    fn change_profile(&mut self, path: PathBuf) {
        if self.load_error.is_some() {
            self.message = Some((
                true,
                "Fix the settings file before changing the profile.".into(),
            ));
            return;
        }
        let mut settings = self.loaded.settings.clone();
        settings.profile.path = path.display().to_string();
        match settings::save(&self.loaded.path, &settings) {
            Ok(()) => {
                self.loaded.settings = settings;
                self.edit.profile.path = self.loaded.settings.profile.path.clone();
                self.load_error = None;
                self.refresh_using();
                self.message = Some((false, "Profile saved.".into()));
            }
            Err(e) => self.message = Some((true, format!("Could not save profile: {e}"))),
        }
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
        // Not set stays not set while the level is the usual one.
        s.openvpn.verb = match (self.loaded.settings.openvpn.verb, self.verb_edit) {
            (None, 3) => None,
            (_, v) => Some(v),
        };
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
                self.refresh_using();
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
            "Diagnostics copied (password and user name removed).".into(),
        ));
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if std::mem::take(&mut self.connect_at_start) {
            self.connect();
        }
        self.pump(ctx);
        if let Some(result) = self.update_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.update_rx = None;
            if self.update_installing {
                self.update_installing = false;
                match result {
                    Ok(_) => {
                        match std::env::current_exe().and_then(|exe| {
                            std::process::Command::new(exe)
                                .args(std::env::args_os().skip(1))
                                .spawn()
                        }) {
                            Ok(_) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                            Err(e) => {
                                self.message =
                                    Some((true, format!("Updated, but could not restart: {e}")))
                            }
                        }
                    }
                    Err(e) => self.message = Some((true, format!("Update failed: {e}"))),
                }
            } else if let Ok(release) = result {
                self.update_available = release;
            }
        }
        if self.update_rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if let Some(shot) = self.shot.as_mut() {
            shot.tick(ctx);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let main = egui::Panel::top("main")
            .show_separator_line(false)
            .show(ui, |ui| self.main_view(ui));
        let main_height = main.inner;
        egui::CentralPanel::default_margins().show(ui, |ui| match self.section {
            Some(Section::Details) => self.details_section(ui),
            Some(Section::Log) => self.log_section(ui),
            Some(Section::Wire) => self.wire_section(ui),
            Some(Section::Settings) => self.settings_section(ui, &ctx),
            None => {}
        });
        self.fit_window(&ctx, main_height);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_path_keeps_its_end() {
        assert_eq!(end_of_path("vpn/work.ovpn", 40), "vpn/work.ovpn");
        assert_eq!(
            end_of_path("/home/alice/Sync/vpn/office/work.ovpn", 24),
            "…/vpn/office/work.ovpn"
        );
        assert_eq!(
            end_of_path(r"C:\Users\alice\Sync\vpn\work.ovpn", 20),
            r"…\Sync\vpn\work.ovpn"
        );
        // One long name with no folder to start at.
        assert_eq!(
            end_of_path("averyveryverylongname.ovpn", 12),
            "…ngname.ovpn"
        );
        assert!(end_of_path("/a/b/c/d/e/f/g/h.ovpn", 10).chars().count() <= 10);
    }

    #[test]
    fn sections_are_found_by_name() {
        assert!(Section::from_name("log") == Some(Section::Log));
        assert!(Section::from_name(" Settings ") == Some(Section::Settings));
        assert!(Section::from_name("nope").is_none());
    }
}
