//! One VPN session: start OpenVPN, log in, watch it, reconnect, stop.
//!
//! [`start`] runs the session on a background thread and returns a
//! [`SessionHandle`]. The caller sends it the authenticator code and the
//! disconnect request, and reads [`Event`]s from it. Feed the events into a
//! [`crate::snapshot::Snapshot`] to get the current picture for display.
//!
//! How the login works: OpenVPN is started with `--management-query-passwords`,
//! so when the server wants a login OpenVPN sends `>PASSWORD:Need 'Auth'` and
//! waits. The session answers with the saved user name and
//! `password + code` (or the `SCRV1` form for `static-challenge` profiles). A
//! code is used once. If OpenVPN asks again later (after a drop; the prepared
//! profile sets `auth-nocache` so it always asks) and no fresh code is waiting,
//! the session sends [`Event::NeedCode`] and waits for [`SessionHandle::send_code`].
//!
//! How keep-alive and reconnect work: `ping`/`ping-restart` in the prepared
//! profile make OpenVPN notice a dead link and restart it in-process. Because
//! OpenVPN runs with `--management-hold`, every restart pauses at `>HOLD`; the
//! session releases it after a backoff delay that doubles on each try. If the
//! OpenVPN process itself ends unexpectedly after having connected, the
//! session starts a new one after the same backoff.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use crate::credentials::{Login, Secret};
use crate::launch::{LaunchRequest, Launched, Launcher, VpnProcess};
use crate::mgmt::{
    self, Line, LogEntry, LogLevel, Notification, PasswordNotice, PushReply, StateInfo,
    StaticChallenge,
};
use crate::reach::{self, ReachResult};
use crate::settings::{KeepAlive, ReachCheck};

/// A code older than this is treated as expired and the user is asked again.
pub const CODE_MAX_AGE: Duration = Duration::from_secs(90);
/// How long to wait for OpenVPN to open its management interface.
const MGMT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long to wait for OpenVPN to exit after asking it to.
const STOP_TIMEOUT: Duration = Duration::from_secs(8);

/// Everything a session needs.
#[derive(Debug, Clone)]
pub struct SessionOptions {
    pub login: Login,
    /// The code for the first login, if already typed.
    pub code: Option<String>,
    /// Expected number of digits in a code.
    pub code_digits: u8,
    pub keepalive: KeepAlive,
    pub reach: ReachCheck,
    pub launch: LaunchRequest,
}

/// Which way a management line went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    /// From OpenVPN to this app.
    In,
    /// From this app to OpenVPN.
    Out,
}

/// Why a code is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CodeReason {
    /// First login and no code was given.
    Initial,
    /// The connection dropped and the server wants a fresh login.
    Reconnect,
    /// The server rejected the last login.
    Rejected,
    /// The code waiting to be used was too old.
    Expired,
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EndReason {
    /// The user asked to disconnect.
    Disconnected,
    /// The connection dropped and auto-reconnect is off.
    Dropped(String),
    /// Something went wrong that retrying will not fix.
    Failed(String),
}

/// Something that happened in the session.
#[derive(Debug, Clone)]
pub enum Event {
    /// About to start OpenVPN (`attempt` is 0 for the first start).
    Launching { at: DateTime<Local>, attempt: u32 },
    /// A line on the management interface, with secrets already removed.
    Wire {
        at: DateTime<Local>,
        dir: Direction,
        text: String,
    },
    /// OpenVPN changed state.
    State {
        at: DateTime<Local>,
        info: StateInfo,
    },
    /// Byte counters, sent every second.
    Bytes {
        at: DateTime<Local>,
        bytes_in: u64,
        bytes_out: u64,
    },
    /// An OpenVPN log line.
    Log(LogEntry),
    /// A message from this app itself.
    Note {
        at: DateTime<Local>,
        level: LogLevel,
        text: String,
    },
    /// OpenVPN is waiting for a login and there is no fresh code.
    NeedCode { reason: CodeReason },
    /// The login was handed to OpenVPN.
    LoginSent { at: DateTime<Local> },
    /// The server rejected the login.
    AuthFailed { reason: String },
    /// Options the server pushed (routes, DNS, address).
    Pushed(PushReply),
    /// The OpenVPN version line.
    Version(String),
    /// The connection dropped; the next try starts after `delay`.
    Reconnecting {
        at: DateTime<Local>,
        attempt: u32,
        delay: Duration,
        reason: String,
    },
    /// Result of a reachability check through the tunnel.
    Reach(ReachResult),
    /// The session is over. Always the last event.
    Ended { reason: EndReason },
}

/// Requests from the user to a running session.
#[derive(Debug)]
enum Command {
    Code(String),
    Disconnect,
}

enum Input {
    Cmd(Command),
    Mgmt(u64, Option<String>),
    Reach(ReachResult),
}

/// Control of a running session.
pub struct SessionHandle {
    tx: Sender<Input>,
    events: Receiver<Event>,
    thread: Option<JoinHandle<()>>,
}

impl SessionHandle {
    /// Give the session an authenticator code.
    pub fn send_code(&self, code: &str) {
        let _ = self.tx.send(Input::Cmd(Command::Code(code.to_string())));
    }

    /// Ask the session to disconnect. [`Event::Ended`] follows.
    pub fn disconnect(&self) {
        let _ = self.tx.send(Input::Cmd(Command::Disconnect));
    }

    /// Events, in order. The channel closes after [`Event::Ended`].
    pub fn events(&self) -> &Receiver<Event> {
        &self.events
    }

    /// Wait for the session thread to finish. Call it after [`Event::Ended`].
    pub fn join(mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for SessionHandle {
    /// Dropping the handle of a running session disconnects it, so OpenVPN is
    /// not left running with nobody watching it.
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.tx.send(Input::Cmd(Command::Disconnect));
        }
    }
}

/// Check that a code looks right: digits only, the expected length.
pub fn validate_code(code: &str, digits: u8) -> Result<String, String> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.is_empty() {
        return Err("Enter the code from your authenticator app.".into());
    }
    if !code.chars().all(|c| c.is_ascii_digit()) {
        return Err("The code must be digits only.".into());
    }
    if digits > 0 && code.len() != digits as usize {
        return Err(format!(
            "The code must be {digits} digits; you entered {}.",
            code.len()
        ));
    }
    Ok(code)
}

/// Wait before reconnect try number `attempt` (1-based): doubles each time.
pub fn backoff(ka: &KeepAlive, attempt: u32) -> Duration {
    let initial = ka.backoff_initial.max(1) as u64;
    let max = (ka.backoff_max as u64).max(initial);
    let shift = attempt.saturating_sub(1).min(16);
    Duration::from_secs((initial << shift).min(max))
}

/// Start a session on a background thread.
pub fn start(opts: SessionOptions, launcher: Box<dyn Launcher>) -> SessionHandle {
    let (tx, rx) = mpsc::channel();
    let (ev_tx, ev_rx) = mpsc::channel();
    let engine_tx = tx.clone();
    let thread = std::thread::Builder::new()
        .name("ovpn-otp-session".into())
        .spawn(move || {
            let mut engine = Engine::new(opts, launcher, engine_tx, rx, ev_tx);
            let reason = engine.run();
            engine.emit(Event::Ended { reason });
        })
        .expect("spawn session thread");
    SessionHandle {
        tx,
        events: ev_rx,
        thread: Some(thread),
    }
}

/// How one OpenVPN process ended.
enum ProcessEnd {
    UserStop,
    Dropped(String),
    Fatal(String),
}

/// What a multi-line reply belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// One `SUCCESS:`/`ERROR:` line.
    Simple,
    /// History lines, `END`, and a `SUCCESS:` line, in either order.
    LogHistory,
    StateHistory,
}

struct PendingCmd {
    kind: Reply,
    got_end: bool,
    got_reply: bool,
}

struct Engine {
    opts: SessionOptions,
    launcher: Box<dyn Launcher>,
    tx: Sender<Input>,
    rx: Receiver<Input>,
    events: Sender<Event>,

    pending_code: Option<(String, Instant)>,
    /// `Some` while OpenVPN waits for a login; holds the static-challenge info.
    awaiting_login: Option<Option<StaticChallenge>>,
    last_login_rejected: bool,
    attempt: u32,
    ever_connected: bool,

    // Per-process state, reset by `run_process`.
    gen: u64,
    writer: Option<TcpStream>,
    pending: VecDeque<PendingCmd>,
    setup_done: bool,
    holds: u32,
    hold_release_at: Option<Instant>,
    connected: bool,
    next_reach_at: Option<Instant>,
    reach_running: bool,
    stopping: bool,
    stop_deadline: Option<Instant>,
    fatal: Option<String>,
    last_reconnect_reason: String,
}

fn now() -> DateTime<Local> {
    Local::now()
}

impl Engine {
    fn new(
        opts: SessionOptions,
        launcher: Box<dyn Launcher>,
        tx: Sender<Input>,
        rx: Receiver<Input>,
        events: Sender<Event>,
    ) -> Self {
        let pending_code = opts.code.clone().map(|c| (c, Instant::now()));
        Engine {
            opts,
            launcher,
            tx,
            rx,
            events,
            pending_code,
            awaiting_login: None,
            last_login_rejected: false,
            attempt: 0,
            ever_connected: false,
            gen: 0,
            writer: None,
            pending: VecDeque::new(),
            setup_done: false,
            holds: 0,
            hold_release_at: None,
            connected: false,
            next_reach_at: None,
            reach_running: false,
            stopping: false,
            stop_deadline: None,
            fatal: None,
            last_reconnect_reason: String::new(),
        }
    }

    fn emit(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    fn note(&self, level: LogLevel, text: impl Into<String>) {
        self.emit(Event::Note {
            at: now(),
            level,
            text: text.into(),
        });
    }

    fn run(&mut self) -> EndReason {
        loop {
            match self.run_process() {
                ProcessEnd::UserStop => return EndReason::Disconnected,
                ProcessEnd::Fatal(msg) => return EndReason::Failed(msg),
                ProcessEnd::Dropped(reason) => {
                    if !self.opts.keepalive.auto_reconnect {
                        return EndReason::Dropped(reason);
                    }
                    self.attempt += 1;
                    let delay = backoff(&self.opts.keepalive, self.attempt);
                    self.emit(Event::Reconnecting {
                        at: now(),
                        attempt: self.attempt,
                        delay,
                        reason: reason.clone(),
                    });
                    if !self.wait_between_processes(delay) {
                        return EndReason::Disconnected;
                    }
                }
            }
        }
    }

    /// Wait out the backoff between two OpenVPN processes, still taking codes.
    /// Returns false if the user disconnected meanwhile.
    fn wait_between_processes(&mut self, delay: Duration) -> bool {
        let until = Instant::now() + delay;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return true;
            }
            match self.rx.recv_timeout(left) {
                Ok(Input::Cmd(Command::Disconnect)) => return false,
                Ok(Input::Cmd(Command::Code(c))) => self.take_code(&c),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => return true,
                Err(RecvTimeoutError::Disconnected) => return false,
            }
        }
    }

    fn reset_process_state(&mut self) {
        self.gen += 1;
        self.writer = None;
        self.pending.clear();
        self.setup_done = false;
        self.holds = 0;
        self.hold_release_at = None;
        self.connected = false;
        self.next_reach_at = None;
        self.stopping = false;
        self.stop_deadline = None;
        self.fatal = None;
        self.awaiting_login = None;
    }

    fn run_process(&mut self) -> ProcessEnd {
        self.reset_process_state();
        self.emit(Event::Launching {
            at: now(),
            attempt: self.attempt,
        });
        let Launched {
            mut process,
            mgmt_addr,
            mgmt_password,
            description,
        } = match self.launcher.launch(&self.opts.launch) {
            Ok(l) => l,
            Err(e) => return ProcessEnd::Fatal(e.to_string()),
        };
        self.note(LogLevel::Info, format!("Started: {description}"));

        // Wait for the management interface to open.
        let deadline = Instant::now() + MGMT_CONNECT_TIMEOUT;
        let stream = loop {
            if let Ok(s) = TcpStream::connect_timeout(&mgmt_addr, Duration::from_millis(500)) {
                break s;
            }
            if let Some(code) = process.try_wait() {
                return ProcessEnd::Fatal(exit_message(code, &process.output_tail()));
            }
            if Instant::now() > deadline {
                process.kill();
                return ProcessEnd::Fatal(format!(
                    "OpenVPN did not open its management interface within {}s.{}",
                    MGMT_CONNECT_TIMEOUT.as_secs(),
                    tail_text(&process.output_tail())
                ));
            }
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Input::Cmd(Command::Disconnect)) => {
                    process.kill();
                    return ProcessEnd::UserStop;
                }
                Ok(Input::Cmd(Command::Code(c))) => self.take_code(&c),
                _ => {}
            }
        };
        let _ = stream.set_nodelay(true);
        match stream.try_clone() {
            Ok(w) => self.writer = Some(w),
            Err(e) => {
                process.kill();
                return ProcessEnd::Fatal(format!("management connection: {e}"));
            }
        }
        spawn_reader(stream, self.gen, self.tx.clone());

        loop {
            let timeout = self.next_timeout();
            let input = match self.rx.recv_timeout(timeout) {
                Ok(i) => Some(i),
                Err(RecvTimeoutError::Timeout) => None,
                Err(RecvTimeoutError::Disconnected) => {
                    process.kill();
                    return ProcessEnd::UserStop;
                }
            };
            match input {
                Some(Input::Mgmt(g, _)) if g != self.gen => {}
                Some(Input::Mgmt(_, Some(line))) => {
                    self.on_line(&line, &mgmt_password, process.as_mut())
                }
                Some(Input::Mgmt(_, None)) => {
                    return self.on_closed(process.as_mut());
                }
                Some(Input::Cmd(Command::Code(c))) => {
                    self.take_code(&c);
                    if self.awaiting_login.is_some() {
                        self.try_send_login();
                    }
                }
                Some(Input::Cmd(Command::Disconnect)) => {
                    if self.stopping {
                        process.kill();
                        return ProcessEnd::UserStop;
                    }
                    self.note(LogLevel::Info, "Disconnecting.");
                    self.stopping = true;
                    self.stop_deadline = Some(Instant::now() + STOP_TIMEOUT);
                    self.send("signal SIGTERM", Reply::Simple);
                }
                Some(Input::Reach(r)) => {
                    self.reach_running = false;
                    self.emit(Event::Reach(r));
                }
                None => {}
            }
            self.on_timers(process.as_mut());
            if let Some(d) = self.stop_deadline {
                if Instant::now() >= d {
                    self.note(
                        LogLevel::Warning,
                        "OpenVPN did not stop in time; ending it.",
                    );
                    process.kill();
                    return ProcessEnd::UserStop;
                }
            }
        }
    }

    fn next_timeout(&self) -> Duration {
        let mut t = Duration::from_millis(500);
        for d in [self.hold_release_at, self.next_reach_at, self.stop_deadline]
            .into_iter()
            .flatten()
        {
            t = t.min(d.saturating_duration_since(Instant::now()));
        }
        t.max(Duration::from_millis(10))
    }

    fn on_timers(&mut self, _process: &mut dyn VpnProcess) {
        let now_i = Instant::now();
        if let Some(at) = self.hold_release_at {
            if now_i >= at {
                self.hold_release_at = None;
                self.send("hold release", Reply::Simple);
            }
        }
        if let Some(at) = self.next_reach_at {
            if now_i >= at && self.connected && !self.reach_running {
                self.reach_running = true;
                let interval = self.opts.reach.interval.max(2) as u64;
                self.next_reach_at = Some(now_i + Duration::from_secs(interval));
                let host = self.opts.reach.host.clone();
                let tx = self.tx.clone();
                std::thread::spawn(move || {
                    let r = reach::check(&host);
                    let _ = tx.send(Input::Reach(r));
                });
            }
        }
    }

    fn on_closed(&mut self, process: &mut dyn VpnProcess) -> ProcessEnd {
        self.writer = None;
        // Give the process a moment to finish exiting.
        let mut code = None;
        for _ in 0..30 {
            if let Some(c) = process.try_wait() {
                code = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if code.is_none() {
            process.kill();
        }
        if self.stopping {
            return ProcessEnd::UserStop;
        }
        if let Some(f) = self.fatal.take() {
            // A fatal error before ever connecting is a setup problem; retrying
            // will not help. After a good connection it may be passing.
            if !self.ever_connected {
                return ProcessEnd::Fatal(f);
            }
            return ProcessEnd::Dropped(f);
        }
        if !self.ever_connected {
            return ProcessEnd::Fatal(exit_message(code.flatten(), &process.output_tail()));
        }
        ProcessEnd::Dropped("OpenVPN exited".into())
    }

    fn send(&mut self, cmd: &str, kind: Reply) {
        let shown = redact_outgoing(cmd);
        self.send_raw(cmd, &shown, kind);
    }

    fn send_raw(&mut self, cmd: &str, shown: &str, kind: Reply) {
        let Some(w) = self.writer.as_mut() else {
            return;
        };
        let mut line = Secret::new(cmd);
        if !line.expose().ends_with('\n') {
            line = Secret::new(format!("{}\n", line.expose()));
        }
        if w.write_all(line.expose().as_bytes()).is_err() {
            return;
        }
        self.pending.push_back(PendingCmd {
            kind,
            got_end: false,
            got_reply: false,
        });
        self.emit(Event::Wire {
            at: now(),
            dir: Direction::Out,
            text: shown.to_string(),
        });
    }

    fn setup(&mut self) {
        if self.setup_done {
            return;
        }
        self.setup_done = true;
        self.send("log on all", Reply::LogHistory);
        self.send("state on all", Reply::StateHistory);
        self.send("bytecount 1", Reply::Simple);
    }

    fn on_line(&mut self, raw: &str, mgmt_password: &Secret, process: &mut dyn VpnProcess) {
        let line = mgmt::parse_line(raw);
        self.emit(Event::Wire {
            at: now(),
            dir: Direction::In,
            text: redact_incoming(raw),
        });
        match line {
            Line::PasswordPrompt => {
                if let Some(w) = self.writer.as_mut() {
                    let msg = Secret::new(format!("{}\n", mgmt_password.expose()));
                    let _ = w.write_all(msg.expose().as_bytes());
                    self.emit(Event::Wire {
                        at: now(),
                        dir: Direction::Out,
                        text: "******** (management password)".into(),
                    });
                }
            }
            Line::Success(text) if text.starts_with("password is correct") => {
                process_logged_in(process);
                self.setup();
            }
            Line::Success(_) | Line::Error(_) => {
                if let Line::Error(e) = &line {
                    self.note(LogLevel::Warning, format!("OpenVPN said: {e}"));
                }
                if let Some(front) = self.pending.front_mut() {
                    front.got_reply = true;
                    if front.kind == Reply::Simple
                        || front.got_end
                        || matches!(line, Line::Error(_))
                    {
                        self.pending.pop_front();
                    }
                }
            }
            Line::End => {
                if let Some(front) = self.pending.front_mut() {
                    front.got_end = true;
                    if front.got_reply {
                        self.pending.pop_front();
                    }
                }
            }
            Line::Data(d) => match self.pending.front().map(|p| p.kind) {
                Some(Reply::LogHistory) => {
                    if let Some(entry) = mgmt::parse_log(&d) {
                        self.on_log(entry);
                    }
                }
                Some(Reply::StateHistory) => {
                    if let Some(info) = mgmt::parse_state(&d) {
                        self.emit(Event::State { at: now(), info });
                    }
                }
                _ => {}
            },
            Line::Notification(n) => self.on_notification(n),
        }
    }

    fn on_log(&mut self, entry: LogEntry) {
        if let Some(reply) = mgmt::parse_push_reply(&entry.message) {
            self.emit(Event::Pushed(reply));
        }
        if entry.message.starts_with("OpenVPN ") && entry.message.contains(" [") {
            self.emit(Event::Version(entry.message.clone()));
        }
        self.emit(Event::Log(entry));
    }

    fn on_notification(&mut self, n: Notification) {
        match n {
            Notification::Info(_) => self.setup(),
            Notification::Hold { .. } => {
                self.holds += 1;
                if self.holds == 1 && !self.connected_before_in_process() {
                    // First start of this process: any backoff already happened.
                    self.send("hold release", Reply::Simple);
                } else {
                    let delay = backoff(&self.opts.keepalive, self.attempt.max(1));
                    self.note(
                        LogLevel::Info,
                        format!("Waiting {}s before reconnecting.", delay.as_secs()),
                    );
                    self.hold_release_at = Some(Instant::now() + delay);
                }
            }
            Notification::State(info) => self.on_state(info),
            Notification::ByteCount {
                bytes_in,
                bytes_out,
            } => self.emit(Event::Bytes {
                at: now(),
                bytes_in,
                bytes_out,
            }),
            Notification::Log(entry) => self.on_log(entry),
            Notification::Password(p) => self.on_password(p),
            Notification::Fatal(msg) => {
                self.note(LogLevel::Fatal, format!("OpenVPN stopped: {msg}"));
                self.fatal = Some(msg);
            }
            Notification::Other { .. } => {}
        }
    }

    fn connected_before_in_process(&self) -> bool {
        // A second hold in the same process means an in-process restart.
        self.holds > 1
    }

    fn on_state(&mut self, info: StateInfo) {
        match info.name.as_str() {
            "CONNECTED" => {
                self.connected = true;
                self.ever_connected = true;
                self.attempt = 0;
                self.last_login_rejected = false;
                if !self.opts.reach.host.trim().is_empty() {
                    self.next_reach_at = Some(Instant::now() + Duration::from_secs(1));
                }
            }
            "RECONNECTING" => {
                self.connected = false;
                self.next_reach_at = None;
                if !self.stopping {
                    self.attempt += 1;
                    let reason = if info.detail.is_empty() {
                        "connection restarted".to_string()
                    } else {
                        info.detail.clone()
                    };
                    self.last_reconnect_reason = reason.clone();
                    if self.opts.keepalive.auto_reconnect || info.detail == "auth-failure" {
                        self.emit(Event::Reconnecting {
                            at: now(),
                            attempt: self.attempt,
                            delay: backoff(&self.opts.keepalive, self.attempt),
                            reason,
                        });
                    } else {
                        self.note(
                            LogLevel::Warning,
                            format!("Connection dropped ({reason}); auto-reconnect is off."),
                        );
                        self.stopping = true;
                        self.stop_deadline = Some(Instant::now() + STOP_TIMEOUT);
                        self.send("signal SIGTERM", Reply::Simple);
                    }
                }
            }
            "EXITING" => {
                self.connected = false;
                self.next_reach_at = None;
            }
            _ => {}
        }
        self.emit(Event::State { at: now(), info });
    }

    fn on_password(&mut self, p: PasswordNotice) {
        match p {
            PasswordNotice::NeedAuth {
                static_challenge, ..
            } => {
                self.awaiting_login = Some(static_challenge);
                self.try_send_login();
            }
            PasswordNotice::NeedPassword { realm } => {
                let msg = format!(
                    "The profile needs a '{realm}' password, which ovpn-otp does not support. \
                     Use a profile without an encrypted private key."
                );
                self.note(LogLevel::Error, msg.clone());
                self.fatal = Some(msg);
                self.send("signal SIGTERM", Reply::Simple);
            }
            PasswordNotice::VerificationFailed { reason, .. } => {
                self.last_login_rejected = true;
                self.emit(Event::AuthFailed {
                    reason: if reason.is_empty() {
                        "the server rejected the user name, password or code".into()
                    } else {
                        reason
                    },
                });
            }
            PasswordNotice::AuthToken | PasswordNotice::Other(_) => {}
        }
    }

    /// Store a code the user typed.
    fn take_code(&mut self, code: &str) {
        match validate_code(code, self.opts.code_digits) {
            Ok(c) => self.pending_code = Some((c, Instant::now())),
            Err(e) => self.note(LogLevel::Warning, e),
        }
    }

    /// Answer OpenVPN's login request if a fresh code is waiting; otherwise ask for one.
    fn try_send_login(&mut self) {
        let Some(sc) = self.awaiting_login.clone() else {
            return;
        };
        let fresh = match self.pending_code.take() {
            Some((code, at)) if at.elapsed() <= CODE_MAX_AGE => Some(code),
            Some(_) => {
                self.note(LogLevel::Warning, "The code waiting to be used is too old.");
                self.emit(Event::NeedCode {
                    reason: CodeReason::Expired,
                });
                return;
            }
            None => None,
        };
        let Some(code) = fresh else {
            let reason = if self.last_login_rejected {
                CodeReason::Rejected
            } else if self.ever_connected || self.attempt > 0 {
                CodeReason::Reconnect
            } else {
                CodeReason::Initial
            };
            self.emit(Event::NeedCode { reason });
            return;
        };
        self.awaiting_login = None;
        let user = self.opts.login.username.clone();
        let pass = match &sc {
            Some(_) => Secret::new(mgmt::static_challenge_response(
                self.opts.login.password.expose(),
                &code,
            )),
            None => Secret::new(format!("{}{}", self.opts.login.password.expose(), code)),
        };
        let user_cmd = format!("username \"Auth\" {}", mgmt::quote(&user));
        self.send_raw(&user_cmd, &user_cmd, Reply::Simple);
        let pass_cmd = Secret::new(format!("password \"Auth\" {}", mgmt::quote(pass.expose())));
        let shown = if sc.is_some() {
            "password \"Auth\" \"********\" (SCRV1: password and code, hidden)"
        } else {
            "password \"Auth\" \"********\" (password + code, hidden)"
        };
        self.send_raw(pass_cmd.expose(), shown, Reply::Simple);
        self.emit(Event::LoginSent { at: now() });
    }
}

fn process_logged_in(process: &mut dyn VpnProcess) {
    // Nothing to do on the process itself today; the password file is removed
    // when the process handle drops. Kept as a hook for clarity.
    let _ = process;
}

fn spawn_reader(stream: TcpStream, gen: u64, tx: Sender<Input>) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            // `ENTER PASSWORD:` arrives without a newline, so read whatever is
            // available and split lines ourselves.
            let chunk = match reader.fill_buf() {
                Ok([]) | Err(_) => break,
                Ok(c) => c.to_vec(),
            };
            reader.consume(chunk.len());
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                if tx.send(Input::Mgmt(gen, Some(text))).is_err() {
                    return;
                }
            }
            if buf == mgmt::PASSWORD_PROMPT.as_bytes() {
                buf.clear();
                if tx
                    .send(Input::Mgmt(gen, Some(mgmt::PASSWORD_PROMPT.into())))
                    .is_err()
                {
                    return;
                }
            }
        }
        let _ = tx.send(Input::Mgmt(gen, None));
    });
}

/// Hide secrets in a command before showing it.
pub fn redact_outgoing(cmd: &str) -> String {
    let lower = cmd.trim_start().to_ascii_lowercase();
    if lower.starts_with("password ") {
        return "password \"Auth\" \"********\" (hidden)".into();
    }
    cmd.trim_end().to_string()
}

/// Hide secrets in a line from OpenVPN before showing it.
pub fn redact_incoming(line: &str) -> String {
    if let Some(i) = line.find(">PASSWORD:Auth-Token:") {
        return format!("{}>PASSWORD:Auth-Token:******** (hidden)", &line[..i]);
    }
    line.to_string()
}

fn tail_text(tail: &[String]) -> String {
    if tail.is_empty() {
        String::new()
    } else {
        format!("\nLast output:\n{}", tail.join("\n"))
    }
}

/// Explain why OpenVPN exited before it was ready.
fn exit_message(code: Option<i32>, tail: &[String]) -> String {
    let joined = tail.join("\n");
    let mut msg = match code {
        Some(c) => format!("OpenVPN exited (code {c}) before it was ready."),
        None => "OpenVPN exited before it was ready.".to_string(),
    };
    if joined.contains("sudo:") && joined.contains("password") {
        msg.push_str(
            "\nsudo wants a password. Allow your user to run openvpn without one \
             (see the README, \"Linux: let openvpn create the tunnel\"), \
             or set [openvpn.linux] command_prefix = [\"pkexec\"] for a password dialog.",
        );
    } else if joined.contains("Cannot open TUN") || joined.contains("Operation not permitted") {
        msg.push_str(
            "\nOpenVPN has no right to create the tunnel. See the README section on privileges.",
        );
    }
    msg.push_str(&tail_text(tail));
    msg
}

/// Path of the prepared config for a connection name inside `dir`.
pub fn prepared_config_path(dir: &std::path::Path, name: &str) -> PathBuf {
    let safe: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(format!("{safe}.ovpn"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_codes() {
        assert_eq!(validate_code("123 456", 6).unwrap(), "123456");
        assert!(validate_code("12345", 6).is_err());
        assert!(validate_code("12a456", 6).is_err());
        assert!(validate_code("", 6).is_err());
        assert_eq!(validate_code("12345678", 0).unwrap(), "12345678");
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let ka = KeepAlive {
            backoff_initial: 2,
            backoff_max: 30,
            ..KeepAlive::default()
        };
        let secs: Vec<u64> = (1..=6).map(|a| backoff(&ka, a).as_secs()).collect();
        assert_eq!(secs, vec![2, 4, 8, 16, 30, 30]);
        assert_eq!(backoff(&ka, 200).as_secs(), 30);
    }

    #[test]
    fn redacts_password_lines() {
        assert!(!redact_outgoing("password \"Auth\" \"hunter2123456\"").contains("hunter2"));
        assert_eq!(redact_outgoing("hold release\n"), "hold release");
        let r = redact_incoming(">PASSWORD:Auth-Token:c2VjcmV0dG9rZW4=");
        assert!(!r.contains("c2VjcmV0"));
        assert_eq!(redact_incoming(">STATE:1,CONNECTED"), ">STATE:1,CONNECTED");
    }

    #[test]
    fn explains_sudo_password_failure() {
        let m = exit_message(Some(1), &["sudo: a password is required".into()]);
        assert!(m.contains("sudo wants a password"));
    }

    #[test]
    fn prepared_config_names_are_safe() {
        let p = prepared_config_path(std::path::Path::new("/r"), "my work/vpn");
        assert_eq!(p, PathBuf::from("/r/my_work_vpn.ovpn"));
    }
}
