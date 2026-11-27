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
//!
//! How a failed try is handled: when a try ends before the tunnel is up, the
//! session works out why (see [`FailureKind`]) and says so with
//! [`Event::ConnectFailed`] or [`Event::AuthFailed`]. A first connect that
//! fails ends the session with that reason, so nobody is asked for code after
//! code while the real problem is somewhere else. Two cases keep going: a
//! server that could not be reached while the profile has more servers to
//! try, and a rejected login when [`SessionOptions::retry_login`] is on. After
//! the tunnel has been up once, the session keeps trying and asks for a new
//! code with [`CodeReason::Retry`].
//!
//! How commands are sent: one at a time. A command goes to OpenVPN only after
//! the answer to the one before has arrived in full (see [`Engine::send`]).
//! OpenVPN on Windows looks for new commands while it is still answering
//! one, and a command that arrives in that moment is lost while the one being
//! answered runs a second time. Sent in a row, the password was lost that way
//! and OpenVPN waited for it for ever.
//!
//! How a stuck try ends: a try that makes no progress for
//! [`SessionOptions::connect_timeout`] ends with [`FailureKind::Timeout`], and
//! so does an OpenVPN that does not answer a command. The session never stays
//! on "connecting" without an end.
//!
//! How the hold is released: not only when OpenVPN's `>HOLD` arrives. OpenVPN
//! can wait at the hold without the notice ever arriving: `>HOLD` is one line
//! in its output queue, and the queue is thrown away when a command arrives
//! while it is being written (`man_read` resets the output list, and on
//! Windows a command is read again before every write). The 0.3.0 session on
//! Windows stood exactly there: the setup commands were answered, `hold
//! release` never went out, and nothing happened until the connect timeout.
//! So once the setup commands are answered, the session releases the hold
//! itself, without waiting for a notice that may never come.

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
/// How long OpenVPN may take to answer one management command. It answers
/// from memory, so anything longer means it is stuck.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// The same while stopping, where the next command is the one that stops it.
const REPLY_TIMEOUT_STOPPING: Duration = Duration::from_secs(2);
/// Extra time on top of the connect timeout, so that OpenVPN, which gets the
/// same timeout, can report a server that does not answer in its own words.
const CONNECT_GRACE: Duration = Duration::from_secs(5);

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
    /// When the server rejects the first login, ask for a new code and try
    /// again (for a person at the window or terminal). When off, the session
    /// ends with [`FailureKind::AuthFailed`] (for scripts).
    pub retry_login: bool,
    /// The servers OpenVPN will try, as `host:port`, for messages.
    pub remotes: Vec<String>,
    /// How many servers OpenVPN tries before it starts over. A first connect
    /// gives up as unreachable after this many tries.
    pub remote_count: usize,
    /// Changes made to the profile, logged when the session starts.
    pub notes: Vec<String>,
    /// End a try that makes no progress for this long. Zero waits for ever.
    pub connect_timeout: Duration,
}

/// Which way a management line went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// From OpenVPN to this app.
    In,
    /// From this app to OpenVPN.
    Out,
}

/// Why a code is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeReason {
    /// First login and no code was given.
    Initial,
    /// The connection dropped and the server wants a fresh login.
    Reconnect,
    /// The server rejected the last login.
    Rejected,
    /// The code waiting to be used was too old.
    Expired,
    /// The last try to reconnect failed (see the error with it), and the code
    /// it used cannot be used again.
    Retry,
}

/// Why a try to connect failed, as a short fixed name that scripts can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The server said the user name, password or code is wrong.
    AuthFailed,
    /// The server closed the connection during login without giving a reason.
    ServerReset,
    /// The server and OpenVPN have no data cipher in common.
    CipherMismatch,
    /// No server answered: wrong address, no network, or a firewall in between.
    Unreachable,
    /// A working connection dropped and auto-reconnect is off.
    Dropped,
    /// A try made no progress for the time in the settings, or OpenVPN
    /// stopped answering.
    Timeout,
    /// Anything else, such as OpenVPN not starting.
    Failed,
}

impl FailureKind {
    /// The name used in `status --json` and in the log.
    pub fn name(self) -> &'static str {
        match self {
            FailureKind::AuthFailed => "auth_failed",
            FailureKind::ServerReset => "server_reset",
            FailureKind::CipherMismatch => "cipher_mismatch",
            FailureKind::Unreachable => "unreachable",
            FailureKind::Dropped => "dropped",
            FailureKind::Timeout => "timeout",
            FailureKind::Failed => "failed",
        }
    }
}

/// A failed try: what kind, and a message for the user.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Failure {
    pub kind: FailureKind,
    pub message: String,
}

impl Failure {
    pub fn new(kind: FailureKind, message: impl Into<String>) -> Failure {
        Failure {
            kind,
            message: message.into(),
        }
    }

    /// A failure with no more specific kind.
    pub fn other(message: impl Into<String>) -> Failure {
        Failure::new(FailureKind::Failed, message)
    }
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EndReason {
    /// The user asked to disconnect.
    Disconnected,
    /// The connection dropped and auto-reconnect is off.
    Dropped(String),
    /// Something went wrong that retrying will not fix.
    Failed(Failure),
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
    /// A try to connect failed for another reason than a rejected login:
    /// the server closed the connection, did not answer, or shares no cipher.
    ConnectFailed {
        at: DateTime<Local>,
        failure: Failure,
    },
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
    Fatal(Failure),
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

/// A command that waits for its turn.
struct QueuedCmd {
    line: Secret,
    /// The command as it may be shown, with secrets removed.
    shown: String,
    kind: Reply,
}

/// The command OpenVPN is answering.
struct PendingCmd {
    kind: Reply,
    shown: String,
    sent_at: Instant,
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
    /// The last try to reconnect failed, so the next code request says so.
    retry_after_failure: bool,
    attempt: u32,
    ever_connected: bool,
    /// Tries in a row, on a first connect, where no server answered.
    unreachable_tries: u32,

    // State of the current try, reset when the hold is released.
    /// The server answered (OpenVPN reached `AUTH`), so the login may have been sent to it.
    reached_auth: bool,
    /// Whether OpenVPN reported that the TLS control channel is established.
    tls_established: bool,
    /// The code handed to OpenVPN for this try, kept until it is known whether
    /// it left this machine. A code the server never saw can be used again.
    sent_code: Option<(String, Instant)>,
    /// A log line that says no cipher could be agreed.
    cipher_error: Option<String>,
    /// The reason the server gave when it rejected the login.
    auth_reason: Option<String>,
    /// The last log line that explains why a try failed.
    last_problem: Option<String>,
    /// The server address of the current try, from the log.
    current_remote: String,
    /// The last state OpenVPN reported in the current try.
    last_state: String,
    /// When OpenVPN last made progress in a try that is under way. `None`
    /// while nothing is expected of it: connected, waiting for a code, or
    /// waiting out a backoff.
    progress_at: Option<Instant>,

    // Per-process state, reset by `run_process`.
    gen: u64,
    writer: Option<TcpStream>,
    /// Commands that wait for the answer to `pending`.
    queue: VecDeque<QueuedCmd>,
    /// The one command OpenVPN is answering.
    pending: Option<PendingCmd>,
    setup_done: bool,
    /// The setup commands are all answered (see `setup_answered`).
    setup_answered: bool,
    holds: u32,
    /// The hold was released at least once in this process (see `release_hold`).
    hold_released: bool,
    hold_release_at: Option<Instant>,
    connected: bool,
    next_reach_at: Option<Instant>,
    reach_running: bool,
    stopping: bool,
    drop_reason: Option<String>,
    /// OpenVPN is being stopped because a try failed in a way that retrying will not fix.
    end_failure: Option<Failure>,
    /// Why OpenVPN said it was exiting by itself.
    exit_failure: Option<Failure>,
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
            retry_after_failure: false,
            attempt: 0,
            ever_connected: false,
            unreachable_tries: 0,
            reached_auth: false,
            tls_established: false,
            sent_code: None,
            cipher_error: None,
            auth_reason: None,
            last_problem: None,
            current_remote: String::new(),
            last_state: String::new(),
            progress_at: None,
            gen: 0,
            writer: None,
            queue: VecDeque::new(),
            pending: None,
            setup_done: false,
            setup_answered: false,
            holds: 0,
            hold_released: false,
            hold_release_at: None,
            connected: false,
            next_reach_at: None,
            reach_running: false,
            stopping: false,
            drop_reason: None,
            end_failure: None,
            exit_failure: None,
            stop_deadline: None,
            fatal: None,
            last_reconnect_reason: String::new(),
        }
    }

    fn emit(&self, ev: Event) {
        #[cfg(feature = "diagnostic-test")]
        let ev = {
            let mut ev = ev;
            redact_test_event(
                &mut ev,
                self.opts.login.password.expose(),
                self.opts.code_digits,
            );
            ev
        };
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
        for text in self.opts.notes.clone() {
            self.note(LogLevel::Info, text);
        }
        loop {
            match self.run_process() {
                ProcessEnd::UserStop => return EndReason::Disconnected,
                ProcessEnd::Fatal(failure) => return EndReason::Failed(failure),
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
        self.queue.clear();
        self.pending = None;
        self.progress_at = None;
        self.setup_done = false;
        self.setup_answered = false;
        self.holds = 0;
        self.hold_released = false;
        self.hold_release_at = None;
        self.connected = false;
        self.next_reach_at = None;
        self.stopping = false;
        self.drop_reason = None;
        self.end_failure = None;
        self.exit_failure = None;
        self.stop_deadline = None;
        self.fatal = None;
        self.awaiting_login = None;
        self.reset_try_state();
    }

    /// Forget what the last try found out, before the next one starts.
    fn reset_try_state(&mut self) {
        self.reached_auth = false;
        self.tls_established = false;
        self.cipher_error = None;
        self.auth_reason = None;
        self.last_problem = None;
        self.last_state.clear();
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
            Err(e) => return ProcessEnd::Fatal(Failure::other(e.to_string())),
        };
        self.note(LogLevel::Info, format!("Started: {description}"));

        // Wait for the management interface to open.
        let deadline = Instant::now() + MGMT_CONNECT_TIMEOUT;
        let stream = loop {
            if let Ok(s) = TcpStream::connect_timeout(&mgmt_addr, Duration::from_millis(500)) {
                break s;
            }
            if let Some(code) = process.try_wait() {
                return ProcessEnd::Fatal(Failure::other(exit_message(
                    code,
                    &process.output_tail(),
                )));
            }
            if Instant::now() > deadline {
                process.kill();
                return ProcessEnd::Fatal(Failure::other(format!(
                    "OpenVPN did not open its management interface within {}s.{}",
                    MGMT_CONNECT_TIMEOUT.as_secs(),
                    tail_text(&process.output_tail())
                )));
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
                return ProcessEnd::Fatal(Failure::other(format!("management connection: {e}")));
            }
        }
        spawn_reader(stream, self.gen, self.tx.clone());
        self.progress_at = Some(Instant::now());

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
                    self.on_line(&line, &mgmt_password, process.as_mut());
                    self.pump_queue();
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
                        self.drop_reason = None;
                        return self.stop_end();
                    }
                    self.note(LogLevel::Info, "Disconnecting.");
                    self.stopping = true;
                    self.progress_at = None;
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
                    return self.stop_end();
                }
            }
        }
    }

    fn stop_end(&mut self) -> ProcessEnd {
        if let Some(failure) = self.end_failure.take() {
            return ProcessEnd::Fatal(failure);
        }
        match self.drop_reason.take() {
            Some(reason) => ProcessEnd::Dropped(reason),
            None => ProcessEnd::UserStop,
        }
    }

    fn next_timeout(&self) -> Duration {
        let mut t = Duration::from_millis(500);
        for d in [
            self.hold_release_at,
            self.next_reach_at,
            self.stop_deadline,
            self.reply_deadline(),
            self.progress_deadline(),
        ]
        .into_iter()
        .flatten()
        {
            t = t.min(d.saturating_duration_since(Instant::now()));
        }
        t.max(Duration::from_millis(10))
    }

    /// When the command OpenVPN is answering counts as unanswered.
    fn reply_deadline(&self) -> Option<Instant> {
        let limit = if self.stopping {
            REPLY_TIMEOUT_STOPPING
        } else {
            REPLY_TIMEOUT
        };
        self.pending.as_ref().map(|p| p.sent_at + limit)
    }

    /// When the current try counts as stuck.
    fn progress_deadline(&self) -> Option<Instant> {
        let limit = self.opts.connect_timeout;
        if limit.is_zero() || self.stopping || self.connected {
            return None;
        }
        self.progress_at
            .map(|t| t + limit + CONNECT_GRACE.min(limit))
    }

    fn on_timers(&mut self, _process: &mut dyn VpnProcess) {
        let now_i = Instant::now();
        if self.reply_deadline().is_some_and(|d| now_i >= d) {
            let shown = self.pending.take().map(|p| p.shown).unwrap_or_default();
            if self.stopping {
                // The next command is the one that stops OpenVPN; send it anyway.
                self.note(
                    LogLevel::Warning,
                    format!("OpenVPN did not answer `{shown}`; going on."),
                );
                self.pump_queue();
            } else {
                self.give_up(Failure::new(
                    FailureKind::Timeout,
                    format!(
                        "OpenVPN stopped answering: no reply to `{shown}` within {} seconds. \
                         See `ovpn-otp logs --wire` for what was said before.",
                        REPLY_TIMEOUT.as_secs()
                    ),
                ));
            }
        }
        if self.progress_deadline().is_some_and(|d| now_i >= d) {
            let failure = self.stalled_failure();
            self.give_up(failure);
        }
        if let Some(at) = self.hold_release_at {
            if now_i >= at {
                self.hold_release_at = None;
                self.release_hold();
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
            return self.stop_end();
        }
        if let Some(f) = self.fatal.take() {
            // A fatal error before ever connecting is a setup problem; retrying
            // will not help. After a good connection it may be passing.
            if !self.ever_connected {
                return ProcessEnd::Fatal(Failure::other(f));
            }
            return ProcessEnd::Dropped(f);
        }
        if !self.ever_connected {
            let failure = self.exit_failure.take().unwrap_or_else(|| {
                Failure::other(exit_message(code.flatten(), &process.output_tail()))
            });
            return ProcessEnd::Fatal(failure);
        }
        ProcessEnd::Dropped("OpenVPN exited".into())
    }

    /// Let OpenVPN start the next try.
    fn release_hold(&mut self) {
        self.hold_released = true;
        self.reset_try_state();
        self.progress_at = Some(Instant::now());
        self.send("hold release", Reply::Simple);
    }

    /// Give a command to OpenVPN when its turn comes.
    ///
    /// This is the only way a command may reach the management interface:
    /// never write to `writer` directly. Commands go out one at a time, each
    /// after the answer to the one before has arrived in full, because
    /// OpenVPN on Windows loses a command that arrives while it is still
    /// answering another (see the module documentation).
    fn send(&mut self, cmd: &str, kind: Reply) {
        let shown = redact_outgoing(cmd);
        self.send_raw(cmd, &shown, kind);
    }

    fn send_raw(&mut self, cmd: &str, shown: &str, kind: Reply) {
        self.queue.push_back(QueuedCmd {
            line: Secret::new(format!("{}\n", cmd.trim_end_matches(['\r', '\n']))),
            shown: shown.to_string(),
            kind,
        });
        self.pump_queue();
    }

    /// Send the next waiting command if OpenVPN is not answering one.
    fn pump_queue(&mut self) {
        if self.pending.is_some() {
            return;
        }
        let Some(w) = self.writer.as_mut() else {
            return;
        };
        let Some(next) = self.queue.pop_front() else {
            return;
        };
        if w.write_all(next.line.expose().as_bytes()).is_err() {
            // The connection is gone; the reader reports it.
            self.queue.clear();
            return;
        }
        self.emit(Event::Wire {
            at: now(),
            dir: Direction::Out,
            text: next.shown.clone(),
        });
        self.pending = Some(PendingCmd {
            kind: next.kind,
            shown: next.shown,
            sent_at: Instant::now(),
            got_end: false,
            got_reply: false,
        });
    }

    /// End a try that cannot go on. Before the tunnel was ever up this ends
    /// the session with `failure`; after, OpenVPN is started again.
    fn give_up(&mut self, failure: Failure) {
        if self.stopping {
            return;
        }
        let unused_code = self.sent_code.take().filter(|_| !self.reached_auth);
        if self.pending_code.is_none() {
            self.pending_code = unused_code;
        }
        self.emit(Event::ConnectFailed {
            at: now(),
            failure: failure.clone(),
        });
        self.stopping = true;
        self.progress_at = None;
        self.hold_release_at = None;
        if self.ever_connected {
            self.retry_after_failure = true;
            self.drop_reason = Some(failure.message);
        } else {
            self.end_failure = Some(failure);
        }
        self.stop_deadline = Some(Instant::now() + STOP_TIMEOUT);
        self.send("signal SIGTERM", Reply::Simple);
    }

    /// The failure for a try that made no progress for the connect timeout.
    fn stalled_failure(&self) -> Failure {
        let server = if self.current_remote.is_empty() {
            self.opts.remotes.join(", ")
        } else {
            self.current_remote.clone()
        };
        let to_server = if server.is_empty() {
            String::new()
        } else {
            format!(" to {server}")
        };
        let what = match self.last_state.as_str() {
            "" | "CONNECTING" => {
                if self.hold_released {
                    "OpenVPN did not start to connect after its hold was released, and no \
                     connection to the server was opened"
                } else {
                    "OpenVPN was still waiting at its management hold, which was never \
                     released, so no connection to the server was opened"
                }
            }
            "RESOLVE" => "OpenVPN was still looking up the address of the server",
            "TCP_CONNECT" => "the server did not answer",
            "WAIT" => "the server took the connection and then said nothing",
            "AUTH" | "AUTH_PENDING" => "the server did not finish the login",
            "GET_CONFIG" => "the server did not send its settings",
            _ => "OpenVPN did not finish setting up the tunnel",
        };
        let problem = self
            .last_problem
            .as_deref()
            .map(|p| format!(" OpenVPN said: {p}."))
            .unwrap_or_default();
        Failure::new(
            FailureKind::Timeout,
            format!(
                "Gave up connecting{to_server} after {} seconds without progress: {what}.{problem} \
                 `ovpn-otp logs --wire` shows the conversation with OpenVPN. The wait is the \
                 setting connect.timeout.",
                self.opts.connect_timeout.as_secs()
            ),
        )
    }

    fn setup(&mut self) {
        if self.setup_done {
            return;
        }
        self.setup_done = true;
        self.send("log on all", Reply::LogHistory);
        self.send("state on all", Reply::StateHistory);
        // The hold is released after this one is answered, so that OpenVPN
        // is ready for the login when it comes (see `setup_answered`).
        self.send("bytecount 1", Reply::Simple);
    }

    /// The setup commands are all answered, so OpenVPN is done with them and
    /// waits for the hold release - whether or not its `>HOLD` notice was
    /// ever sent (see the module documentation).
    fn setup_answered(&mut self) {
        if self.setup_answered || !self.setup_done || self.holds > 0 || self.hold_released {
            // The `>HOLD` notice arrived (or a hold is being waited out):
            // that path releases the hold.
            return;
        }
        self.setup_answered = true;
        self.release_hold();
    }

    fn on_line(&mut self, raw: &str, mgmt_password: &Secret, process: &mut dyn VpnProcess) {
        let line = mgmt::parse_line(raw);
        // Anything OpenVPN says while a try is under way is progress, except
        // the byte counters, which tick by themselves.
        if self.progress_at.is_some()
            && !matches!(line, Line::Notification(Notification::ByteCount { .. }))
        {
            self.progress_at = Some(Instant::now());
        }
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
                if let Some(cmd) = self.pending.as_mut() {
                    cmd.got_reply = true;
                    if cmd.kind == Reply::Simple || cmd.got_end || matches!(line, Line::Error(_)) {
                        self.pending = None;
                    }
                }
                self.setup_answered();
            }
            Line::End => {
                if let Some(cmd) = self.pending.as_mut() {
                    cmd.got_end = true;
                    if cmd.got_reply {
                        self.pending = None;
                    }
                }
                self.setup_answered();
            }
            Line::Data(d) => match self.pending.as_ref().map(|p| p.kind) {
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
        if entry.message.starts_with("Control Channel: TLS")
            || entry.message.contains("Peer Connection Initiated with")
        {
            self.tls_established = true;
        }
        if let Some(reply) = mgmt::parse_push_reply(&entry.message) {
            self.emit(Event::Pushed(reply));
        }
        if entry.message.starts_with("OpenVPN ") && entry.message.contains(" [") {
            self.emit(Event::Version(entry.message.clone()));
        }
        if let Some(remote) = mgmt::parse_link_remote(&entry.message) {
            self.current_remote = remote;
        }
        if is_cipher_error(&entry.message) {
            self.cipher_error = Some(entry.message.clone());
        }
        if entry.level >= LogLevel::Error || explains_a_failure(&entry.message) {
            self.last_problem = Some(entry.message.clone());
        }
        self.emit(Event::Log(entry));
    }

    fn on_notification(&mut self, n: Notification) {
        match n {
            Notification::Info(_) => self.setup(),
            Notification::Hold { .. } => {
                self.holds += 1;
                if self.stopping {
                    // OpenVPN is about to be stopped; do not start another try.
                } else if self.holds == 1 && !self.connected_before_in_process() {
                    // First start of this process: any backoff already happened.
                    // The notice may come after the release that already happened
                    // when the setup commands were answered.
                    if !self.hold_released {
                        self.release_hold();
                    }
                } else {
                    let delay = backoff(&self.opts.keepalive, self.attempt.max(1));
                    self.note(
                        LogLevel::Info,
                        format!("Waiting {}s before reconnecting.", delay.as_secs()),
                    );
                    self.hold_release_at = Some(Instant::now() + delay);
                    self.progress_at = None;
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
        self.last_state = info.name.clone();
        if matches!(
            info.name.as_str(),
            "GET_CONFIG" | "ASSIGN_IP" | "ADD_ROUTES" | "CONNECTED"
        ) {
            self.tls_established = true;
        }
        match info.name.as_str() {
            "AUTH" | "GET_CONFIG" | "ASSIGN_IP" | "ADD_ROUTES" => {
                // The server answered, and the login goes to it now: the code
                // counts as used from here on.
                self.reached_auth = true;
                self.sent_code = None;
            }
            "CONNECTED" => {
                self.connected = true;
                self.ever_connected = true;
                self.attempt = 0;
                self.unreachable_tries = 0;
                self.last_login_rejected = false;
                self.retry_after_failure = false;
                self.reached_auth = true;
                self.sent_code = None;
                self.progress_at = None;
                if !self.opts.reach.host.trim().is_empty() {
                    self.next_reach_at = Some(Instant::now() + Duration::from_secs(1));
                }
            }
            "RECONNECTING" => {
                let was_connected = self.connected;
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
                    if was_connected {
                        self.on_drop(reason);
                    } else {
                        self.on_failed_try(reason, &info.detail);
                    }
                }
            }
            "EXITING" => {
                if !self.stopping && !self.connected && is_failure_detail(&info.detail) {
                    self.exit_failure = Some(self.classify_try(&info.detail));
                }
                self.connected = false;
                self.next_reach_at = None;
            }
            _ => {}
        }
        self.emit(Event::State { at: now(), info });
    }

    /// A working connection dropped.
    fn on_drop(&mut self, reason: String) {
        self.sent_code = None;
        self.progress_at = Some(Instant::now());
        if self.opts.keepalive.auto_reconnect {
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
            self.drop_reason = Some(reason);
            self.stop_deadline = Some(Instant::now() + STOP_TIMEOUT);
            self.send("signal SIGTERM", Reply::Simple);
        }
    }

    /// A try ended before the tunnel was up: say why, then give up or go on.
    fn on_failed_try(&mut self, reason: String, detail: &str) {
        let failure = self.classify_try(detail);
        // A code the server never saw has not been used; keep it for the next try.
        let unused_code = self.sent_code.take().filter(|_| !self.reached_auth);
        if self.pending_code.is_none() {
            self.pending_code = unused_code;
        }
        // A rejected login was already announced with `AuthFailed`.
        if failure.kind != FailureKind::AuthFailed {
            self.emit(Event::ConnectFailed {
                at: now(),
                failure: failure.clone(),
            });
        }
        let give_up = if self.ever_connected {
            // After a good connection the cause may be passing: keep trying.
            false
        } else {
            match failure.kind {
                FailureKind::AuthFailed => !self.opts.retry_login,
                FailureKind::Unreachable => {
                    self.unreachable_tries += 1;
                    self.unreachable_tries >= self.opts.remote_count.max(1) as u32
                }
                _ => true,
            }
        };
        if give_up {
            self.stopping = true;
            self.end_failure = Some(failure);
            self.stop_deadline = Some(Instant::now() + STOP_TIMEOUT);
            self.send("signal SIGTERM", Reply::Simple);
            return;
        }
        if !matches!(
            failure.kind,
            FailureKind::AuthFailed | FailureKind::Unreachable
        ) {
            self.retry_after_failure = true;
        }
        self.emit(Event::Reconnecting {
            at: now(),
            attempt: self.attempt,
            delay: backoff(&self.opts.keepalive, self.attempt),
            reason,
        });
    }

    /// Work out why the current try failed, from what OpenVPN reported.
    ///
    /// `detail` is the reason OpenVPN gives with `RECONNECTING` or `EXITING`,
    /// such as `connection-reset`, `auth-failure` or `tls-error`.
    fn classify_try(&self, detail: &str) -> Failure {
        let server = if self.current_remote.is_empty() {
            self.opts.remotes.join(", ")
        } else {
            self.current_remote.clone()
        };
        let at_server = if server.is_empty() {
            String::new()
        } else {
            format!(" at {server}")
        };
        let problem = self
            .last_problem
            .as_deref()
            .map(|p| format!(" OpenVPN said: {p}."))
            .unwrap_or_default();
        if let Some(line) = &self.cipher_error {
            return Failure::new(
                FailureKind::CipherMismatch,
                format!(
                    "The server{at_server} and OpenVPN have no encryption cipher in common. \
                     OpenVPN said: {line}. Add the cipher that the server uses with [openvpn] \
                     extra_options, for example \"data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC\"."
                ),
            );
        }
        if detail == "auth-failure" || self.auth_reason.is_some() {
            return Failure::new(
                FailureKind::AuthFailed,
                auth_failed_message(self.auth_reason.as_deref().unwrap_or("")),
            );
        }
        if !self.reached_auth {
            return Failure::new(
                FailureKind::Unreachable,
                format!(
                    "Could not reach the VPN server{at_server}.{problem} Check the network \
                     connection, and the server address and port in the profile."
                ),
            );
        }
        if detail == "connection-reset" && !self.tls_established {
            return Failure::new(
                FailureKind::ServerReset,
                format!(
                    "The server{at_server} closed the connection during login before OpenVPN \
                     reported that the secure channel was established. If your VPN provider \
                     gives each user a profile, select the profile downloaded for this user. \
                     If it still fails, ask your VPN administrator to check the client \
                     certificate and server logs."
                ),
            );
        }
        if detail == "connection-reset" {
            return Failure::new(
                FailureKind::ServerReset,
                format!(
                    "The server{at_server} closed the connection during login and gave no reason. \
                     Likely causes: the code was wrong or was already used once (wait for the next \
                     code), the password is wrong, or the server does not accept the encryption \
                     cipher that OpenVPN offered (a cipher mismatch)."
                ),
            );
        }
        let what = if detail.is_empty() {
            "connection restarted"
        } else {
            detail
        };
        Failure::other(format!(
            "The connection to the server{at_server} failed during login ({what}).{problem}"
        ))
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
                if is_cipher_error(&reason) {
                    // Not a wrong login: the server refused because no cipher
                    // matched. `on_failed_try` reports it.
                    self.cipher_error = Some(reason);
                    return;
                }
                self.last_login_rejected = true;
                self.auth_reason = Some(reason.clone());
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
            Some((code, at)) if at.elapsed() <= CODE_MAX_AGE => Some((code, at)),
            Some(_) => {
                self.note(LogLevel::Warning, "The code waiting to be used is too old.");
                self.progress_at = None;
                self.emit(Event::NeedCode {
                    reason: CodeReason::Expired,
                });
                return;
            }
            None => None,
        };
        let Some((code, typed_at)) = fresh else {
            let reason = if self.last_login_rejected {
                CodeReason::Rejected
            } else if self.retry_after_failure {
                CodeReason::Retry
            } else if self.ever_connected || self.attempt > 0 {
                CodeReason::Reconnect
            } else {
                CodeReason::Initial
            };
            // The wait is for the user now, not for OpenVPN.
            self.progress_at = None;
            self.emit(Event::NeedCode { reason });
            return;
        };
        self.awaiting_login = None;
        self.progress_at = Some(Instant::now());
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
        self.sent_code = Some((code, typed_at));
        self.last_login_rejected = false;
        self.retry_after_failure = false;
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

// The separate diagnostic build must not persist credentials, even if an
// unexpected OpenVPN message echoes them. Mask digit runs long enough to hold
// a code as well, because a code can have been discarded before a log arrives.
#[cfg(feature = "diagnostic-test")]
fn redact_test_text(text: &mut String, password: &str, digits: u8) {
    let lower = text.to_ascii_lowercase();
    if lower.contains("auth-token") || lower.contains("scrv1:") {
        *text = "******** (authentication data hidden)".into();
        return;
    }
    if !password.is_empty() {
        *text = text.replace(password, "********");
    }
    let mut output = String::new();
    let mut run = String::new();
    let flush = |output: &mut String, run: &mut String| {
        if run.len() >= usize::from(digits).max(1) {
            output.push_str("********");
        } else {
            output.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if c.is_ascii_digit() {
            run.push(c);
        } else {
            flush(&mut output, &mut run);
            output.push(c);
        }
    }
    flush(&mut output, &mut run);
    *text = output;
}

#[cfg(feature = "diagnostic-test")]
fn redact_test_event(event: &mut Event, password: &str, digits: u8) {
    let clean = |s: &mut String| redact_test_text(s, password, digits);
    match event {
        Event::Wire { text, .. } | Event::Note { text, .. } => clean(text),
        Event::Log(entry) => clean(&mut entry.message),
        Event::State { info, .. } => {
            clean(&mut info.detail);
            clean(&mut info.local_ip);
            clean(&mut info.remote_ip);
            clean(&mut info.remote_port);
        }
        Event::AuthFailed { reason } | Event::Reconnecting { reason, .. } => clean(reason),
        Event::ConnectFailed { failure, .. } => clean(&mut failure.message),
        Event::Ended { reason } => match reason {
            EndReason::Dropped(s) => clean(s),
            EndReason::Failed(f) => clean(&mut f.message),
            EndReason::Disconnected => {}
        },
        Event::Version(s) => clean(s),
        Event::Pushed(p) => {
            for s in &mut p.routes {
                clean(s);
            }
            for s in &mut p.dns {
                clean(s);
            }
            if let Some(s) = &mut p.ifconfig {
                clean(s);
            }
        }
        Event::Reach(r) => {
            clean(&mut r.target);
            if let Some(s) = &mut r.error {
                clean(s);
            }
        }
        _ => {}
    }
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

/// Whether a log line or a server reason says no data cipher could be agreed.
fn is_cipher_error(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    t.contains("cipher negotiation failed")
        || t.contains("failed to negotiate cipher")
        || t.contains("no shared cipher")
}

/// Whether a log line explains a failed try even though OpenVPN logs it as plain information.
fn explains_a_failure(message: &str) -> bool {
    [
        "TCP: connect to",
        "RESOLVE: Cannot resolve",
        "TLS Error",
        "Connection reset",
    ]
    .iter()
    .any(|p| message.starts_with(p))
}

/// Whether the reason OpenVPN gives for exiting means a try failed (rather
/// than someone stopping it).
fn is_failure_detail(detail: &str) -> bool {
    [
        "auth-failure",
        "connection-reset",
        "tls-error",
        "init_instance",
        "server_poll",
        "ping-restart",
        "process-push-msg-failed",
    ]
    .contains(&detail)
}

/// The message for a login the server rejected.
pub fn auth_failed_message(reason: &str) -> String {
    let said = if reason.is_empty() {
        String::new()
    } else {
        format!(" (the server said: {reason})")
    };
    format!(
        "The server rejected the login{said}. Check the code first: wait for a new one in your \
         authenticator app and try again. If it keeps failing, check the user name and password."
    )
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
    } else if joined.contains("Options error") {
        msg.push_str(
            "\nOpenVPN did not accept an option in the profile or in [openvpn] extra_options. \
             Run `ovpn-otp doctor` to check the extra options.",
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

    #[cfg(feature = "diagnostic-test")]
    #[test]
    fn diagnostic_events_remove_password_and_digit_codes() {
        let mut event = Event::Log(LogEntry {
            time: 1,
            level: LogLevel::Info,
            message: "received passWord-123 and 871234".into(),
        });
        redact_test_event(&mut event, "passWord-123", 6);
        let Event::Log(entry) = event else {
            panic!("expected log")
        };
        assert!(!entry.message.contains("passWord-123"));
        assert!(!entry.message.contains("871234"));
        assert!(entry.message.contains("********"));
        let mut wire = Event::Wire {
            at: now(),
            dir: Direction::In,
            text: ">PASSWORD:Auth-Token:secret".into(),
        };
        redact_test_event(&mut wire, "secret", 6);
        let Event::Wire { text, .. } = wire else {
            panic!("expected wire")
        };
        assert!(!text.contains("secret"));
        let mut challenge = "SCRV1:encoded-password:encoded-code".to_string();
        redact_test_text(&mut challenge, "different", 6);
        assert!(!challenge.contains("encoded-password"));
        let mut token = "PUSH_REPLY,auth-token,unrelated-secret".to_string();
        redact_test_text(&mut token, "different", 6);
        assert!(!token.contains("unrelated-secret"));
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
    fn explains_a_refused_option() {
        let m = exit_message(
            Some(1),
            &["Options error: Unrecognized option or missing or extra parameter(s) in work.ovpn:113: data-ciphers (2.7.0)".into()],
        );
        assert!(m.contains("extra_options"), "{m}");
        assert!(m.contains("work.ovpn:113"), "{m}");
    }

    #[test]
    fn failure_kinds_have_fixed_names() {
        for (kind, name) in [
            (FailureKind::AuthFailed, "auth_failed"),
            (FailureKind::ServerReset, "server_reset"),
            (FailureKind::CipherMismatch, "cipher_mismatch"),
            (FailureKind::Unreachable, "unreachable"),
            (FailureKind::Dropped, "dropped"),
            (FailureKind::Timeout, "timeout"),
            (FailureKind::Failed, "failed"),
        ] {
            assert_eq!(kind.name(), name);
            assert_eq!(serde_json::to_value(kind).unwrap(), name);
        }
    }

    #[test]
    fn prepared_config_names_are_safe() {
        let p = prepared_config_path(std::path::Path::new("/r"), "my work/vpn");
        assert_eq!(p, PathBuf::from("/r/my_work_vpn.ovpn"));
    }
}
