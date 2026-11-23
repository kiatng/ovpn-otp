//! The current picture of a session, built from its events.
//!
//! Both the GUI and the CLI fold [`Event`]s into a [`Snapshot`] and draw from
//! it, so they always agree on what is going on.

use std::collections::VecDeque;

use chrono::{DateTime, Local, TimeZone};
use serde::{Deserialize, Serialize};

use crate::mgmt::{self, LogEntry, LogLevel};
use crate::reach::ReachResult;
use crate::session::{self, CodeReason, Direction, EndReason, Event, FailureKind};

const MAX_TIMELINE: usize = 300;
const MAX_LOG: usize = 3000;
const MAX_WIRE: usize = 3000;

/// The overall situation, in plain terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    #[default]
    Idle,
    Starting,
    Connecting,
    NeedCode,
    Connected,
    Reconnecting,
    Disconnecting,
    Disconnected,
    Failed,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Idle => "Not connected",
            Phase::Starting => "Starting OpenVPN",
            Phase::Connecting => "Connecting",
            Phase::NeedCode => "Waiting for your code",
            Phase::Connected => "Connected",
            Phase::Reconnecting => "Reconnecting",
            Phase::Disconnecting => "Disconnecting",
            Phase::Disconnected => "Disconnected",
            Phase::Failed => "Failed",
        }
    }

    /// Whether a session is running (so Connect should be disabled).
    pub fn is_active(self) -> bool {
        !matches!(self, Phase::Idle | Phase::Disconnected | Phase::Failed)
    }

    /// Whether the session is working towards a connection by itself.
    pub fn is_connecting(self) -> bool {
        matches!(
            self,
            Phase::Starting | Phase::Connecting | Phase::Reconnecting
        )
    }
}

/// What kind of news a [`Headline`] is, for the colour it is shown in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Connected.
    Good,
    /// Working on it.
    Busy,
    /// The user has to do something, or the connection is being restored.
    Attention,
    /// Failed.
    Bad,
    /// Nothing is running.
    Idle,
}

/// The state of the session in words, the same in the window and in
/// `ovpn-otp status`: a short title and the detail that goes with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Headline {
    pub tone: Tone,
    /// `Connected`, `Connecting…`, `Disconnected`, `Failed`, ...
    pub title: String,
    /// The address and time when connected, the step and time while
    /// connecting, the reason when failed. May be empty.
    pub detail: String,
}

impl Headline {
    /// Title and detail on one line.
    pub fn line(&self) -> String {
        if self.detail.is_empty() {
            self.title.clone()
        } else {
            format!("{}: {}", self.title, self.detail)
        }
    }
}

/// What OpenVPN is doing in a state, in plain words.
pub fn step_label(state: &str) -> &'static str {
    match state {
        "" => "starting OpenVPN",
        "INITIAL" | "CONNECTING" => "getting ready",
        "RESOLVE" => "looking up the server",
        "TCP_CONNECT" => "opening a connection to the server",
        "WAIT" => "waiting for the server to answer",
        "AUTH" => "logging in",
        "AUTH_PENDING" => "waiting for the server to accept the login",
        "GET_CONFIG" => "getting settings from the server",
        "ASSIGN_IP" => "setting the tunnel address",
        "ADD_ROUTES" => "adding routes",
        "RECONNECTING" => "starting again",
        "EXITING" => "stopping",
        _ => "working",
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub at: DateTime<Local>,
    pub state: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogLine {
    pub at: DateTime<Local>,
    pub level: LogLevel,
    /// `openvpn` or `app`.
    pub source: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireLine {
    pub at: DateTime<Local>,
    pub dir: Direction,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub phase: Phase,
    /// When the session entered the current phase.
    pub phase_since: Option<DateTime<Local>>,
    /// When the session started working towards a connection, while it does.
    #[serde(default)]
    pub connecting_since: Option<DateTime<Local>>,
    /// OpenVPN's own state name (`CONNECTED`, `WAIT`, ...).
    pub state: String,
    pub state_detail: String,
    pub timeline: VecDeque<TimelineEntry>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// Bytes per second, from the last two counter samples.
    pub rate_in: f64,
    pub rate_out: f64,
    /// When the received-bytes counter last went up.
    pub last_received: Option<DateTime<Local>>,
    pub connected_since: Option<DateTime<Local>>,
    pub local_ip: String,
    pub server: String,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub openvpn_version: String,
    pub reach: Option<ReachResult>,
    pub code_reason: Option<CodeReason>,
    pub reconnect_attempt: u32,
    pub next_retry: Option<DateTime<Local>>,
    /// Why the last try failed, until the session connects.
    pub failure: Option<FailureKind>,
    /// The message that goes with `failure`, until the session connects.
    pub last_error: Option<String>,
    pub ended: Option<EndReason>,
    #[serde(skip)]
    pub logs: VecDeque<LogLine>,
    #[serde(skip)]
    pub wire: VecDeque<WireLine>,
    #[serde(skip)]
    last_sample: Option<(DateTime<Local>, u64, u64)>,
}

fn push_capped<T>(q: &mut VecDeque<T>, item: T, cap: usize) {
    if q.len() >= cap {
        q.pop_front();
    }
    q.push_back(item);
}

fn ts(secs: i64) -> DateTime<Local> {
    Local
        .timestamp_opt(secs, 0)
        .single()
        .unwrap_or_else(Local::now)
}

impl Snapshot {
    /// Fold one event in.
    pub fn apply(&mut self, ev: &Event) {
        let before = self.phase;
        self.fold(ev);
        if self.phase != before || self.phase_since.is_none() {
            self.phase_since = Some(Local::now());
        }
        if !self.phase.is_connecting() {
            self.connecting_since = None;
        } else if self.connecting_since.is_none() {
            self.connecting_since = Some(Local::now());
        }
    }

    /// What OpenVPN is doing right now, while the session is connecting.
    pub fn step(&self) -> Option<&'static str> {
        match self.phase {
            Phase::Starting => Some(step_label("")),
            Phase::Connecting | Phase::Reconnecting => Some(step_label(&self.state)),
            _ => None,
        }
    }

    /// The state of the session in words. See [`Headline`].
    pub fn headline(&self, now: DateTime<Local>) -> Headline {
        let elapsed = |since: Option<DateTime<Local>>| {
            since.map(|t| format_duration((now - t).num_seconds()))
        };
        let (tone, title, detail) = match self.phase {
            Phase::Idle => (Tone::Idle, "Disconnected", String::new()),
            Phase::Disconnected => (
                Tone::Idle,
                "Disconnected",
                // A dropped connection says why.
                self.last_error
                    .clone()
                    .filter(|_| self.failure == Some(FailureKind::Dropped))
                    .unwrap_or_default(),
            ),
            Phase::Failed => (
                Tone::Bad,
                "Failed",
                self.last_error.clone().unwrap_or_default(),
            ),
            Phase::Connected => {
                let mut parts = Vec::new();
                if !self.local_ip.is_empty() {
                    parts.push(format!("address {}", self.local_ip));
                }
                if let Some(since) = self.connected_since {
                    parts.push(format!(
                        "since {} ({})",
                        since.format("%H:%M:%S"),
                        format_duration((now - since).num_seconds())
                    ));
                }
                (Tone::Good, "Connected", parts.join(", "))
            }
            Phase::NeedCode => (
                Tone::Attention,
                "Waiting for your code",
                match self.code_reason {
                    Some(CodeReason::Reconnect) => "the connection dropped; enter a new code",
                    Some(CodeReason::Rejected) => "the login was rejected; enter a new code",
                    Some(CodeReason::Expired) => "the code was too old; enter a new one",
                    Some(CodeReason::Retry) => "the last try failed; enter a new code",
                    _ => "the server asks for your authenticator code",
                }
                .to_string(),
            ),
            Phase::Disconnecting => (Tone::Busy, "Disconnecting…", String::new()),
            Phase::Starting | Phase::Connecting | Phase::Reconnecting => {
                let mut detail = self.step().unwrap_or("working").to_string();
                if let Some(at) = self.next_retry.filter(|t| *t > now) {
                    detail = format!(
                        "try {} starts in {}",
                        self.reconnect_attempt,
                        format_duration((at - now).num_seconds())
                    );
                }
                if let Some(e) = elapsed(self.connecting_since) {
                    detail = format!("{detail} ({e})");
                }
                if self.phase == Phase::Reconnecting {
                    (Tone::Attention, "Reconnecting…", detail)
                } else {
                    (Tone::Busy, "Connecting…", detail)
                }
            }
        };
        Headline {
            tone,
            title: title.to_string(),
            detail,
        }
    }

    fn fold(&mut self, ev: &Event) {
        match ev {
            Event::Launching { at, attempt } => {
                self.phase = Phase::Starting;
                self.ended = None;
                self.next_retry = None;
                if *attempt == 0 {
                    self.last_error = None;
                    self.failure = None;
                }
                self.push_timeline(
                    *at,
                    "START",
                    if *attempt == 0 {
                        "starting OpenVPN".into()
                    } else {
                        format!("retry {attempt}")
                    },
                );
            }
            Event::Wire { at, dir, text } => push_capped(
                &mut self.wire,
                WireLine {
                    at: *at,
                    dir: *dir,
                    text: text.clone(),
                },
                MAX_WIRE,
            ),
            Event::State { at, info } => {
                let at = if info.time > 0 { ts(info.time) } else { *at };
                self.state = info.name.clone();
                self.state_detail = info.detail.clone();
                if !info.remote_ip.is_empty() {
                    self.server = if info.remote_port.is_empty() {
                        info.remote_ip.clone()
                    } else {
                        format!("{}:{}", info.remote_ip, info.remote_port)
                    };
                }
                match info.name.as_str() {
                    "CONNECTED" => {
                        self.phase = Phase::Connected;
                        self.connected_since = Some(at);
                        self.reconnect_attempt = 0;
                        self.next_retry = None;
                        self.code_reason = None;
                        self.failure = None;
                        self.last_error = None;
                        if !info.local_ip.is_empty() {
                            self.local_ip = info.local_ip.clone();
                        }
                    }
                    "RECONNECTING" => {
                        self.phase = Phase::Reconnecting;
                        self.connected_since = None;
                    }
                    "EXITING" => {
                        self.phase = Phase::Disconnecting;
                        self.connected_since = None;
                    }
                    _ => {
                        if self.phase != Phase::NeedCode {
                            self.phase = Phase::Connecting;
                        }
                    }
                }
                let detail = [info.detail.as_str(), info.local_ip.as_str()]
                    .iter()
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                self.push_timeline(at, &info.name, detail);
            }
            Event::Bytes {
                at,
                bytes_in,
                bytes_out,
            } => {
                if let Some((t0, i0, o0)) = self.last_sample {
                    let dt = (*at - t0).num_milliseconds() as f64 / 1000.0;
                    if dt > 0.0 && *bytes_in >= i0 && *bytes_out >= o0 {
                        self.rate_in = (*bytes_in - i0) as f64 / dt;
                        self.rate_out = (*bytes_out - o0) as f64 / dt;
                    }
                    if *bytes_in > i0 {
                        self.last_received = Some(*at);
                    }
                } else if *bytes_in > 0 {
                    self.last_received = Some(*at);
                }
                self.last_sample = Some((*at, *bytes_in, *bytes_out));
                self.bytes_in = *bytes_in;
                self.bytes_out = *bytes_out;
            }
            Event::Log(LogEntry {
                time,
                level,
                message,
            }) => {
                // The server being tried, before OpenVPN reports it in a state.
                if let Some(remote) = mgmt::parse_link_remote(message) {
                    self.server = remote;
                }
                push_capped(
                    &mut self.logs,
                    LogLine {
                        at: if *time > 0 { ts(*time) } else { Local::now() },
                        level: *level,
                        source: "openvpn".into(),
                        message: message.clone(),
                    },
                    MAX_LOG,
                )
            }
            Event::Note { at, level, text } => {
                if *level >= LogLevel::Error {
                    self.last_error = Some(text.clone());
                }
                self.push_app_log(*at, *level, text.clone());
            }
            Event::NeedCode { reason } => {
                self.phase = Phase::NeedCode;
                self.code_reason = Some(*reason);
                let text = match reason {
                    CodeReason::Initial => "Waiting for the authenticator code.",
                    CodeReason::Reconnect => "Reconnecting: enter a new authenticator code.",
                    CodeReason::Rejected => {
                        "Login rejected: check the password and enter a new code."
                    }
                    CodeReason::Expired => "The code was too old: enter a new one.",
                    CodeReason::Retry => "The last try failed: enter a new code to try again.",
                };
                self.push_app_log(Local::now(), LogLevel::Warning, text.into());
            }
            Event::LoginSent { at } => {
                self.code_reason = None;
                if self.phase == Phase::NeedCode {
                    self.phase = Phase::Connecting;
                }
                self.push_timeline(*at, "LOGIN", "login sent".into());
            }
            Event::AuthFailed { reason } => {
                self.failure = Some(FailureKind::AuthFailed);
                self.last_error = Some(session::auth_failed_message(reason));
                self.push_timeline(Local::now(), "AUTH_FAILED", reason.clone());
                self.push_app_log(
                    Local::now(),
                    LogLevel::Error,
                    format!("Login rejected: {reason}"),
                );
            }
            Event::ConnectFailed { at, failure } => {
                self.failure = Some(failure.kind);
                self.last_error = Some(failure.message.clone());
                self.push_timeline(*at, "FAILED", failure.kind.name().to_string());
                self.push_app_log(*at, LogLevel::Error, failure.message.clone());
            }
            Event::Pushed(p) => {
                if !p.routes.is_empty() {
                    self.routes = p.routes.clone();
                }
                if !p.dns.is_empty() {
                    self.dns = p.dns.clone();
                }
            }
            Event::Version(v) => self.openvpn_version = v.clone(),
            Event::Reconnecting {
                at,
                attempt,
                delay,
                reason,
            } => {
                self.phase = Phase::Reconnecting;
                self.reconnect_attempt = *attempt;
                self.next_retry = chrono::Duration::from_std(*delay).ok().map(|d| *at + d);
                self.connected_since = None;
                self.push_app_log(
                    *at,
                    LogLevel::Warning,
                    format!(
                        "Connection lost ({reason}). Try {attempt} in {}s.",
                        delay.as_secs()
                    ),
                );
            }
            Event::Reach(r) => self.reach = Some(r.clone()),
            Event::Ended { reason } => {
                self.phase = match reason {
                    EndReason::Disconnected => Phase::Disconnected,
                    EndReason::Dropped(_) => Phase::Disconnected,
                    EndReason::Failed(_) => Phase::Failed,
                };
                self.connected_since = None;
                self.next_retry = None;
                self.code_reason = None;
                self.rate_in = 0.0;
                self.rate_out = 0.0;
                let text = match reason {
                    EndReason::Disconnected => "Disconnected.".to_string(),
                    EndReason::Dropped(r) => {
                        let text = format!("Connection dropped: {r}");
                        self.failure = Some(FailureKind::Dropped);
                        self.last_error = Some(text.clone());
                        text
                    }
                    EndReason::Failed(f) => {
                        // The message is already in the log when a failed try ended the session.
                        let said = self.last_error.as_deref() == Some(f.message.as_str());
                        self.failure = Some(f.kind);
                        self.last_error = Some(f.message.clone());
                        if said {
                            format!("Failed ({}).", f.kind.name())
                        } else {
                            format!("Failed: {}", f.message)
                        }
                    }
                };
                let level = if matches!(reason, EndReason::Disconnected) {
                    LogLevel::Info
                } else {
                    LogLevel::Error
                };
                self.push_timeline(Local::now(), "ENDED", text.clone());
                self.push_app_log(Local::now(), level, text);
                self.ended = Some(reason.clone());
            }
        }
    }

    fn push_timeline(&mut self, at: DateTime<Local>, state: &str, detail: String) {
        push_capped(
            &mut self.timeline,
            TimelineEntry {
                at,
                state: state.to_string(),
                detail,
            },
            MAX_TIMELINE,
        );
    }

    fn push_app_log(&mut self, at: DateTime<Local>, level: LogLevel, message: String) {
        push_capped(
            &mut self.logs,
            LogLine {
                at,
                level,
                source: "app".into(),
                message,
            },
            MAX_LOG,
        );
    }

    /// Seconds since data last arrived, if any did.
    pub fn idle_secs(&self, now: DateTime<Local>) -> Option<i64> {
        self.last_received.map(|t| (now - t).num_seconds().max(0))
    }
}

/// `1536` -> `1.5 KiB`.
pub fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// `75` -> `1m 15s`.
pub fn format_duration(secs: i64) -> String {
    let secs = secs.max(0);
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mgmt::StateInfo;
    use crate::session::Failure;

    fn state(name: &str, ip: &str) -> Event {
        Event::State {
            at: Local::now(),
            info: StateInfo {
                time: 0,
                name: name.into(),
                detail: if name == "CONNECTED" {
                    "SUCCESS".into()
                } else {
                    String::new()
                },
                local_ip: ip.into(),
                remote_ip: "198.51.100.7".into(),
                remote_port: "8443".into(),
            },
        }
    }

    #[test]
    fn follows_a_connection() {
        let mut s = Snapshot::default();
        s.apply(&Event::Launching {
            at: Local::now(),
            attempt: 0,
        });
        assert_eq!(s.phase, Phase::Starting);
        s.apply(&state("WAIT", ""));
        assert_eq!(s.phase, Phase::Connecting);
        s.apply(&Event::NeedCode {
            reason: CodeReason::Initial,
        });
        assert_eq!(s.phase, Phase::NeedCode);
        s.apply(&Event::LoginSent { at: Local::now() });
        assert_eq!(s.phase, Phase::Connecting);
        s.apply(&state("CONNECTED", "10.8.0.6"));
        assert_eq!(s.phase, Phase::Connected);
        assert_eq!(s.local_ip, "10.8.0.6");
        assert_eq!(s.server, "198.51.100.7:8443");
        assert!(s.connected_since.is_some());
        let names: Vec<_> = s.timeline.iter().map(|t| t.state.as_str()).collect();
        assert_eq!(names, vec!["START", "WAIT", "LOGIN", "CONNECTED"]);
    }

    #[test]
    fn computes_rates_and_last_received() {
        let mut s = Snapshot::default();
        let t0 = Local::now();
        s.apply(&Event::Bytes {
            at: t0,
            bytes_in: 1000,
            bytes_out: 500,
        });
        s.apply(&Event::Bytes {
            at: t0 + chrono::Duration::seconds(2),
            bytes_in: 3000,
            bytes_out: 500,
        });
        assert_eq!(s.rate_in, 1000.0);
        assert_eq!(s.rate_out, 0.0);
        assert_eq!(s.last_received, Some(t0 + chrono::Duration::seconds(2)));
        s.apply(&Event::Bytes {
            at: t0 + chrono::Duration::seconds(3),
            bytes_in: 3000,
            bytes_out: 900,
        });
        assert_eq!(s.last_received, Some(t0 + chrono::Duration::seconds(2)));
        assert_eq!(s.idle_secs(t0 + chrono::Duration::seconds(10)), Some(8));
    }

    #[test]
    fn ended_failed_keeps_error() {
        let mut s = Snapshot::default();
        s.apply(&Event::Ended {
            reason: EndReason::Failed(Failure::other("no openvpn")),
        });
        assert_eq!(s.phase, Phase::Failed);
        assert_eq!(s.failure, Some(FailureKind::Failed));
        assert_eq!(s.last_error.as_deref(), Some("no openvpn"));
        assert!(!s.phase.is_active());
    }

    #[test]
    fn a_failed_try_shows_until_the_session_connects() {
        let mut s = Snapshot::default();
        s.apply(&Event::ConnectFailed {
            at: Local::now(),
            failure: Failure::new(FailureKind::ServerReset, "closed during login"),
        });
        assert_eq!(s.failure, Some(FailureKind::ServerReset));
        assert_eq!(s.last_error.as_deref(), Some("closed during login"));
        assert!(s
            .timeline
            .iter()
            .any(|t| t.state == "FAILED" && t.detail == "server_reset"));
        s.apply(&Event::NeedCode {
            reason: CodeReason::Retry,
        });
        assert_eq!(s.phase, Phase::NeedCode);
        assert_eq!(s.failure, Some(FailureKind::ServerReset));
        s.apply(&state("CONNECTED", "10.8.0.6"));
        assert_eq!(s.failure, None);
        assert_eq!(s.last_error, None);

        s.apply(&Event::AuthFailed {
            reason: String::new(),
        });
        assert_eq!(s.failure, Some(FailureKind::AuthFailed));
        assert!(s
            .last_error
            .as_deref()
            .unwrap()
            .contains("rejected the login"));
        s.apply(&Event::Ended {
            reason: EndReason::Dropped("ping-restart".into()),
        });
        assert_eq!(s.phase, Phase::Disconnected);
        assert_eq!(s.failure, Some(FailureKind::Dropped));
    }

    #[test]
    fn tracks_when_the_phase_began_and_the_server_being_tried() {
        let mut s = Snapshot::default();
        s.apply(&Event::Launching {
            at: Local::now(),
            attempt: 0,
        });
        let started = s.phase_since.expect("phase_since is set");
        s.apply(&Event::Log(LogEntry {
            time: 0,
            level: LogLevel::Info,
            message: "TCP connection established with [AF_INET]203.0.113.10:8443".into(),
        }));
        assert_eq!(s.server, "203.0.113.10:8443");
        assert_eq!(
            s.phase_since,
            Some(started),
            "a log line does not change the phase"
        );
        s.apply(&state("WAIT", ""));
        assert!(s.phase_since.unwrap() >= started);
        assert_eq!(s.phase, Phase::Connecting);
    }

    /// The state line that the window and `ovpn-otp status` both show.
    #[test]
    fn the_headline_says_the_state_in_words() {
        let now = Local::now();
        let mut s = Snapshot::default();
        let h = s.headline(now);
        assert_eq!((h.tone, h.line().as_str()), (Tone::Idle, "Disconnected"));

        s.apply(&Event::Launching {
            at: now,
            attempt: 0,
        });
        s.connecting_since = Some(now - chrono::Duration::seconds(3));
        let h = s.headline(now);
        assert_eq!(h.tone, Tone::Busy);
        assert_eq!(h.line(), "Connecting…: starting OpenVPN (3s)");

        s.apply(&state("TCP_CONNECT", ""));
        assert_eq!(s.step(), Some("opening a connection to the server"));
        s.apply(&state("AUTH", ""));
        s.connecting_since = Some(now - chrono::Duration::seconds(12));
        assert_eq!(s.headline(now).line(), "Connecting…: logging in (12s)");

        s.apply(&Event::NeedCode {
            reason: CodeReason::Rejected,
        });
        let h = s.headline(now);
        assert_eq!(h.tone, Tone::Attention);
        assert_eq!(h.title, "Waiting for your code");
        assert!(h.detail.contains("rejected"), "{}", h.detail);
        assert_eq!(s.connecting_since, None, "the wait is for the user");

        s.apply(&Event::LoginSent { at: now });
        assert!(s.connecting_since.is_some());
        s.apply(&state("CONNECTED", "10.8.0.6"));
        s.connected_since = Some(now - chrono::Duration::seconds(75));
        let h = s.headline(now);
        assert_eq!(h.tone, Tone::Good);
        assert_eq!(h.title, "Connected");
        assert!(
            h.detail.starts_with("address 10.8.0.6, since "),
            "{}",
            h.detail
        );
        assert!(h.detail.ends_with("(1m 15s)"), "{}", h.detail);
        assert_eq!(s.step(), None);

        s.apply(&Event::Reconnecting {
            at: now,
            attempt: 2,
            delay: std::time::Duration::from_secs(4),
            reason: "ping-restart".into(),
        });
        let h = s.headline(now);
        assert_eq!(h.tone, Tone::Attention);
        assert!(
            h.line().starts_with("Reconnecting…: try 2 starts in"),
            "{}",
            h.line()
        );

        s.apply(&Event::Ended {
            reason: EndReason::Failed(Failure::new(FailureKind::Timeout, "gave up")),
        });
        let h = s.headline(now);
        assert_eq!((h.tone, h.line().as_str()), (Tone::Bad, "Failed: gave up"));

        let mut s = Snapshot::default();
        s.apply(&Event::Ended {
            reason: EndReason::Dropped("ping-restart".into()),
        });
        assert_eq!(
            s.headline(now).line(),
            "Disconnected: Connection dropped: ping-restart"
        );
        s.apply(&Event::Ended {
            reason: EndReason::Disconnected,
        });
        // Every state OpenVPN reports has words.
        for name in ["RESOLVE", "WAIT", "GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES"] {
            assert_ne!(step_label(name), "working", "{name}");
        }
    }

    #[test]
    fn phases_and_reasons_use_fixed_lower_case_names() {
        assert_eq!(serde_json::to_value(Phase::NeedCode).unwrap(), "need_code");
        assert_eq!(serde_json::to_value(Phase::Connected).unwrap(), "connected");
        assert_eq!(serde_json::to_value(CodeReason::Retry).unwrap(), "retry");
        assert_eq!(serde_json::to_value(LogLevel::Warning).unwrap(), "warning");
        assert_eq!(serde_json::to_value(Direction::In).unwrap(), "in");
    }

    #[test]
    fn formats_numbers() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(format_duration(75), "1m 15s");
        assert_eq!(format_duration(3661), "1h 1m 1s");
    }
}
