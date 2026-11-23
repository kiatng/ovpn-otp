//! What scripts and agents read: the status report and the exit codes.
//!
//! `ovpn-otp status --json` prints a [`StatusReport`]. The field names and the
//! values of `phase`, `failure_reason` and `code_reason` are fixed, so a
//! script can rely on them. The commands that wait for an outcome
//! (`connect --background`, `wait`) end with one of the codes in
//! [`exit_code`], decided by [`wait_verdict`].

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::runtime::{StatusFile, Using};
use crate::session::{CodeReason, FailureKind};
use crate::snapshot::{Headline, Phase, Tone};

/// The exit codes of the `ovpn-otp` command.
pub mod exit_code {
    /// It worked: connected, disconnected, or the answer was printed.
    pub const OK: u8 = 0;
    /// Something else failed, for example OpenVPN did not start.
    pub const FAILED: u8 = 1;
    /// The command line was wrong.
    pub const USAGE: u8 = 2;
    /// The server rejected the user name, password or code.
    pub const AUTH_FAILED: u8 = 3;
    /// The server closed the connection during login, or shares no cipher.
    pub const SERVER_RESET: u8 = 4;
    /// No server answered.
    pub const UNREACHABLE: u8 = 5;
    /// The session is waiting for an authenticator code.
    pub const NEEDS_CODE: u8 = 6;
    /// A time limit ran out: the one given with `--timeout`, or a connect
    /// made no progress for the `connect.timeout` in the settings.
    pub const TIMEOUT: u8 = 7;
    /// A working connection dropped and auto-reconnect is off.
    pub const DROPPED: u8 = 8;
}

/// The exit code that goes with a kind of failure.
pub fn failure_exit_code(kind: FailureKind) -> u8 {
    match kind {
        FailureKind::AuthFailed => exit_code::AUTH_FAILED,
        FailureKind::ServerReset | FailureKind::CipherMismatch => exit_code::SERVER_RESET,
        FailureKind::Unreachable => exit_code::UNREACHABLE,
        FailureKind::Dropped => exit_code::DROPPED,
        FailureKind::Timeout => exit_code::TIMEOUT,
        FailureKind::Failed => exit_code::FAILED,
    }
}

/// The session as `ovpn-otp status --json` prints it.
///
/// Every field is always present; one without a value is `null`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    /// A session is running right now.
    pub running: bool,
    /// `idle`, `starting`, `connecting`, `need_code`, `connected`,
    /// `reconnecting`, `disconnecting`, `disconnected` or `failed`.
    pub phase: Phase,
    /// The state in words, as the window shows it: `Connected`,
    /// `Connecting…`, `Waiting for your code`, `Reconnecting…`,
    /// `Disconnecting…`, `Disconnected` or `Failed`.
    pub state: String,
    /// What goes with `state`: the address and time when connected, the
    /// step and time while connecting, the reason when failed.
    pub state_detail: Option<String>,
    /// What OpenVPN is doing right now, while connecting.
    pub step: Option<String>,
    /// The session waits for a code; give it one with `ovpn-otp code`.
    pub needs_code: bool,
    /// Why a code is needed: `initial`, `reconnect`, `rejected`, `expired` or `retry`.
    pub code_reason: Option<CodeReason>,
    /// Why the last try failed: `auth_failed`, `server_reset`,
    /// `cipher_mismatch`, `unreachable`, `dropped`, `timeout` or `failed`.
    /// `null` once the session is connected.
    pub failure_reason: Option<FailureKind>,
    /// The message that goes with `failure_reason`.
    pub last_error: Option<String>,
    /// The server in use or being tried, as `host:port`.
    pub remote: Option<String>,
    /// The address of this machine inside the VPN.
    pub local_ip: Option<String>,
    /// When the session entered the current phase.
    pub since: Option<DateTime<Local>>,
    /// When the tunnel came up, while connected.
    pub connected_since: Option<DateTime<Local>>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    /// The state name OpenVPN itself reports, such as `CONNECTED` or `WAIT`.
    pub openvpn_state: Option<String>,
    /// How many times the session has tried to reconnect since the last drop.
    pub reconnect_attempt: u32,
    /// When the next reconnect try starts.
    pub next_retry: Option<DateTime<Local>>,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    /// The name of the connection in the settings file.
    pub name: Option<String>,
    /// The settings file the session uses.
    pub settings: Option<String>,
    /// The profile file in use.
    pub profile: Option<String>,
    /// The servers the profile points at, in the order OpenVPN tries them,
    /// such as `vpn.example.org:8443 (tcp)`.
    pub servers: Vec<String>,
    /// The user name of the login. The password is never in a report.
    pub username: Option<String>,
    /// The process that runs the session.
    pub pid: Option<u32>,
    /// When this status was written.
    pub updated: Option<DateTime<Local>>,
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

impl StatusReport {
    /// The report when no session has run yet.
    pub fn idle() -> StatusReport {
        StatusReport {
            running: false,
            phase: Phase::Idle,
            state: "Disconnected".into(),
            state_detail: None,
            step: None,
            needs_code: false,
            code_reason: None,
            failure_reason: None,
            last_error: None,
            remote: None,
            local_ip: None,
            since: None,
            connected_since: None,
            bytes_in: 0,
            bytes_out: 0,
            openvpn_state: None,
            reconnect_attempt: 0,
            next_retry: None,
            routes: Vec::new(),
            dns: Vec::new(),
            name: None,
            settings: None,
            profile: None,
            servers: Vec::new(),
            username: None,
            pid: None,
            updated: None,
        }
    }

    /// Say which connection, profile, servers and user name are in use.
    fn set_using(&mut self, using: &Using) {
        self.name = non_empty(&using.name);
        self.settings = non_empty(&using.settings);
        self.profile = non_empty(&using.profile);
        self.servers = using.servers.clone();
        self.username = non_empty(&using.username);
    }

    fn set_headline(&mut self, headline: Headline) {
        self.state = headline.title;
        self.state_detail = non_empty(&headline.detail);
    }

    /// Build the report from the status file of a session, if there is one.
    ///
    /// `current` is what the settings say right now. A running session
    /// reports what it uses itself; without one, the report says what the
    /// next connect would use.
    pub fn from_status(status: Option<&StatusFile>, current: Option<&Using>) -> StatusReport {
        let Some(st) = status else {
            let mut report = StatusReport::idle();
            if let Some(using) = current {
                report.set_using(using);
            }
            return report;
        };
        let s = &st.snapshot;
        let running = st.is_live();
        let mut report = StatusReport {
            running,
            phase: s.phase,
            state: String::new(),
            state_detail: None,
            step: s.step().filter(|_| running).map(str::to_string),
            needs_code: running && s.phase == Phase::NeedCode,
            code_reason: s.code_reason.filter(|_| running),
            failure_reason: s.failure,
            last_error: s.last_error.clone(),
            remote: non_empty(&s.server),
            local_ip: non_empty(&s.local_ip),
            since: s.phase_since,
            connected_since: s.connected_since.filter(|_| running),
            bytes_in: s.bytes_in,
            bytes_out: s.bytes_out,
            openvpn_state: non_empty(&s.state),
            reconnect_attempt: s.reconnect_attempt,
            next_retry: s.next_retry.filter(|_| running),
            routes: s.routes.clone(),
            dns: s.dns.clone(),
            name: None,
            settings: None,
            profile: None,
            servers: Vec::new(),
            username: None,
            pid: Some(st.pid),
            updated: Some(st.updated),
        };
        match current.filter(|_| !running) {
            Some(using) => report.set_using(using),
            None => report.set_using(&st.using()),
        }
        report.set_headline(s.headline(Local::now()));
        if !running && s.phase.is_active() {
            // The program that ran the session is gone and never wrote how it ended.
            report.phase = Phase::Failed;
            report.failure_reason = Some(FailureKind::Failed);
            report.last_error = Some(format!(
                "The session ended without cleaning up (process {} is gone).",
                st.pid
            ));
            report.since = Some(st.updated);
            report.state = "Failed".into();
            report.state_detail = report.last_error.clone();
        }
        report
    }

    /// The state as one line with its colour, for `ovpn-otp status`.
    pub fn headline(&self) -> Headline {
        let tone = match self.phase {
            Phase::Connected => Tone::Good,
            Phase::Failed => Tone::Bad,
            Phase::NeedCode | Phase::Reconnecting => Tone::Attention,
            Phase::Idle | Phase::Disconnected => Tone::Idle,
            Phase::Starting | Phase::Connecting | Phase::Disconnecting => Tone::Busy,
        };
        Headline {
            tone,
            title: self.state.clone(),
            detail: self.state_detail.clone().unwrap_or_default(),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a status report always serializes")
    }
}

/// What `wait --until` waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitTarget {
    Connected,
    Disconnected,
}

/// Whether a wait is over, and with which exit code. `None` means keep waiting.
///
/// Waiting for `connected` ends early when it cannot happen by itself: the
/// session failed or is not running (the code for the failure), or it waits
/// for an authenticator code ([`exit_code::NEEDS_CODE`]).
pub fn wait_verdict(report: &StatusReport, target: WaitTarget) -> Option<u8> {
    match target {
        WaitTarget::Disconnected => (!report.running).then_some(exit_code::OK),
        WaitTarget::Connected => {
            if !report.running {
                return Some(
                    report
                        .failure_reason
                        .map(failure_exit_code)
                        .unwrap_or(exit_code::FAILED),
                );
            }
            match report.phase {
                Phase::Connected => Some(exit_code::OK),
                Phase::NeedCode => Some(exit_code::NEEDS_CODE),
                _ => None,
            }
        }
    }
}

/// One sentence for the person or script that waited, to go with the exit code.
pub fn outcome_text(report: &StatusReport, target: WaitTarget) -> String {
    let dash = |v: &Option<String>| v.clone().unwrap_or_else(|| "-".into());
    match (target, report.running, report.phase) {
        (WaitTarget::Disconnected, false, _) => "Not connected.".into(),
        (_, true, Phase::Connected) => format!(
            "Connected. Tunnel address {}, server {}.",
            dash(&report.local_ip),
            dash(&report.remote)
        ),
        (_, true, Phase::NeedCode) => {
            "The session is waiting for an authenticator code. Send one with `ovpn-otp code`."
                .into()
        }
        (_, true, phase) => format!("Still {}.", phase.label().to_lowercase()),
        (_, false, _) => match &report.last_error {
            Some(e) if report.failure_reason.is_some() => e.clone(),
            _ => "No session is running.".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Snapshot;

    fn status(running: bool, edit: impl FnOnce(&mut Snapshot)) -> StatusFile {
        let mut snapshot = Snapshot::default();
        edit(&mut snapshot);
        StatusFile {
            pid: std::process::id(),
            name: "work".into(),
            settings: "/x/settings.toml".into(),
            profile: "/x/work.ovpn".into(),
            servers: vec!["203.0.113.10:8443 (tcp)".into()],
            username: "alice".into(),
            updated: Local::now(),
            running,
            snapshot,
        }
    }

    fn report(running: bool, edit: impl FnOnce(&mut Snapshot)) -> StatusReport {
        StatusReport::from_status(Some(&status(running, edit)), None)
    }

    /// The window and `status` always say what is in use: the profile, the
    /// server with its protocol, the connection and the user name.
    #[test]
    fn the_report_always_says_what_is_in_use() {
        let now_set = Using {
            name: "home".into(),
            settings: "/y/settings.toml".into(),
            profile: "/y/home.ovpn".into(),
            servers: vec!["vpn.example.org:1194 (udp)".into()],
            username: "bob".into(),
        };
        // Before any session: what the next connect would use.
        let r = StatusReport::from_status(None, Some(&now_set));
        assert_eq!(r.state, "Disconnected");
        assert_eq!(r.profile.as_deref(), Some("/y/home.ovpn"));
        assert_eq!(r.servers, vec!["vpn.example.org:1194 (udp)"]);
        assert_eq!(r.name.as_deref(), Some("home"));
        assert_eq!(r.username.as_deref(), Some("bob"));

        // A running session: what it uses, even when the settings changed since.
        let st = status(true, |s| {
            s.phase = Phase::Connecting;
            s.state = "AUTH".into();
            s.connecting_since = Some(Local::now() - chrono::Duration::seconds(12));
        });
        let r = StatusReport::from_status(Some(&st), Some(&now_set));
        assert_eq!(r.profile.as_deref(), Some("/x/work.ovpn"));
        assert_eq!(r.servers, vec!["203.0.113.10:8443 (tcp)"]);
        assert_eq!(r.name.as_deref(), Some("work"));
        assert_eq!(r.username.as_deref(), Some("alice"));
        assert_eq!(r.state, "Connecting…");
        assert_eq!(r.step.as_deref(), Some("logging in"));
        assert_eq!(r.state_detail.as_deref(), Some("logging in (12s)"));
        assert_eq!(r.headline().tone, Tone::Busy);

        // After it ended: the settings as they are now.
        let st = status(false, |s| {
            s.phase = Phase::Failed;
            s.failure = Some(FailureKind::Timeout);
            s.last_error = Some("gave up".into());
        });
        let r = StatusReport::from_status(Some(&st), Some(&now_set));
        assert_eq!(r.profile.as_deref(), Some("/y/home.ovpn"));
        assert_eq!(r.state, "Failed");
        assert_eq!(r.state_detail.as_deref(), Some("gave up"));
        assert_eq!(r.step, None);
        assert_eq!(r.headline().line(), "Failed: gave up");
        // Without the settings at hand, the last session still says what it used.
        let r = StatusReport::from_status(Some(&st), None);
        assert_eq!(r.profile.as_deref(), Some("/x/work.ovpn"));
        // The password has no place in a report.
        assert!(!r.to_json().to_lowercase().contains("password"));
    }

    #[test]
    fn every_field_is_present_even_before_any_session() {
        let v: serde_json::Value = serde_json::from_str(&StatusReport::idle().to_json()).unwrap();
        for field in [
            "running",
            "phase",
            "state",
            "state_detail",
            "step",
            "profile",
            "servers",
            "username",
            "needs_code",
            "code_reason",
            "failure_reason",
            "last_error",
            "remote",
            "local_ip",
            "since",
            "connected_since",
            "bytes_in",
            "bytes_out",
            "openvpn_state",
            "reconnect_attempt",
            "next_retry",
            "routes",
            "dns",
            "name",
            "settings",
            "pid",
            "updated",
        ] {
            assert!(v.get(field).is_some(), "missing field {field}");
        }
        assert_eq!(v["running"], false);
        assert_eq!(v["phase"], "idle");
        assert_eq!(v["needs_code"], false);
        assert!(v["failure_reason"].is_null());
    }

    #[test]
    fn a_connected_session_reports_where_and_how_much() {
        let r = report(true, |s| {
            s.phase = Phase::Connected;
            s.server = "203.0.113.10:8443".into();
            s.local_ip = "10.81.0.6".into();
            s.bytes_in = 5000;
            s.bytes_out = 900;
            s.connected_since = Some(Local::now());
            s.phase_since = Some(Local::now());
            s.state = "CONNECTED".into();
        });
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["running"], true);
        assert_eq!(v["phase"], "connected");
        assert_eq!(v["remote"], "203.0.113.10:8443");
        assert_eq!(v["local_ip"], "10.81.0.6");
        assert_eq!(v["bytes_in"], 5000);
        assert_eq!(v["bytes_out"], 900);
        assert_eq!(v["openvpn_state"], "CONNECTED");
        assert!(v["since"].is_string());
        assert!(v["connected_since"].is_string());
        assert_eq!(wait_verdict(&r, WaitTarget::Connected), Some(exit_code::OK));
        assert_eq!(wait_verdict(&r, WaitTarget::Disconnected), None);
    }

    #[test]
    fn a_waiting_session_says_it_needs_a_code() {
        let r = report(true, |s| {
            s.phase = Phase::NeedCode;
            s.code_reason = Some(CodeReason::Reconnect);
        });
        assert!(r.needs_code);
        let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
        assert_eq!(v["phase"], "need_code");
        assert_eq!(v["needs_code"], true);
        assert_eq!(v["code_reason"], "reconnect");
        assert_eq!(
            wait_verdict(&r, WaitTarget::Connected),
            Some(exit_code::NEEDS_CODE)
        );
    }

    #[test]
    fn each_kind_of_failure_has_its_own_exit_code() {
        for (kind, name, code) in [
            (FailureKind::AuthFailed, "auth_failed", 3),
            (FailureKind::ServerReset, "server_reset", 4),
            (FailureKind::CipherMismatch, "cipher_mismatch", 4),
            (FailureKind::Unreachable, "unreachable", 5),
            (FailureKind::Dropped, "dropped", 8),
            (FailureKind::Timeout, "timeout", 7),
            (FailureKind::Failed, "failed", 1),
        ] {
            let r = report(false, |s| {
                s.phase = if kind == FailureKind::Dropped {
                    Phase::Disconnected
                } else {
                    Phase::Failed
                };
                s.failure = Some(kind);
                s.last_error = Some("why".into());
            });
            let v: serde_json::Value = serde_json::from_str(&r.to_json()).unwrap();
            assert_eq!(v["failure_reason"], name);
            assert_eq!(v["last_error"], "why");
            assert_eq!(v["running"], false);
            assert_eq!(v["needs_code"], false);
            assert_eq!(
                wait_verdict(&r, WaitTarget::Connected),
                Some(code),
                "{name}"
            );
            assert_eq!(wait_verdict(&r, WaitTarget::Disconnected), Some(0));
            assert_eq!(outcome_text(&r, WaitTarget::Connected), "why");
        }
        // The codes are all different from each other and from ok, usage and timeout.
        let mut codes = vec![
            exit_code::OK,
            exit_code::FAILED,
            exit_code::USAGE,
            exit_code::AUTH_FAILED,
            exit_code::SERVER_RESET,
            exit_code::UNREACHABLE,
            exit_code::NEEDS_CODE,
            exit_code::TIMEOUT,
            exit_code::DROPPED,
        ];
        codes.dedup();
        assert_eq!(codes, vec![0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn waiting_goes_on_while_the_session_is_still_working() {
        for phase in [Phase::Starting, Phase::Connecting, Phase::Reconnecting] {
            let r = report(true, |s| s.phase = phase);
            assert_eq!(wait_verdict(&r, WaitTarget::Connected), None, "{phase:?}");
            assert_eq!(wait_verdict(&r, WaitTarget::Disconnected), None);
        }
    }

    #[test]
    fn a_session_that_never_ran_or_ended_normally_cannot_become_connected() {
        let idle = StatusReport::idle();
        assert_eq!(
            wait_verdict(&idle, WaitTarget::Connected),
            Some(exit_code::FAILED)
        );
        assert_eq!(
            outcome_text(&idle, WaitTarget::Connected),
            "No session is running."
        );
        let done = report(false, |s| s.phase = Phase::Disconnected);
        assert_eq!(
            wait_verdict(&done, WaitTarget::Connected),
            Some(exit_code::FAILED)
        );
        assert_eq!(wait_verdict(&done, WaitTarget::Disconnected), Some(0));
    }

    #[test]
    fn a_session_that_vanished_is_reported_as_failed() {
        let mut st = status(true, |s| {
            s.phase = Phase::Connected;
            s.connected_since = Some(Local::now());
        });
        // Long past the time a live session would have rewritten the file.
        st.updated = Local::now() - chrono::Duration::seconds(120);
        let r = StatusReport::from_status(Some(&st), None);
        assert!(!r.running);
        assert_eq!(r.phase, Phase::Failed);
        assert_eq!(r.state, "Failed");
        assert_eq!(r.failure_reason, Some(FailureKind::Failed));
        assert!(r.last_error.unwrap().contains("without cleaning up"));
        assert_eq!(r.connected_since, None);
    }
}
