//! What scripts and agents read: the status report and the exit codes.
//!
//! `ovpn-otp status --json` prints a [`StatusReport`]. The field names and the
//! values of `phase`, `failure_reason` and `code_reason` are fixed, so a
//! script can rely on them. The commands that wait for an outcome
//! (`connect --background`, `wait`) end with one of the codes in
//! [`exit_code`], decided by [`wait_verdict`].

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::runtime::StatusFile;
use crate::session::{CodeReason, FailureKind};
use crate::snapshot::Phase;

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
    /// The time given with `--timeout` ran out.
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
    /// The session waits for a code; give it one with `ovpn-otp code`.
    pub needs_code: bool,
    /// Why a code is needed: `initial`, `reconnect`, `rejected`, `expired` or `retry`.
    pub code_reason: Option<CodeReason>,
    /// Why the last try failed: `auth_failed`, `server_reset`,
    /// `cipher_mismatch`, `unreachable`, `dropped` or `failed`. `null` once
    /// the session is connected.
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
            pid: None,
            updated: None,
        }
    }

    /// Build the report from the status file of a session, if there is one.
    pub fn from_status(status: Option<&StatusFile>) -> StatusReport {
        let Some(st) = status else {
            return StatusReport::idle();
        };
        let s = &st.snapshot;
        let running = st.is_live();
        let mut report = StatusReport {
            running,
            phase: s.phase,
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
            name: Some(st.name.clone()),
            settings: Some(st.settings.clone()),
            pid: Some(st.pid),
            updated: Some(st.updated),
        };
        if !running && s.phase.is_active() {
            // The program that ran the session is gone and never wrote how it ended.
            report.phase = Phase::Failed;
            report.failure_reason = Some(FailureKind::Failed);
            report.last_error = Some(format!(
                "The session ended without cleaning up (process {} is gone).",
                st.pid
            ));
            report.since = Some(st.updated);
        }
        report
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
            updated: Local::now(),
            running,
            snapshot,
        }
    }

    fn report(running: bool, edit: impl FnOnce(&mut Snapshot)) -> StatusReport {
        StatusReport::from_status(Some(&status(running, edit)))
    }

    #[test]
    fn every_field_is_present_even_before_any_session() {
        let v: serde_json::Value = serde_json::from_str(&StatusReport::idle().to_json()).unwrap();
        for field in [
            "running",
            "phase",
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
        let r = StatusReport::from_status(Some(&st));
        assert!(!r.running);
        assert_eq!(r.phase, Phase::Failed);
        assert_eq!(r.failure_reason, Some(FailureKind::Failed));
        assert!(r.last_error.unwrap().contains("without cleaning up"));
        assert_eq!(r.connected_since, None);
    }
}
