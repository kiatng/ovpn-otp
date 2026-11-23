//! Session tests against a fake OpenVPN management interface.
//!
//! The fake (in the `ovpn-otp-testkit` crate) speaks enough of the management
//! protocol to walk a session through password check, hold, login, connect,
//! drops and exits, so the login, failure and reconnect logic can be tested
//! without a real OpenVPN.

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ovpn_otp_core::credentials::{Login, Secret};
use ovpn_otp_core::launch::{LaunchError, LaunchRequest, Launched, Launcher, VpnProcess};
use ovpn_otp_core::session::{
    self, CodeReason, Direction, EndReason, Event, FailureKind, SessionHandle, SessionOptions,
};
use ovpn_otp_core::settings::{KeepAlive, ReachCheck};
use ovpn_otp_core::snapshot::{Phase, Snapshot};
use ovpn_otp_testkit::{Fake, Outcome, MGMT_PW};

struct FakeProcess {
    exited: Arc<AtomicBool>,
}

impl VpnProcess for FakeProcess {
    fn try_wait(&mut self) -> Option<Option<i32>> {
        self.exited.load(Ordering::SeqCst).then_some(Some(0))
    }
    fn kill(&mut self) {
        self.exited.store(true, Ordering::SeqCst);
    }
    fn output_tail(&self) -> Vec<String> {
        vec!["fake openvpn output".into()]
    }
}

/// Starts the fake in this process instead of an `openvpn` program.
struct FakeLauncher {
    fake: Fake,
    fail_launch: bool,
}

fn launcher(fake: &Fake) -> Box<dyn Launcher> {
    Box::new(FakeLauncher {
        fake: fake.clone(),
        fail_launch: false,
    })
}

impl Launcher for FakeLauncher {
    fn launch(&self, _req: &LaunchRequest) -> Result<Launched, LaunchError> {
        if self.fail_launch {
            return Err(LaunchError::NotFound("no openvpn here".into()));
        }
        let shared = &self.fake.shared;
        shared.launches.fetch_add(1, Ordering::SeqCst);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let exited = Arc::new(AtomicBool::new(false));
        *shared.exited.lock().unwrap() = Some(exited.clone());
        let fake = self.fake.clone();
        let ex = exited.clone();
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                fake.serve(stream, ex);
            }
        });
        Ok(Launched {
            process: Box::new(FakeProcess { exited }),
            mgmt_addr: addr,
            mgmt_password: Secret::new(MGMT_PW),
            description: "fake openvpn".into(),
        })
    }
}

fn options(code: Option<&str>, password: &str) -> SessionOptions {
    SessionOptions {
        login: Login {
            username: "alice".into(),
            password: Secret::new(password),
        },
        code: code.map(str::to_string),
        code_digits: 6,
        keepalive: KeepAlive {
            ping: 10,
            ping_restart: 60,
            auto_reconnect: true,
            backoff_initial: 1,
            backoff_max: 2,
        },
        reach: ReachCheck::default(),
        launch: LaunchRequest {
            config: "unused.ovpn".into(),
            work_dir: ".".into(),
            private_dir: std::env::temp_dir(),
            verb: 3,
        },
        retry_login: true,
        remotes: vec![ovpn_otp_testkit::SERVER.into()],
        remote_count: 1,
        notes: Vec::new(),
        connect_timeout: Duration::from_secs(60),
    }
}

/// Collect events until `done` returns true for one, or panic after a timeout.
fn wait_for(
    h: &SessionHandle,
    seen: &mut Vec<Event>,
    what: &str,
    done: impl Fn(&Event) -> bool,
) -> Event {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match h.events().recv_timeout(left) {
            Ok(ev) => {
                seen.push(ev.clone());
                if done(&ev) {
                    return ev;
                }
            }
            Err(_) => panic!(
                "timed out waiting for {what}; events so far:\n{:#?}",
                seen.iter()
                    .filter(|e| !matches!(e, Event::Wire { .. }))
                    .collect::<Vec<_>>()
            ),
        }
    }
}

fn is_connected(e: &Event) -> bool {
    matches!(e, Event::State { info, .. } if info.name == "CONNECTED")
}

fn is_ended(e: &Event) -> bool {
    matches!(e, Event::Ended { .. })
}

fn need_code(e: &Event) -> Option<CodeReason> {
    match e {
        Event::NeedCode { reason } => Some(*reason),
        _ => None,
    }
}

#[test]
fn connects_with_code_appended_to_password() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    wait_for(&h, &mut seen, "bytes", |e| {
        matches!(e, Event::Bytes { bytes_in: 5000, .. })
    });

    let got = fake.received();
    assert!(got.contains(&"log on all".to_string()));
    assert!(got.contains(&"state on all".to_string()));
    assert!(got.contains(&"bytecount 1".to_string()));
    assert!(got.contains(&"hold release".to_string()));
    assert!(got.contains(&"username \"Auth\" \"alice\"".to_string()));
    assert_eq!(
        fake.password_lines(),
        vec!["password \"Auth\" \"pw123456\""]
    );

    // The transcript never shows the password or the combined string.
    for e in &seen {
        if let Event::Wire { text, .. } = e {
            assert!(!text.contains("pw123456"), "secret leaked: {text}");
            assert!(
                !text.contains(MGMT_PW),
                "management password leaked: {text}"
            );
        }
    }
    assert!(seen.iter().any(
        |e| matches!(e, Event::Wire { dir: Direction::Out, text, .. } if text.contains("hidden"))
    ));

    h.disconnect();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(matches!(
        end,
        Event::Ended {
            reason: EndReason::Disconnected
        }
    ));
    assert!(fake.received().contains(&"signal SIGTERM".to_string()));

    // Fold everything into a snapshot, as the GUI and CLI do.
    let mut snap = Snapshot::default();
    for e in &seen {
        snap.apply(e);
    }
    assert_eq!(snap.phase, Phase::Disconnected);
    assert_eq!(snap.local_ip, "10.8.0.6");
    assert_eq!(snap.server, "198.51.100.7:8443");
    assert_eq!(snap.routes, vec!["10.20.0.0/16"]);
    assert_eq!(snap.dns, vec!["10.20.0.53"]);
    assert_eq!(snap.bytes_in, 5000);
    assert!(snap.openvpn_version.starts_with("OpenVPN 2.6.12"));
    let states: Vec<&str> = snap.timeline.iter().map(|t| t.state.as_str()).collect();
    for s in [
        "CONNECTING",
        "WAIT",
        "AUTH",
        "GET_CONFIG",
        "ASSIGN_IP",
        "ADD_ROUTES",
        "CONNECTED",
        "EXITING",
    ] {
        assert!(states.contains(&s), "timeline misses {s}: {states:?}");
    }
    assert!(snap
        .logs
        .iter()
        .any(|l| l.message.contains("history warning, with commas")));
}

#[test]
fn asks_for_code_when_none_given() {
    let fake = Fake::new("pw654321");
    let h = session::start(options(None, "pw"), launcher(&fake));
    let mut seen = Vec::new();
    let ev = wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Initial));
    assert!(fake.password_lines().is_empty());
    h.send_code("654 321");
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        fake.password_lines(),
        vec!["password \"Auth\" \"pw654321\""]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn rejected_login_asks_for_a_new_code() {
    let fake = Fake::new("pw111111");
    let h = session::start(options(Some("999999"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "auth failed", |e| {
        matches!(e, Event::AuthFailed { .. })
    });
    let ev = wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Rejected));
    h.send_code("111111");
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        fake.password_lines(),
        vec![
            "password \"Auth\" \"pw999999\"",
            "password \"Auth\" \"pw111111\""
        ]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn link_drop_waits_backoff_and_asks_for_fresh_code() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);

    let dropped_at = Instant::now();
    fake.drop_link();
    let ev = wait_for(&h, &mut seen, "reconnecting", |e| {
        matches!(e, Event::Reconnecting { .. })
    });
    let Event::Reconnecting {
        attempt, reason, ..
    } = ev
    else {
        unreachable!()
    };
    assert_eq!(attempt, 1);
    assert_eq!(reason, "ping-restart");

    // The old code is not reused: the session asks for a new one.
    let ev = wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Reconnect));
    let releases = fake.shared.hold_releases.lock().unwrap().clone();
    assert_eq!(releases.len(), 2);
    assert!(
        releases[1].duration_since(dropped_at) >= Duration::from_millis(900),
        "hold released before the backoff"
    );

    h.send_code("123456");
    wait_for(&h, &mut seen, "CONNECTED again", is_connected);
    assert_eq!(fake.password_lines().len(), 2);
    assert_eq!(fake.shared.launches.load(Ordering::SeqCst), 1);
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn process_exit_after_connect_relaunches_openvpn() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    fake.crash();
    wait_for(&h, &mut seen, "reconnecting", |e| {
        matches!(e, Event::Reconnecting { .. })
    });
    // A code typed during the backoff is used for the next login.
    h.send_code("123456");
    wait_for(&h, &mut seen, "CONNECTED again", is_connected);
    assert_eq!(fake.shared.launches.load(Ordering::SeqCst), 2);
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn process_exit_without_auto_reconnect_ends_the_session() {
    let fake = Fake::new("pw123456");
    let mut opts = options(Some("123456"), "pw");
    opts.keepalive.auto_reconnect = false;
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    fake.crash();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(matches!(
        end,
        Event::Ended {
            reason: EndReason::Dropped(_)
        }
    ));
}

#[test]
fn link_drop_without_auto_reconnect_ends_as_dropped() {
    let fake = Fake::new("pw123456");
    let mut opts = options(Some("123456"), "pw");
    opts.keepalive.auto_reconnect = false;
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    fake.drop_link();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(matches!(
        end,
        Event::Ended {
            reason: EndReason::Dropped(_)
        }
    ));
}

#[test]
fn static_challenge_profiles_get_scrv1_password() {
    let mut fake = Fake::new("");
    fake.static_challenge = true;
    *fake.accept.lock().unwrap() = ovpn_otp_core::mgmt::static_challenge_response("pw", "123456");
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        fake.password_lines(),
        vec!["password \"Auth\" \"SCRV1:cHc=:MTIzNDU2\""]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn passwords_with_quotes_are_escaped() {
    let fake = Fake::new("p\"w\\x123456");
    let h = session::start(options(Some("123456"), "p\"w\\x"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        fake.password_lines(),
        vec![r#"password "Auth" "p\"w\\x123456""#]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn launch_failure_ends_with_failed() {
    let failing = Box::new(FakeLauncher {
        fake: Fake::new("x"),
        fail_launch: true,
    });
    let h = session::start(options(Some("123456"), "pw"), failing);
    let mut seen = Vec::new();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(
        matches!(end, Event::Ended { reason: EndReason::Failed(f) } if f.kind == FailureKind::Failed && f.message.contains("no openvpn here"))
    );
}

#[test]
fn bad_codes_are_refused_before_sending() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(None, "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    h.send_code("12ab");
    wait_for(
        &h,
        &mut seen,
        "warning",
        |e| matches!(e, Event::Note { text, .. } if text.contains("digits")),
    );
    assert!(fake.password_lines().is_empty());
    h.send_code("123456");
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn reach_check_runs_while_connected() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = target.local_addr().unwrap();
    let fake = Fake::new("pw123456");
    let mut opts = options(Some("123456"), "pw");
    opts.reach = ReachCheck {
        host: addr.to_string(),
        interval: 2,
    };
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    let ev = wait_for(&h, &mut seen, "reach", |e| matches!(e, Event::Reach(_)));
    let Event::Reach(r) = ev else { unreachable!() };
    assert!(r.ok, "{r:?}");
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

/// Wait for the session to end and give back the failure it ended with.
fn failed_end(h: &SessionHandle, seen: &mut Vec<Event>) -> session::Failure {
    match wait_for(h, seen, "end", is_ended) {
        Event::Ended {
            reason: EndReason::Failed(f),
        } => f,
        other => panic!("the session did not end as failed: {other:?}"),
    }
}

fn need_code_count(seen: &[Event]) -> usize {
    seen.iter().filter(|e| need_code(e).is_some()).count()
}

fn snapshot_of(seen: &[Event]) -> Snapshot {
    let mut snap = Snapshot::default();
    for e in seen {
        snap.apply(e);
    }
    snap
}

/// The failure this was first reported with: the secure channel is set up,
/// then the server closes the connection in the same second and says nothing.
#[test]
fn server_reset_during_first_login_ends_with_a_clear_reason() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::Reset]);
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert_eq!(failure.kind, FailureKind::ServerReset);
    for cause in [
        "closed the connection during login",
        "198.51.100.7:8443",
        "code was wrong or was already used once",
        "password is wrong",
        "cipher mismatch",
    ] {
        assert!(
            failure.message.contains(cause),
            "the message does not mention `{cause}`: {}",
            failure.message
        );
    }
    // The point of the fix: nobody is asked for a second code.
    assert_eq!(
        need_code_count(&seen),
        0,
        "asked for a code after the reset"
    );
    assert_eq!(fake.password_lines().len(), 1);
    assert_eq!(fake.shared.hold_releases.lock().unwrap().len(), 1);
    assert!(seen.iter().any(
        |e| matches!(e, Event::ConnectFailed { failure, .. } if failure.kind == FailureKind::ServerReset)
    ));
    assert!(fake.received().contains(&"signal SIGTERM".to_string()));

    let snap = snapshot_of(&seen);
    assert_eq!(snap.phase, Phase::Failed);
    assert_eq!(snap.failure, Some(FailureKind::ServerReset));
    assert_eq!(snap.last_error.as_deref(), Some(failure.message.as_str()));
    assert_eq!(snap.server, "198.51.100.7:8443");
    // The code and password are in no event.
    for e in &seen {
        let text = format!("{e:?}");
        assert!(!text.contains("pw123456"), "secret leaked: {text}");
    }
}

#[test]
fn unreachable_server_ends_as_unreachable() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::Unreachable]);
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert_eq!(failure.kind, FailureKind::Unreachable);
    assert!(
        failure
            .message
            .contains("Could not reach the VPN server at 198.51.100.7:8443"),
        "{}",
        failure.message
    );
    assert!(
        failure.message.contains("Connection timed out"),
        "the message leaves out what OpenVPN said: {}",
        failure.message
    );
    assert_eq!(need_code_count(&seen), 0);
    assert_eq!(snapshot_of(&seen).failure, Some(FailureKind::Unreachable));
}

/// With two servers in the profile, the first one not answering is not the
/// end: OpenVPN moves on, and the code goes with it because the first server
/// never saw it.
#[test]
fn unreachable_first_server_moves_on_with_the_same_code() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::Unreachable, Outcome::Login]);
    let mut opts = options(Some("123456"), "pw");
    opts.remote_count = 2;
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        fake.password_lines(),
        vec![
            "password \"Auth\" \"pw123456\"",
            "password \"Auth\" \"pw123456\""
        ]
    );
    assert_eq!(
        need_code_count(&seen),
        0,
        "asked for a code that was never used"
    );
    assert!(seen.iter().any(
        |e| matches!(e, Event::ConnectFailed { failure, .. } if failure.kind == FailureKind::Unreachable)
    ));
    // Once connected, the earlier failure is no longer the status.
    let snap = snapshot_of(&seen);
    assert_eq!(snap.phase, Phase::Connected);
    assert_eq!(snap.failure, None);
    assert_eq!(snap.last_error, None);
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn every_server_unreachable_ends_after_one_round() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::Unreachable]);
    let mut opts = options(Some("123456"), "pw");
    opts.remote_count = 2;
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert_eq!(failure.kind, FailureKind::Unreachable);
    assert_eq!(fake.password_lines().len(), 2, "each server is tried once");
}

#[test]
fn no_shared_cipher_is_not_reported_as_a_wrong_login() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::NoSharedCipher]);
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert_eq!(failure.kind, FailureKind::CipherMismatch);
    assert!(
        failure.message.contains("no encryption cipher in common")
            && failure.message.contains("no shared cipher")
            && failure.message.contains("extra_options"),
        "{}",
        failure.message
    );
    assert!(
        !seen.iter().any(|e| matches!(e, Event::AuthFailed { .. })),
        "a cipher refusal was shown as a rejected login"
    );
    assert_eq!(need_code_count(&seen), 0);
}

/// A script has nobody to ask for another code, so a rejected first login
/// ends the session instead of waiting.
#[test]
fn rejected_login_ends_the_session_when_nobody_can_be_asked() {
    let fake = Fake::new("pw111111");
    let mut opts = options(Some("999999"), "pw");
    opts.retry_login = false;
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert_eq!(failure.kind, FailureKind::AuthFailed);
    assert!(
        failure.message.contains("rejected the login"),
        "{}",
        failure.message
    );
    assert_eq!(need_code_count(&seen), 0);
    assert!(seen.iter().any(|e| matches!(e, Event::AuthFailed { .. })));
    assert_eq!(snapshot_of(&seen).failure, Some(FailureKind::AuthFailed));
}

/// After the tunnel has been up, a failed try to reconnect is said out loud
/// and the next code request says why another code is needed.
#[test]
fn reset_while_reconnecting_reports_it_and_asks_with_the_reason() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::Login, Outcome::Reset, Outcome::Login]);
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    fake.drop_link();
    let ev = wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Reconnect));

    h.send_code("123456");
    let ev = wait_for(&h, &mut seen, "the failed try", |e| {
        matches!(e, Event::ConnectFailed { .. })
    });
    assert!(
        matches!(&ev, Event::ConnectFailed { failure, .. } if failure.kind == FailureKind::ServerReset),
        "{ev:?}"
    );
    let ev = wait_for(&h, &mut seen, "need code again", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Retry));
    let snap = snapshot_of(&seen);
    assert_eq!(snap.phase, Phase::NeedCode);
    assert_eq!(snap.failure, Some(FailureKind::ServerReset));

    h.send_code("123456");
    wait_for(&h, &mut seen, "CONNECTED again", is_connected);
    assert_eq!(fake.password_lines().len(), 3);
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn profile_notes_are_logged_when_the_session_starts() {
    let fake = Fake::new("pw123456");
    let mut opts = options(Some("123456"), "pw");
    opts.notes = vec!["Added for this session: data-ciphers-fallback AES-128-CBC.".into()];
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    wait_for(
        &h,
        &mut seen,
        "the note",
        |e| matches!(e, Event::Note { text, .. } if text.contains("data-ciphers-fallback")),
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

/// The states OpenVPN can report. A log line is never one of them.
fn assert_only_real_states(seen: &[Event]) {
    for e in seen {
        if let Event::State { info, .. } = e {
            assert!(
                info.name.len() >= 4,
                "a log line was taken for the state `{}`",
                info.name
            );
        }
    }
}

/// The stall first seen with OpenVPN 2.6 on Windows, started directly.
///
/// OpenVPN on Windows looks for new commands while it is still answering one
/// (the fake does the same with `windows_reentry`). A command that arrives in
/// that moment is lost and the one being answered runs again. The session
/// used to send the user name and the password in a row: the password was
/// lost, OpenVPN waited for it for ever, and the window stayed on
/// "Connecting". Now every command waits for the answer to the one before.
#[test]
fn connects_to_an_openvpn_that_reads_while_it_answers() {
    let mut fake = Fake::new("pw123456");
    fake.windows_reentry = true;
    let h = session::start(options(Some("123456"), "pw"), launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);

    // Every command ran once, in order, and none was lost.
    assert_eq!(
        fake.received(),
        vec![
            "log on all",
            "state on all",
            "bytecount 1",
            "hold release",
            "username \"Auth\" \"alice\"",
            "password \"Auth\" \"pw123456\"",
        ]
    );
    assert_only_real_states(&seen);
    let snap = snapshot_of(&seen);
    assert_eq!(snap.phase, Phase::Connected);
    assert_eq!(snap.state, "CONNECTED");

    // A drop, a new code and the disconnect go the same careful way.
    fake.drop_link();
    wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    h.send_code("123456");
    wait_for(&h, &mut seen, "CONNECTED again", is_connected);
    assert_eq!(fake.password_lines().len(), 2);
    h.disconnect();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(matches!(
        end,
        Event::Ended {
            reason: EndReason::Disconnected
        }
    ));
    assert_eq!(
        fake.received().last().map(String::as_str),
        Some("signal SIGTERM")
    );
    assert_only_real_states(&seen);
}

/// A server that never answers used to leave the session on "Connecting"
/// for as long as OpenVPN cared to wait. Now a try without progress ends
/// after the time in the settings, with the step it was stuck in.
#[test]
fn a_try_without_progress_ends_with_a_timeout() {
    let fake = Fake::new("pw123456").with_plan(&[Outcome::Hang]);
    let mut opts = options(Some("123456"), "pw");
    opts.connect_timeout = Duration::from_secs(1);
    let started = Instant::now();
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert!(started.elapsed() < Duration::from_secs(8), "took too long");
    assert_eq!(failure.kind, FailureKind::Timeout);
    for part in [
        "Gave up connecting to 198.51.100.7:8443 after 1 seconds without progress",
        "the server did not answer",
        "connect.timeout",
    ] {
        assert!(
            failure.message.contains(part),
            "`{part}` is not in: {}",
            failure.message
        );
    }
    assert_eq!(need_code_count(&seen), 0);
    assert!(fake.received().contains(&"signal SIGTERM".to_string()));
    let snap = snapshot_of(&seen);
    assert_eq!(snap.phase, Phase::Failed);
    assert_eq!(snap.failure, Some(FailureKind::Timeout));
    assert_eq!(snap.headline(chrono::Local::now()).title, "Failed");
}

/// A server that goes quiet in the given step ends the try with a timeout
/// that names the step.
fn assert_stall_times_out(outcome: Outcome, step: &str) {
    let fake = Fake::new("pw123456").with_plan(&[outcome]);
    let mut opts = options(Some("123456"), "pw");
    opts.connect_timeout = Duration::from_secs(1);
    let started = Instant::now();
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert!(started.elapsed() < Duration::from_secs(8), "took too long");
    assert_eq!(failure.kind, FailureKind::Timeout);
    assert!(
        failure.message.contains(step),
        "`{step}` is not in: {}",
        failure.message
    );
}

#[test]
fn a_server_that_hangs_during_login_ends_with_a_timeout() {
    assert_stall_times_out(Outcome::HangInAuth, "the server did not finish the login");
}

#[test]
fn a_server_that_hangs_during_the_config_push_ends_with_a_timeout() {
    assert_stall_times_out(
        Outcome::HangInConfig,
        "the server did not send its settings",
    );
}

/// Waiting for the user to type a code is not a stuck try.
#[test]
fn waiting_for_a_code_is_not_a_timeout() {
    let fake = Fake::new("pw123456");
    let mut opts = options(None, "pw");
    opts.connect_timeout = Duration::from_secs(1);
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    std::thread::sleep(Duration::from_millis(2600));
    h.send_code("123456");
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    // Nor is a tunnel that is up and quiet.
    std::thread::sleep(Duration::from_millis(2600));
    h.disconnect();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(matches!(
        end,
        Event::Ended {
            reason: EndReason::Disconnected
        }
    ));
    assert!(!seen
        .iter()
        .any(|e| matches!(e, Event::ConnectFailed { .. })));
}

/// The captured stall itself: OpenVPN took the user name and then never
/// answered the password command. Even with the connect timeout turned off
/// the session ends, and it names the command that got no answer.
#[test]
fn an_openvpn_that_stops_answering_ends_the_session_with_the_reason() {
    let fake = Fake::new("pw123456");
    *fake.ignore.lock().unwrap() = Some("password ".into());
    let mut opts = options(Some("123456"), "pw");
    opts.connect_timeout = Duration::ZERO;
    let h = session::start(opts, launcher(&fake));
    let mut seen = Vec::new();
    let failure = failed_end(&h, &mut seen);
    assert_eq!(failure.kind, FailureKind::Timeout);
    assert!(
        failure
            .message
            .contains("OpenVPN stopped answering: no reply to `password \"Auth\" \"********\"")
            && failure.message.contains("within 10 seconds"),
        "{}",
        failure.message
    );
    assert!(!failure.message.contains("pw123456"));
    // The stop command still went out after the one that got no answer.
    assert!(fake.received().contains(&"signal SIGTERM".to_string()));
    assert_eq!(snapshot_of(&seen).failure, Some(FailureKind::Timeout));
}
