//! Session tests against a fake OpenVPN management interface.
//!
//! The fake speaks enough of the management protocol to walk a session
//! through password check, hold, login, connect, drops and exits, so the auth
//! and reconnect logic can be tested without a real OpenVPN.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ovpn_otp_core::credentials::{Login, Secret};
use ovpn_otp_core::launch::{LaunchError, LaunchRequest, Launched, Launcher, VpnProcess};
use ovpn_otp_core::session::{
    self, CodeReason, Direction, EndReason, Event, SessionHandle, SessionOptions,
};
use ovpn_otp_core::settings::{KeepAlive, ReachCheck};
use ovpn_otp_core::snapshot::{Phase, Snapshot};

const MGMT_PW: &str = "fake-management-pw";

#[derive(Clone, Default)]
struct Shared {
    /// Lines the fake received from the session.
    received: Arc<Mutex<Vec<String>>>,
    /// Writer for the current management connection.
    writer: Arc<Mutex<Option<TcpStream>>>,
    /// Exit flag of the current fake process.
    exited: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    launches: Arc<AtomicU32>,
    hold_releases: Arc<Mutex<Vec<Instant>>>,
}

#[derive(Clone)]
struct Fake {
    shared: Shared,
    /// The password+code (or SCRV1 string) the fake accepts.
    accept: Arc<Mutex<String>>,
    static_challenge: bool,
    fail_launch: bool,
}

impl Fake {
    fn new(accept: &str) -> Fake {
        Fake {
            shared: Shared::default(),
            accept: Arc::new(Mutex::new(accept.to_string())),
            static_challenge: false,
            fail_launch: false,
        }
    }

    fn send(&self, line: &str) {
        if let Some(w) = self.shared.writer.lock().unwrap().as_mut() {
            let _ = w.write_all(format!("{line}\n").as_bytes());
        }
    }

    /// The link went quiet: OpenVPN restarts in-process and waits at hold.
    fn drop_link(&self) {
        self.send(">STATE:1700000100,RECONNECTING,ping-restart,,,,,");
        self.send(">HOLD:Waiting for hold release:5");
    }

    /// The OpenVPN process dies.
    fn crash(&self) {
        if let Some(e) = self.shared.exited.lock().unwrap().as_ref() {
            e.store(true, Ordering::SeqCst);
        }
        if let Some(w) = self.shared.writer.lock().unwrap().take() {
            let _ = w.shutdown(std::net::Shutdown::Both);
        }
    }

    fn received(&self) -> Vec<String> {
        self.shared.received.lock().unwrap().clone()
    }
}

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

impl Launcher for Fake {
    fn launch(&self, _req: &LaunchRequest) -> Result<Launched, LaunchError> {
        if self.fail_launch {
            return Err(LaunchError::NotFound("no openvpn here".into()));
        }
        self.shared.launches.fetch_add(1, Ordering::SeqCst);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let exited = Arc::new(AtomicBool::new(false));
        *self.shared.exited.lock().unwrap() = Some(exited.clone());
        let fake = self.clone();
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

/// Undo management quoting: `"a\"b"` -> `a"b`.
fn unquote(s: &str) -> String {
    let s = s.trim();
    let inner = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s);
    let mut out = String::new();
    let mut esc = false;
    for c in inner.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    out
}

impl Fake {
    fn serve(&self, stream: TcpStream, exited: Arc<AtomicBool>) {
        let mut w = stream.try_clone().unwrap();
        *self.shared.writer.lock().unwrap() = Some(stream.try_clone().unwrap());
        let mut reader = BufReader::new(stream);
        let out = |w: &mut TcpStream, s: &str| {
            let _ = w.write_all(s.as_bytes());
        };
        out(&mut w, "ENTER PASSWORD:");
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim() != MGMT_PW {
            out(&mut w, "ERROR: bad password\n");
            return;
        }
        out(&mut w, "SUCCESS: password is correct\n");
        out(
            &mut w,
            ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n",
        );
        out(&mut w, ">HOLD:Waiting for hold release:0\n");
        let sc = self.static_challenge;
        let need = if sc {
            ">PASSWORD:Need 'Auth' username/password SC:1,Enter code\n"
        } else {
            ">PASSWORD:Need 'Auth' username/password\n"
        };
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let cmd = line.trim_end().to_string();
            self.shared.received.lock().unwrap().push(cmd.clone());
            if cmd == "log on all" {
                out(
                    &mut w,
                    "1700000000,I,OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZ4]\n",
                );
                out(
                    &mut w,
                    "1700000000,W,WARNING: a history warning, with commas\n",
                );
                out(
                    &mut w,
                    "END\nSUCCESS: real-time log notification set to ON\n",
                );
            } else if cmd == "state on all" {
                out(&mut w, "1700000000,CONNECTING,,,,,,\nEND\nSUCCESS: real-time state notification set to ON\n");
            } else if cmd == "bytecount 1" {
                out(&mut w, "SUCCESS: bytecount interval changed\n");
            } else if cmd == "hold release" {
                self.shared
                    .hold_releases
                    .lock()
                    .unwrap()
                    .push(Instant::now());
                out(&mut w, "SUCCESS: hold release succeeded\n");
                out(
                    &mut w,
                    ">STATE:1700000001,WAIT,,,,,,\n>STATE:1700000002,AUTH,,,,,,\n",
                );
                out(&mut w, need);
            } else if cmd.starts_with("username ") {
                out(
                    &mut w,
                    "SUCCESS: 'Auth' username entered, but not yet verified\n",
                );
            } else if let Some(rest) = cmd.strip_prefix("password \"Auth\" ") {
                out(
                    &mut w,
                    "SUCCESS: 'Auth' password entered, but not yet verified\n",
                );
                if unquote(rest) == *self.accept.lock().unwrap() {
                    out(&mut w, ">LOG:1700000003,I,PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,dhcp-option DNS 10.20.0.53,ifconfig 10.8.0.6 255.255.255.0'\n");
                    out(&mut w, ">STATE:1700000003,GET_CONFIG,,,,,,\n>STATE:1700000004,ASSIGN_IP,,10.8.0.6,,,,\n>STATE:1700000004,ADD_ROUTES,,,,,,\n");
                    out(
                        &mut w,
                        ">STATE:1700000005,CONNECTED,SUCCESS,10.8.0.6,198.51.100.7,8443,,\n",
                    );
                    out(&mut w, ">BYTECOUNT:1000,500\n>BYTECOUNT:5000,900\n");
                } else {
                    out(&mut w, ">PASSWORD:Verification Failed: 'Auth'\n");
                    out(&mut w, ">STATE:1700000006,RECONNECTING,auth-failure,,,,,\n");
                    out(&mut w, ">HOLD:Waiting for hold release:5\n");
                }
            } else if cmd == "signal SIGTERM" {
                out(
                    &mut w,
                    "SUCCESS: signal SIGTERM thrown\n>STATE:1700000009,EXITING,SIGTERM,,,,,\n",
                );
                exited.store(true, Ordering::SeqCst);
                let _ = w.shutdown(std::net::Shutdown::Both);
                break;
            } else {
                out(&mut w, "ERROR: unknown command\n");
            }
        }
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

fn password_lines(fake: &Fake) -> Vec<String> {
    fake.received()
        .into_iter()
        .filter(|l| l.starts_with("password "))
        .collect()
}

#[test]
fn connects_with_code_appended_to_password() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(Some("123456"), "pw"), Box::new(fake.clone()));
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
        password_lines(&fake),
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
    let h = session::start(options(None, "pw"), Box::new(fake.clone()));
    let mut seen = Vec::new();
    let ev = wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Initial));
    assert!(password_lines(&fake).is_empty());
    h.send_code("654 321");
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        password_lines(&fake),
        vec!["password \"Auth\" \"pw654321\""]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn rejected_login_asks_for_a_new_code() {
    let fake = Fake::new("pw111111");
    let h = session::start(options(Some("999999"), "pw"), Box::new(fake.clone()));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "auth failed", |e| {
        matches!(e, Event::AuthFailed { .. })
    });
    let ev = wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    assert_eq!(need_code(&ev), Some(CodeReason::Rejected));
    h.send_code("111111");
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        password_lines(&fake),
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
    let h = session::start(options(Some("123456"), "pw"), Box::new(fake.clone()));
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
    assert_eq!(password_lines(&fake).len(), 2);
    assert_eq!(fake.shared.launches.load(Ordering::SeqCst), 1);
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn process_exit_after_connect_relaunches_openvpn() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(Some("123456"), "pw"), Box::new(fake.clone()));
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
    let h = session::start(opts, Box::new(fake.clone()));
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
    let h = session::start(opts, Box::new(fake.clone()));
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
    let h = session::start(options(Some("123456"), "pw"), Box::new(fake.clone()));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        password_lines(&fake),
        vec!["password \"Auth\" \"SCRV1:cHc=:MTIzNDU2\""]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn passwords_with_quotes_are_escaped() {
    let fake = Fake::new("p\"w\\x123456");
    let h = session::start(options(Some("123456"), "p\"w\\x"), Box::new(fake.clone()));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    assert_eq!(
        password_lines(&fake),
        vec![r#"password "Auth" "p\"w\\x123456""#]
    );
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}

#[test]
fn launch_failure_ends_with_failed() {
    let mut fake = Fake::new("x");
    fake.fail_launch = true;
    let h = session::start(options(Some("123456"), "pw"), Box::new(fake));
    let mut seen = Vec::new();
    let end = wait_for(&h, &mut seen, "end", is_ended);
    assert!(
        matches!(end, Event::Ended { reason: EndReason::Failed(m) } if m.contains("no openvpn here"))
    );
}

#[test]
fn bad_codes_are_refused_before_sending() {
    let fake = Fake::new("pw123456");
    let h = session::start(options(None, "pw"), Box::new(fake.clone()));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "need code", |e| need_code(e).is_some());
    h.send_code("12ab");
    wait_for(
        &h,
        &mut seen,
        "warning",
        |e| matches!(e, Event::Note { text, .. } if text.contains("digits")),
    );
    assert!(password_lines(&fake).is_empty());
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
    let h = session::start(opts, Box::new(fake));
    let mut seen = Vec::new();
    wait_for(&h, &mut seen, "CONNECTED", is_connected);
    let ev = wait_for(&h, &mut seen, "reach", |e| matches!(e, Event::Reach(_)));
    let Event::Reach(r) = ev else { unreachable!() };
    assert!(r.ok, "{r:?}");
    h.disconnect();
    wait_for(&h, &mut seen, "end", is_ended);
}
