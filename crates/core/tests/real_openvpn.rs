//! End-to-end test against a real OpenVPN server.
//!
//! Run through `tests/integration/run.sh`, which creates the servers, the
//! certificates and a private network namespace, then runs these tests with
//! `--ignored`. They prove connect, state, byte counts, a drop with reconnect
//! (and a fresh code), a rejected code, and disconnect; a server that only
//! accepts an old cipher; and a server that closes the connection during login.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ovpn_otp_core::connect;
use ovpn_otp_core::credentials::{Login, Secret};
use ovpn_otp_core::runtime::RuntimeDir;
use ovpn_otp_core::session::{CodeReason, EndReason, Event, FailureKind, SessionHandle};
use ovpn_otp_core::settings;
use ovpn_otp_core::snapshot::{Phase, Snapshot};

const CODE: &str = "246810";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} not set; run tests/integration/run.sh"))
}

struct Watch<'a> {
    h: &'a SessionHandle,
    snap: Snapshot,
    seen: Vec<Event>,
}

impl Watch<'_> {
    fn until(&mut self, what: &str, done: impl Fn(&Event, &Snapshot) -> bool) -> Event {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.h.events().recv_timeout(left) {
                Ok(ev) => {
                    self.snap.apply(&ev);
                    match &ev {
                        Event::Wire { .. } | Event::Bytes { .. } => {}
                        other => eprintln!("event: {other:?}"),
                    }
                    self.seen.push(ev.clone());
                    if done(&ev, &self.snap) {
                        return ev;
                    }
                }
                Err(_) => panic!("timed out waiting for {what}"),
            }
        }
    }
}

fn connected(e: &Event, _: &Snapshot) -> bool {
    matches!(e, Event::State { info, .. } if info.name == "CONNECTED")
}

/// Ask the server's management interface to kick the client off.
fn kick_client(mgmt_port: &str) {
    let mut s = TcpStream::connect(format!("127.0.0.1:{mgmt_port}")).unwrap();
    s.write_all(b"kill tester\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut line = String::new();
    // Skip the banner, wait for the kill reply.
    for _ in 0..10 {
        line.clear();
        if r.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        eprintln!("server mgmt: {}", line.trim_end());
        if line.starts_with("SUCCESS") || line.starts_with("ERROR") {
            break;
        }
    }
    let _ = s.write_all(b"quit\n");
}

#[test]
#[ignore = "needs a real OpenVPN server; run tests/integration/run.sh"]
fn real_server_connect_drop_reconnect_disconnect() {
    let dir = PathBuf::from(env("OVPN_OTP_IT_DIR"));
    let openvpn = env("OVPN_OTP_IT_OPENVPN");
    let server_mgmt = env("OVPN_OTP_IT_SERVER_MGMT");

    // Something to reach through the tunnel: listen on all addresses and
    // check it at the server's tunnel address.
    let target = TcpListener::bind("0.0.0.0:0").unwrap();
    let target_port = target.local_addr().unwrap().port();

    let settings_path = dir.join("lib-settings.toml");
    std::fs::write(
        &settings_path,
        format!(
            r#"name = "it"
[profile]
path = "client.ovpn"
[keepalive]
ping = 2
ping_restart = 8
backoff_initial = 1
backoff_max = 2
[check]
host = "10.89.0.1:{target_port}"
interval = 2
[openvpn.linux]
path = "{openvpn}"
command_prefix = []
"#
        ),
    )
    .unwrap();
    let loaded = settings::load(&settings_path).unwrap();
    let runtime = RuntimeDir::at(dir.join("lib-run")).unwrap();
    let login = Login {
        username: "tester".into(),
        password: Secret::new("letmein"),
    };
    let prepared = connect::prepare(&loaded, &runtime, login, Some(CODE.into())).unwrap();
    let prepared_text = std::fs::read_to_string(&prepared.config_path).unwrap();
    assert!(prepared_text.contains("auth-nocache"));
    assert!(prepared_text.contains("ping-restart 8"));
    let (h, config_path) = prepared.start();
    let mut w = Watch {
        h: &h,
        snap: Snapshot::default(),
        seen: Vec::new(),
    };

    // 1. Connect.
    w.until("first CONNECTED", connected);
    assert_eq!(w.snap.phase, Phase::Connected);
    assert!(
        w.snap.local_ip.starts_with("10.89.0."),
        "ip {}",
        w.snap.local_ip
    );
    assert_eq!(w.snap.server, "127.0.0.1:11940");
    assert!(
        w.snap.routes.contains(&"10.90.0.0/24".to_string()),
        "routes {:?}",
        w.snap.routes
    );
    assert!(w.snap.dns.contains(&"10.89.0.53".to_string()));
    assert!(w.snap.openvpn_version.starts_with("OpenVPN 2."));
    // GET_CONFIG is not reported by every OpenVPN version.
    for s in ["WAIT", "AUTH", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED"] {
        assert!(
            w.snap.timeline.iter().any(|t| t.state == s),
            "timeline misses {s}"
        );
    }

    // 2. Byte counts arrive and grow.
    w.until(
        "bytes",
        |e, _| matches!(e, Event::Bytes { bytes_in, .. } if *bytes_in > 0),
    );
    // 3. The reachability check works through the tunnel address.
    let ev = w.until("reach", |e, _| matches!(e, Event::Reach(_)));
    let Event::Reach(r) = ev else { unreachable!() };
    assert!(r.ok, "reach failed: {r:?}");

    // 4. The server drops us: the session reconnects and wants a fresh code.
    kick_client(&server_mgmt);
    w.until("reconnecting", |e, _| {
        matches!(e, Event::Reconnecting { .. })
    });
    let ev = w.until("need code", |e, _| matches!(e, Event::NeedCode { .. }));
    assert!(
        matches!(
            ev,
            Event::NeedCode {
                reason: CodeReason::Reconnect
            }
        ),
        "{ev:?}"
    );

    // 5. A wrong code is rejected and the session asks again.
    h.send_code("000000");
    w.until("auth failed", |e, _| matches!(e, Event::AuthFailed { .. }));
    let ev = w.until("need code again", |e, _| {
        matches!(e, Event::NeedCode { .. })
    });
    assert!(
        matches!(
            ev,
            Event::NeedCode {
                reason: CodeReason::Rejected
            }
        ),
        "{ev:?}"
    );

    // 6. The right code reconnects.
    h.send_code(CODE);
    w.until("second CONNECTED", connected);
    assert_eq!(w.snap.phase, Phase::Connected);

    // 7. Disconnect.
    h.disconnect();
    let end = w.until("end", |e, _| matches!(e, Event::Ended { .. }));
    assert!(
        matches!(
            end,
            Event::Ended {
                reason: EndReason::Disconnected
            }
        ),
        "{end:?}"
    );
    let seen = std::mem::take(&mut w.seen);
    drop(w);
    h.join();
    let _ = std::fs::remove_file(config_path);

    // The password never appears in anything the session emitted.
    for e in &seen {
        let text = format!("{e:?}");
        assert!(!text.contains("letmein"), "password leaked: {text}");
    }
}

/// Start a session for `profile` (a file `run.sh` wrote), with `extra`
/// settings lines, the way a script does: a rejected login ends it.
fn start_session(name: &str, profile: &str, extra: &str) -> (SessionHandle, PathBuf) {
    let dir = PathBuf::from(env("OVPN_OTP_IT_DIR"));
    let openvpn = env("OVPN_OTP_IT_OPENVPN");
    let settings_path = dir.join(format!("{name}-settings.toml"));
    std::fs::write(
        &settings_path,
        format!(
            r#"name = "{name}"
[profile]
path = "{profile}"
[keepalive]
ping = 2
ping_restart = 8
backoff_initial = 1
backoff_max = 2
[openvpn]
{extra}
[openvpn.linux]
path = "{openvpn}"
command_prefix = []
"#
        ),
    )
    .unwrap();
    let loaded = settings::load(&settings_path).unwrap();
    let runtime = RuntimeDir::at(dir.join(format!("{name}-run"))).unwrap();
    let login = Login {
        username: "tester".into(),
        password: Secret::new("letmein"),
    };
    let mut prepared = connect::prepare(&loaded, &runtime, login, Some(CODE.into())).unwrap();
    prepared.options.retry_login = false;
    prepared.start()
}

fn asked_for_a_code(seen: &[Event]) -> bool {
    seen.iter().any(|e| matches!(e, Event::NeedCode { .. }))
}

fn log_has(seen: &[Event], text: &str) -> bool {
    seen.iter()
        .any(|e| matches!(e, Event::Log(l) if l.message.contains(text)))
}

/// Watch a session until it ends as failed, and give back the failure.
fn failed_end(w: &mut Watch) -> ovpn_otp_core::session::Failure {
    let end = w.until("the end of the session", |e, _| {
        matches!(e, Event::Ended { .. })
    });
    match end {
        Event::Ended {
            reason: EndReason::Failed(failure),
        } => failure,
        other => panic!("the session did not fail: {other:?}"),
    }
}

/// A server that only accepts AES-128-CBC, like an older firewall, and a
/// profile that names that cipher the old way (`cipher AES-128-CBC`).
#[test]
#[ignore = "needs a real OpenVPN server; run tests/integration/run.sh"]
fn cbc_only_server_needs_the_cipher_lines_ovpn_otp_adds() {
    // Without the added lines (here taken away again through extra_options),
    // OpenVPN offers only its own ciphers and the server refuses the client
    // right after the TLS handshake. That is the failure being fixed.
    let (h, config_path) = start_session(
        "it-cbc-unfixed",
        "client-cbc.ovpn",
        r#"extra_options = ["--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"]"#,
    );
    let text = std::fs::read_to_string(&config_path).unwrap();
    assert!(!text.contains("data-ciphers-fallback"), "{text}");
    let mut w = Watch {
        h: &h,
        snap: Snapshot::default(),
        seen: Vec::new(),
    };
    let failure = failed_end(&mut w);
    assert_eq!(failure.kind, FailureKind::CipherMismatch, "{failure:?}");
    assert!(failure.message.contains("no shared cipher"), "{failure:?}");
    assert!(
        log_has(&w.seen, "VERIFY OK"),
        "the TLS handshake did not happen"
    );
    assert!(!asked_for_a_code(&w.seen), "asked for another code");
    assert_eq!(w.snap.phase, Phase::Failed);
    drop(w);
    h.join();
    let _ = std::fs::remove_file(config_path);

    // With the profile as exported and no extra settings, it connects, and
    // the data channel uses the cipher the profile names.
    let (h, config_path) = start_session("it-cbc", "client-cbc.ovpn", "");
    let text = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        text.contains(
            "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC\n\
             data-ciphers-fallback AES-128-CBC\n"
        ),
        "{text}"
    );
    assert!(!text.contains("disable-dco"), "{text}");
    let mut w = Watch {
        h: &h,
        snap: Snapshot::default(),
        seen: Vec::new(),
    };
    w.until("CONNECTED to the CBC-only server", connected);
    assert_eq!(w.snap.phase, Phase::Connected);
    assert_eq!(w.snap.failure, None);
    assert!(
        w.snap.local_ip.starts_with("10.91.0."),
        "ip {}",
        w.snap.local_ip
    );
    // OpenVPN names the cipher of the data channel in its log, around the
    // time it reports CONNECTED.
    let names_cipher =
        |m: &str| m.contains("Cipher 'AES-128-CBC'") || m.contains("cipher 'AES-128-CBC'");
    if !w.snap.logs.iter().any(|l| names_cipher(&l.message)) {
        w.until(
            "AES-128-CBC on the data channel",
            |e, _| matches!(e, Event::Log(l) if names_cipher(&l.message)),
        );
    }
    assert!(
        !log_has(&w.seen, "DEPRECATED OPTION: --cipher"),
        "OpenVPN still warns about the cipher line"
    );
    assert!(w.seen.iter().any(
        |e| matches!(e, Event::Note { text, .. } if text.contains("data-ciphers-fallback AES-128-CBC"))
    ));
    h.disconnect();
    w.until("end", |e, _| matches!(e, Event::Ended { .. }));
    drop(w);
    h.join();
    let _ = std::fs::remove_file(config_path);
}

/// The server closes the connection during login and says nothing: OpenVPN
/// reports "Connection reset, restarting" right after the TLS handshake. The
/// session must end with that reason instead of asking for another code.
#[test]
#[ignore = "needs a real OpenVPN server; run tests/integration/run.sh"]
fn connection_reset_during_login_ends_with_server_reset() {
    let (h, config_path) = start_session("it-reset", "client-reset.ovpn", "");
    let mut w = Watch {
        h: &h,
        snap: Snapshot::default(),
        seen: Vec::new(),
    };
    let failure = failed_end(&mut w);
    assert_eq!(failure.kind, FailureKind::ServerReset, "{failure:?}");
    for cause in [
        "127.0.0.1:11944",
        "code was wrong",
        "password is wrong",
        "cipher mismatch",
    ] {
        assert!(
            failure.message.contains(cause),
            "`{cause}` not in {failure:?}"
        );
    }
    assert!(
        log_has(&w.seen, "VERIFY OK"),
        "the TLS handshake did not happen"
    );
    assert!(log_has(&w.seen, "Connection reset, restarting"));
    assert!(!asked_for_a_code(&w.seen), "asked for another code");
    assert_eq!(w.snap.phase, Phase::Failed);
    assert_eq!(w.snap.failure, Some(FailureKind::ServerReset));
    for e in &w.seen {
        let text = format!("{e:?}");
        assert!(!text.contains("letmein"), "password leaked: {text}");
    }
    drop(w);
    h.join();
    let _ = std::fs::remove_file(config_path);
}
