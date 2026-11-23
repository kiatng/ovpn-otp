//! A fake OpenVPN management interface, for tests only.
//!
//! The fake speaks enough of the management protocol to walk a session
//! through password check, hold, login, connect, drops and exits, and it can
//! play the ways a login goes wrong (see [`Outcome`]). The library tests use
//! it in-process; the command-line tests run it as a stand-in `openvpn`
//! program (`crates/cli/examples/fake_openvpn.rs`).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// The management password the fake expects unless told otherwise.
pub const MGMT_PW: &str = "fake-management-pw";

/// The server address the fake reports, from the range reserved for examples.
pub const SERVER: &str = "198.51.100.7:8443";

/// What the fake server does with one login.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Check the password and code: connect when right, reject when wrong.
    Login,
    /// The secure channel is set up, then the server closes the connection
    /// without a reason, as some firewalls do.
    Reset,
    /// No server answers.
    Unreachable,
    /// The server refuses because it shares no data cipher with the client.
    NoSharedCipher,
    /// Nothing happens: OpenVPN keeps waiting for the server.
    Hang,
}

#[derive(Clone, Default)]
pub struct Shared {
    /// Lines the fake received from the session.
    pub received: Arc<Mutex<Vec<String>>>,
    /// Writer for the current management connection.
    pub writer: Arc<Mutex<Option<TcpStream>>>,
    /// Exit flag of the current fake process.
    pub exited: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    pub launches: Arc<AtomicU32>,
    pub hold_releases: Arc<Mutex<Vec<Instant>>>,
}

#[derive(Clone)]
pub struct Fake {
    pub shared: Shared,
    /// The password+code (or SCRV1 string) the fake accepts.
    pub accept: Arc<Mutex<String>>,
    pub static_challenge: bool,
    /// One outcome per login, in order. The last one repeats.
    pub plan: Arc<Mutex<Vec<Outcome>>>,
    /// Logins handled so far, over every start of the fake.
    pub logins: Arc<AtomicU32>,
    pub mgmt_password: String,
}

impl Fake {
    pub fn new(accept: &str) -> Fake {
        Fake {
            shared: Shared::default(),
            accept: Arc::new(Mutex::new(accept.to_string())),
            static_challenge: false,
            plan: Arc::new(Mutex::new(vec![Outcome::Login])),
            logins: Arc::new(AtomicU32::new(0)),
            mgmt_password: MGMT_PW.to_string(),
        }
    }

    /// Set what happens to each login, in order. The last outcome repeats.
    pub fn with_plan(self, plan: &[Outcome]) -> Fake {
        assert!(!plan.is_empty(), "a plan needs at least one outcome");
        *self.plan.lock().unwrap() = plan.to_vec();
        self
    }

    /// Build a fake from text such as `accept=pw123456;plan=unreachable,login`.
    pub fn from_spec(spec: &str) -> Result<Fake, String> {
        let mut fake = Fake::new("");
        for part in spec.split(';').filter(|p| !p.trim().is_empty()) {
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| format!("`{part}` is not key=value"))?;
            match key.trim() {
                "accept" => *fake.accept.lock().unwrap() = value.to_string(),
                "plan" => {
                    let plan: Result<Vec<Outcome>, String> = value
                        .split(',')
                        .map(|o| match o.trim() {
                            "login" => Ok(Outcome::Login),
                            "reset" => Ok(Outcome::Reset),
                            "unreachable" => Ok(Outcome::Unreachable),
                            "no-shared-cipher" => Ok(Outcome::NoSharedCipher),
                            "hang" => Ok(Outcome::Hang),
                            other => Err(format!("unknown outcome `{other}`")),
                        })
                        .collect();
                    fake = fake.with_plan(&plan?);
                }
                other => return Err(format!("unknown key `{other}`")),
            }
        }
        Ok(fake)
    }

    pub fn send(&self, line: &str) {
        if let Some(w) = self.shared.writer.lock().unwrap().as_mut() {
            let _ = w.write_all(format!("{line}\n").as_bytes());
        }
    }

    /// The link went quiet: OpenVPN restarts in-process and waits at hold.
    pub fn drop_link(&self) {
        self.send(">STATE:1700000100,RECONNECTING,ping-restart,,,,,");
        self.send(">HOLD:Waiting for hold release:5");
    }

    /// The OpenVPN process dies.
    pub fn crash(&self) {
        if let Some(e) = self.shared.exited.lock().unwrap().as_ref() {
            e.store(true, Ordering::SeqCst);
        }
        if let Some(w) = self.shared.writer.lock().unwrap().take() {
            let _ = w.shutdown(std::net::Shutdown::Both);
        }
    }

    pub fn received(&self) -> Vec<String> {
        self.shared.received.lock().unwrap().clone()
    }

    /// The `password` commands the fake received.
    pub fn password_lines(&self) -> Vec<String> {
        self.received()
            .into_iter()
            .filter(|l| l.starts_with("password "))
            .collect()
    }

    fn next_outcome(&self) -> Outcome {
        let n = self.logins.fetch_add(1, Ordering::SeqCst) as usize;
        let plan = self.plan.lock().unwrap();
        plan[n.min(plan.len() - 1)]
    }

    /// Talk to one management client until it disconnects or stops the fake.
    /// `exited` is set when the fake "process" ends.
    pub fn serve(&self, stream: TcpStream, exited: Arc<AtomicBool>) {
        let mut w = stream.try_clone().unwrap();
        *self.shared.writer.lock().unwrap() = Some(stream.try_clone().unwrap());
        let mut reader = BufReader::new(stream);
        let out = |w: &mut TcpStream, s: &str| {
            let _ = w.write_all(s.as_bytes());
        };
        out(&mut w, "ENTER PASSWORD:");
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim() != self.mgmt_password {
            out(&mut w, "ERROR: bad password\n");
            return;
        }
        out(&mut w, "SUCCESS: password is correct\n");
        out(
            &mut w,
            ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n",
        );
        out(&mut w, ">HOLD:Waiting for hold release:0\n");
        let need = if self.static_challenge {
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
                // Like OpenVPN, ask for the login before connecting to the server.
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
                self.play_login(&mut w, unquote(rest));
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

    /// What OpenVPN reports while it connects and logs in with `password`.
    fn play_login(&self, w: &mut TcpStream, password: String) {
        let mut out = |s: String| {
            let _ = w.write_all(format!("{s}\n").as_bytes());
        };
        let restart = ">HOLD:Waiting for hold release:5";
        let outcome = self.next_outcome();
        out(">STATE:1700000001,TCP_CONNECT,,,,,,".into());
        if outcome == Outcome::Hang {
            return;
        }
        if outcome == Outcome::Unreachable {
            out(format!(
                ">LOG:1700000002,N,TCP: connect to [AF_INET]{SERVER} failed: Connection timed out"
            ));
            out(">LOG:1700000002,I,SIGUSR1[connection failed(soft),init_instance] received, process restarting".into());
            out(">STATE:1700000002,RECONNECTING,init_instance,,,,,".into());
            out(restart.into());
            return;
        }
        out(format!(
            ">LOG:1700000001,I,TCP connection established with [AF_INET]{SERVER}"
        ));
        out(format!(
            ">LOG:1700000001,I,TCPv4_CLIENT link remote: [AF_INET]{SERVER}"
        ));
        out(">STATE:1700000001,WAIT,,,,,,".into());
        out(">STATE:1700000002,AUTH,,,,,,".into());
        out(">LOG:1700000002,I,VERIFY OK: depth=0, CN=fake-server".into());
        match outcome {
            Outcome::Unreachable | Outcome::Hang => unreachable!("handled above"),
            Outcome::Reset => {
                out(">LOG:1700000002,N,Connection reset, restarting [0]".into());
                out(
                    ">LOG:1700000002,I,SIGUSR1[soft,connection-reset] received, process restarting"
                        .into(),
                );
                out(">STATE:1700000002,RECONNECTING,connection-reset,,,,,".into());
                out(restart.into());
            }
            Outcome::NoSharedCipher => {
                let why = "Data channel cipher negotiation failed (no shared cipher)";
                out(format!(
                    ">LOG:1700000002,I,AUTH: Received control message: AUTH_FAILED,{why}"
                ));
                out(format!(">PASSWORD:Verification Failed: 'Auth' ['{why}']"));
                out(">STATE:1700000006,RECONNECTING,auth-failure,,,,,".into());
                out(restart.into());
            }
            Outcome::Login if password == *self.accept.lock().unwrap() => {
                out(">LOG:1700000003,I,PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,dhcp-option DNS 10.20.0.53,ifconfig 10.8.0.6 255.255.255.0'".into());
                out(">STATE:1700000003,GET_CONFIG,,,,,,".into());
                out(">STATE:1700000004,ASSIGN_IP,,10.8.0.6,,,,".into());
                out(">STATE:1700000004,ADD_ROUTES,,,,,,".into());
                let (ip, port) = SERVER.split_once(':').unwrap();
                out(format!(
                    ">STATE:1700000005,CONNECTED,SUCCESS,10.8.0.6,{ip},{port},,"
                ));
                out(">BYTECOUNT:1000,500".into());
                out(">BYTECOUNT:5000,900".into());
            }
            Outcome::Login => {
                out(">PASSWORD:Verification Failed: 'Auth'".into());
                out(">STATE:1700000006,RECONNECTING,auth-failure,,,,,".into());
                out(restart.into());
            }
        }
    }
}

/// Undo management quoting: `"a\"b"` -> `a"b`.
pub fn unquote(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_fake_from_text() {
        let fake = Fake::from_spec("accept=pw123456;plan=unreachable,reset,no-shared-cipher,login")
            .unwrap();
        assert_eq!(*fake.accept.lock().unwrap(), "pw123456");
        assert_eq!(
            *fake.plan.lock().unwrap(),
            vec![
                Outcome::Unreachable,
                Outcome::Reset,
                Outcome::NoSharedCipher,
                Outcome::Login
            ]
        );
        assert!(Fake::from_spec("plan=nonsense").is_err());
        assert!(Fake::from_spec("what").is_err());
        // The last outcome repeats.
        let fake = Fake::new("x").with_plan(&[Outcome::Reset, Outcome::Login]);
        assert_eq!(fake.next_outcome(), Outcome::Reset);
        assert_eq!(fake.next_outcome(), Outcome::Login);
        assert_eq!(fake.next_outcome(), Outcome::Login);
    }

    #[test]
    fn unquotes_management_values() {
        assert_eq!(unquote(r#""a\"b\\c""#), r#"a"b\c"#);
        assert_eq!(unquote("plain"), "plain");
    }
}
