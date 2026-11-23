//! A fake OpenVPN management interface, for tests only.
//!
//! The fake speaks enough of the management protocol to walk a session
//! through password check, hold, login, connect, drops and exits, and it can
//! play the ways a login goes wrong (see [`Outcome`]). The library tests use
//! it in-process; the command-line tests run it as a stand-in `openvpn`
//! program (`crates/cli/examples/fake_openvpn.rs`).

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
    /// Read the management socket the way OpenVPN does on Windows: it looks
    /// for new commands again while it is still answering one. A command that
    /// arrives in that moment is lost, and the command being answered runs a
    /// second time. So a client must wait for each answer before it sends the
    /// next command. See `Conn::emit`.
    pub windows_reentry: bool,
    /// A command that starts with this text gets no answer at all, as from an
    /// OpenVPN that is stuck.
    pub ignore: Arc<Mutex<Option<String>>>,
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
            windows_reentry: false,
            ignore: Arc::new(Mutex::new(None)),
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
                "windows-reentry" => fake.windows_reentry = value.trim() == "1",
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
        self.send(&format!(
            ">STATE:{},RECONNECTING,ping-restart,,,,,",
            unix_now()
        ));
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
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let _ = w.write_all(b"ENTER PASSWORD:");
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim() != self.mgmt_password {
            let _ = w.write_all(b"ERROR: bad password\n");
            return;
        }
        // Whatever came with the password line already belongs to the commands.
        let early = reader.buffer().to_vec();
        let mut conn = Conn {
            fake: self,
            stream,
            w,
            line: CommandLine::default(),
            history: vec![
                "1700000000,I,OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZ4]".into(),
                "1700000000,W,WARNING: a history warning, with commas".into(),
            ],
            log_realtime: false,
            exited,
            done: false,
            depth: 0,
            fresh: false,
            later: VecDeque::new(),
        };
        conn.write("SUCCESS: password is correct");
        conn.write(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info");
        conn.write(">HOLD:Waiting for hold release:0");
        if !early.is_empty() {
            conn.take(&early);
        }
        while !conn.done && conn.read(true) {}
    }
}

/// The time the fake gives the next command to arrive before it looks at the
/// socket again in [`Conn::emit`]. A client that sends two commands in a row
/// does so within microseconds.
const REENTRY_PAUSE: Duration = Duration::from_millis(20);

/// The command buffer of OpenVPN's management interface (`struct
/// command_line` in OpenVPN's `manage.c`), with its two quirks kept: the
/// line being worked on stays in `buf`, ended by a NUL, and a line is read
/// back as a C string, which stops at the first NUL.
#[derive(Default)]
struct CommandLine {
    buf: Vec<u8>,
    residual: Vec<u8>,
}

impl CommandLine {
    /// `command_line_add`
    fn add(&mut self, data: &[u8]) {
        self.buf
            .extend(data.iter().filter(|b| **b != 0 && **b != b'\r'));
    }

    /// `command_line_get`: the next whole line, if there is one.
    fn get(&mut self) -> Option<String> {
        let nl = self.buf.iter().position(|b| *b == b'\n')?;
        self.residual = self.buf[nl + 1..].to_vec();
        self.buf.truncate(nl);
        self.buf.push(0);
        // A C string: everything up to the first NUL. When new bytes were
        // added behind a line that is still being worked on, this is that
        // old line again, and the new line behind the NUL is never seen.
        let end = self.buf.iter().position(|b| *b == 0).unwrap_or(0);
        Some(String::from_utf8_lossy(&self.buf[..end]).into_owned())
    }

    /// `command_line_next`
    fn next(&mut self) {
        self.buf = std::mem::take(&mut self.residual);
    }
}

/// One management connection of the fake.
struct Conn<'a> {
    fake: &'a Fake,
    stream: TcpStream,
    w: TcpStream,
    line: CommandLine,
    /// The log so far, as `log on all` prints it.
    history: Vec<String>,
    log_realtime: bool,
    exited: Arc<AtomicBool>,
    done: bool,
    /// How deep inside [`Conn::emit`] the current read is.
    depth: u32,
    /// No output was written yet for the command being worked on.
    fresh: bool,
    /// What OpenVPN does once it is done with the commands at hand.
    later: VecDeque<Later>,
}

/// What a command sets off after it has been answered. OpenVPN does these
/// from its main loop, not while it still holds the command.
enum Later {
    /// Ask for the login.
    NeedLogin,
    /// Connect to the server and log in with this password.
    Login(String),
}

impl Conn<'_> {
    fn write(&mut self, text: &str) {
        let _ = self
            .w
            .write_all(format!("{}\n", stamp_now(text)).as_bytes());
    }

    /// Bytes from the socket: `None` when it closed. Without `wait`, an empty
    /// answer means nothing has arrived.
    fn recv(&mut self, wait: bool) -> Option<Vec<u8>> {
        let mut buf = [0u8; 4096];
        if !wait {
            // Not with a read timeout: on Windows a read that timed out
            // leaves the socket in a state that is not defined.
            let _ = self.stream.set_nonblocking(true);
            let got = self.stream.read(&mut buf);
            let _ = self.stream.set_nonblocking(false);
            return match got {
                Ok(0) => None,
                Ok(n) => Some(buf[..n].to_vec()),
                Err(_) => Some(Vec::new()),
            };
        }
        // One command at a time, the way separate writes reach OpenVPN on a
        // loopback connection: what was written after it is still on its way.
        let n = match self.stream.peek(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        let take = buf[..n]
            .iter()
            .position(|b| *b == b'\n')
            .map_or(n, |i| i + 1);
        match self.stream.read(&mut buf[..take]) {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(buf[..n].to_vec()),
        }
    }

    /// `man_read`: take what arrived and work through the whole lines in it.
    /// Returns false when the connection is closed.
    fn read(&mut self, wait: bool) -> bool {
        match self.recv(wait) {
            None => false,
            Some(data) => {
                self.take(&data);
                true
            }
        }
    }

    fn take(&mut self, data: &[u8]) {
        self.line.add(data);
        while let Some(cmd) = self.line.get() {
            self.fresh = true;
            self.process(&cmd);
            if self.done {
                break;
            }
            self.line.next();
        }
        // Back in the main loop, with no command at hand.
        while self.depth == 0 && !self.done {
            match self.later.pop_front() {
                Some(Later::NeedLogin) => self.emit(if self.fake.static_challenge {
                    ">PASSWORD:Need 'Auth' username/password SC:1,Enter code"
                } else {
                    ">PASSWORD:Need 'Auth' username/password"
                }),
                Some(Later::Login(password)) => self.play_login(password),
                None => break,
            }
        }
    }

    /// Send one line to the client.
    ///
    /// With [`Fake::windows_reentry`] this first looks at the socket again,
    /// as OpenVPN on Windows does before every write (`management_io` handles
    /// `FD_READ` before `FD_WRITE`). If something arrived, the line that was
    /// about to be sent is thrown away (`man_read` resets the output list)
    /// and the new bytes are read while the current command is still in the
    /// command buffer.
    fn emit(&mut self, text: &str) {
        if self.fake.windows_reentry && self.depth < 5 && !self.done {
            if self.fresh {
                std::thread::sleep(REENTRY_PAUSE);
            }
            self.fresh = false;
            if let Some(data) = self.recv(false).filter(|d| !d.is_empty()) {
                self.depth += 1;
                self.take(&data);
                self.depth -= 1;
                return;
            }
        }
        self.fresh = false;
        if !self.done {
            self.write(text);
        }
    }

    /// A state change, with the time of now as OpenVPN gives it.
    fn emit_state(&mut self, name: &str, rest: &str) {
        self.emit(&format!(">STATE:{},{name},{rest}", unix_now()));
    }

    fn process(&mut self, cmd: &str) {
        self.fake
            .shared
            .received
            .lock()
            .unwrap()
            .push(cmd.to_string());
        // OpenVPN logs every command, with the value of a password left out.
        let shown = if cmd.starts_with("password ") {
            "password [...]"
        } else {
            cmd
        };
        let echo = format!("1700000000,D,MANAGEMENT: CMD '{shown}'");
        self.history.push(echo.clone());
        if self.log_realtime {
            self.emit(&format!(">LOG:{echo}"));
        }
        let ignored = self.fake.ignore.lock().unwrap().clone();
        if ignored.is_some_and(|prefix| cmd.starts_with(&prefix)) {
            return;
        }
        if cmd == "log on all" {
            self.log_realtime = true;
            self.emit("SUCCESS: real-time log notification set to ON");
            for line in self.history.clone() {
                self.emit(&line);
            }
            self.emit("END");
        } else if cmd == "state on all" {
            self.emit("SUCCESS: real-time state notification set to ON");
            self.emit("1700000000,CONNECTING,,,,,,");
            self.emit("END");
        } else if cmd == "bytecount 1" {
            self.emit("SUCCESS: bytecount interval changed");
        } else if cmd == "hold release" {
            self.fake
                .shared
                .hold_releases
                .lock()
                .unwrap()
                .push(Instant::now());
            self.emit("SUCCESS: hold release succeeded");
            // Like OpenVPN, ask for the login before connecting to the server.
            self.later.push_back(Later::NeedLogin);
        } else if cmd.starts_with("username ") {
            self.emit("SUCCESS: 'Auth' username entered, but not yet verified");
        } else if let Some(rest) = cmd.strip_prefix("password \"Auth\" ") {
            self.emit("SUCCESS: 'Auth' password entered, but not yet verified");
            self.later.push_back(Later::Login(unquote(rest)));
        } else if cmd == "signal SIGTERM" {
            self.emit("SUCCESS: signal SIGTERM thrown");
            self.emit_state("EXITING", "SIGTERM,,,,,");
            self.exited.store(true, Ordering::SeqCst);
            let _ = self.w.shutdown(std::net::Shutdown::Both);
            self.done = true;
        } else {
            self.emit("ERROR: unknown command");
        }
    }

    /// What OpenVPN reports while it connects and logs in with `password`.
    fn play_login(&mut self, password: String) {
        let restart = ">HOLD:Waiting for hold release:5";
        let outcome = self.fake.next_outcome();
        self.emit_state("TCP_CONNECT", ",,,,,");
        if outcome == Outcome::Hang {
            return;
        }
        if outcome == Outcome::Unreachable {
            self.emit(&format!(
                ">LOG:1700000002,N,TCP: connect to [AF_INET]{SERVER} failed: Connection timed out"
            ));
            self.emit(">LOG:1700000002,I,SIGUSR1[connection failed(soft),init_instance] received, process restarting");
            self.emit_state("RECONNECTING", "init_instance,,,,,");
            self.emit(restart);
            return;
        }
        self.emit(&format!(
            ">LOG:1700000001,I,TCP connection established with [AF_INET]{SERVER}"
        ));
        self.emit(&format!(
            ">LOG:1700000001,I,TCPv4_CLIENT link remote: [AF_INET]{SERVER}"
        ));
        self.emit_state("WAIT", ",,,,,");
        self.emit_state("AUTH", ",,,,,");
        self.emit(">LOG:1700000002,I,VERIFY OK: depth=0, CN=fake-server");
        match outcome {
            Outcome::Unreachable | Outcome::Hang => unreachable!("handled above"),
            Outcome::Reset => {
                self.emit(">LOG:1700000002,N,Connection reset, restarting [0]");
                self.emit(
                    ">LOG:1700000002,I,SIGUSR1[soft,connection-reset] received, process restarting",
                );
                self.emit_state("RECONNECTING", "connection-reset,,,,,");
                self.emit(restart);
            }
            Outcome::NoSharedCipher => {
                let why = "Data channel cipher negotiation failed (no shared cipher)";
                self.emit(&format!(
                    ">LOG:1700000002,I,AUTH: Received control message: AUTH_FAILED,{why}"
                ));
                self.emit(&format!(">PASSWORD:Verification Failed: 'Auth' ['{why}']"));
                self.emit_state("RECONNECTING", "auth-failure,,,,,");
                self.emit(restart);
            }
            Outcome::Login if password == *self.fake.accept.lock().unwrap() => {
                self.emit(">LOG:1700000003,I,PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,dhcp-option DNS 10.20.0.53,ifconfig 10.8.0.6 255.255.255.0'");
                self.emit_state("GET_CONFIG", ",,,,,");
                self.emit_state("ASSIGN_IP", ",10.8.0.6,,,,");
                self.emit_state("ADD_ROUTES", ",,,,,");
                let (ip, port) = SERVER.split_once(':').unwrap();
                self.emit_state("CONNECTED", &format!("SUCCESS,10.8.0.6,{ip},{port},,"));
                self.emit(">BYTECOUNT:1000,500");
                self.emit(">BYTECOUNT:5000,900");
            }
            Outcome::Login => {
                self.emit(">PASSWORD:Verification Failed: 'Auth'");
                self.emit_state("RECONNECTING", "auth-failure,,,,,");
                self.emit(restart);
            }
        }
    }
}

/// Give a log line the time of now. The lines in this file are written with
/// the stamp `17000000xx`, in `>LOG:` lines and in the lines of the log history.
fn stamp_now(text: &str) -> String {
    let (head, rest) = match text.strip_prefix(">LOG:") {
        Some(rest) => (">LOG:", rest),
        None => ("", text),
    };
    match rest.split_once(',') {
        Some((stamp, tail))
            if stamp.len() == 10
                && stamp.starts_with("17000000")
                && stamp.chars().all(|c| c.is_ascii_digit()) =>
        {
            format!("{head}{},{tail}", unix_now())
        }
        _ => text.to_string(),
    }
}

/// Seconds since 1970, as OpenVPN stamps its state lines.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    /// A management client for the tests below: it sends lines and collects
    /// what comes back.
    struct Client {
        stream: TcpStream,
        seen: Vec<String>,
        rest: String,
    }

    impl Client {
        fn connect(fake: &Fake) -> Client {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let fake = fake.clone();
            std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                fake.serve(stream, Arc::new(AtomicBool::new(false)));
            });
            let stream = TcpStream::connect(addr).unwrap();
            stream.set_nodelay(true).unwrap();
            let mut client = Client {
                stream,
                seen: Vec::new(),
                rest: String::new(),
            };
            client.send(MGMT_PW);
            // The password prompt comes without a line ending.
            client.until("ENTER PASSWORD:SUCCESS: password is correct");
            client
        }

        fn send(&mut self, line: &str) {
            self.stream
                .write_all(format!("{line}\n").as_bytes())
                .unwrap();
        }

        /// Read for `quiet` without anything new arriving.
        fn settle(&mut self, quiet: Duration) {
            self.stream.set_read_timeout(Some(quiet)).unwrap();
            let mut buf = [0u8; 4096];
            while let Ok(n) = self.stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
                self.rest.push_str(&String::from_utf8_lossy(&buf[..n]));
                while let Some(i) = self.rest.find('\n') {
                    let line: String = self.rest.drain(..=i).collect();
                    self.seen.push(line.trim_end().to_string());
                }
            }
        }

        /// Read until a line that starts with `prefix` has arrived.
        fn until(&mut self, prefix: &str) {
            let from = self.seen.len();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.seen[from..].iter().any(|l| l.starts_with(prefix)) {
                assert!(
                    Instant::now() < deadline,
                    "no `{prefix}` line; got {:#?}",
                    self.seen
                );
                self.settle(Duration::from_millis(20));
            }
        }

        /// Read until a line with `part` in it has arrived.
        fn until_has(&mut self, part: &str) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.seen.iter().any(|l| l.contains(part)) {
                assert!(
                    Instant::now() < deadline,
                    "no line with `{part}`; got {:#?}",
                    self.seen
                );
                self.settle(Duration::from_millis(20));
            }
        }

        fn count(&self, prefix: &str) -> usize {
            self.seen.iter().filter(|l| l.starts_with(prefix)).count()
        }
    }

    const USERNAME_CMD: &str = "username \"Auth\" \"alice\"";
    const USERNAME_OK: &str = "SUCCESS: 'Auth' username entered";
    const PASSWORD_OK: &str = "SUCCESS: 'Auth' password entered";

    /// The exchange that was captured from OpenVPN 2.6 on Windows: the client
    /// sent each command without waiting for the answer to the one before.
    /// `state on all` and the password never ran, `log on all` and the user
    /// name ran twice, and OpenVPN went on waiting for a password for ever.
    #[test]
    fn windows_reentry_loses_a_command_sent_before_the_last_answer() {
        let mut fake = Fake::new("pw123456");
        fake.windows_reentry = true;
        let mut c = Client::connect(&fake);
        c.send("log on all");
        c.send("state on all");
        c.send("bytecount 1");
        c.until("SUCCESS: bytecount");
        c.send("hold release");
        c.until(">PASSWORD:Need 'Auth'");
        c.send(USERNAME_CMD);
        c.send("password \"Auth\" \"pw123456\"");
        c.settle(Duration::from_millis(300));

        assert_eq!(
            fake.received(),
            vec![
                "log on all",
                "log on all",
                "bytecount 1",
                "hold release",
                USERNAME_CMD,
                USERNAME_CMD
            ],
            "what the fake ran"
        );
        assert_eq!(c.count(USERNAME_OK), 2, "{:#?}", c.seen);
        assert_eq!(c.count(PASSWORD_OK), 0, "{:#?}", c.seen);
        assert_eq!(c.count(">STATE:"), 0, "no connection was started");
        // The second `log on all` printed the log again, with the command
        // lines in it that the old state reader took for states.
        let dumped = c
            .seen
            .iter()
            .filter(|l| !l.starts_with('>') && l.ends_with(",D,MANAGEMENT: CMD 'log on all'"))
            .count();
        assert!(dumped >= 2, "{:#?}", c.seen);
        assert_eq!(c.count("SUCCESS: real-time state notification"), 0);
    }

    /// The same commands, each sent after the answer to the one before.
    #[test]
    fn windows_reentry_is_harmless_for_a_client_that_waits_for_each_answer() {
        let mut fake = Fake::new("pw123456");
        fake.windows_reentry = true;
        let mut c = Client::connect(&fake);
        c.send("log on all");
        c.until("END");
        c.send("state on all");
        c.until("END");
        c.send("bytecount 1");
        c.until("SUCCESS: bytecount");
        c.send("hold release");
        c.until(">PASSWORD:Need 'Auth'");
        c.send(USERNAME_CMD);
        c.until(USERNAME_OK);
        c.send("password \"Auth\" \"pw123456\"");
        c.until_has(",CONNECTED,SUCCESS,");
        assert_eq!(
            fake.received(),
            vec![
                "log on all",
                "state on all",
                "bytecount 1",
                "hold release",
                USERNAME_CMD,
                "password \"Auth\" \"pw123456\""
            ]
        );
        assert_eq!(c.count(USERNAME_OK), 1);
        assert_eq!(c.count(PASSWORD_OK), 1);
        // OpenVPN's own log of the command leaves the password out.
        assert!(!c.seen.iter().any(|l| l.contains("CMD 'password \"Auth\"")));
    }

    /// Without the Windows way of reading, commands sent in a row all run.
    #[test]
    fn commands_sent_in_a_row_all_run_elsewhere() {
        let fake = Fake::new("pw123456");
        let mut c = Client::connect(&fake);
        c.send("log on all");
        c.send("state on all");
        c.send("bytecount 1");
        c.send("hold release");
        c.until(">PASSWORD:Need 'Auth'");
        c.send(USERNAME_CMD);
        c.send("password \"Auth\" \"pw123456\"");
        c.until_has(",CONNECTED,SUCCESS,");
        assert_eq!(fake.received().len(), 6);
    }

    #[test]
    fn log_lines_get_the_time_of_now() {
        let now = unix_now().to_string();
        assert_eq!(
            stamp_now(">LOG:1700000002,N,Connection reset, restarting [0]"),
            format!(">LOG:{now},N,Connection reset, restarting [0]")
        );
        assert_eq!(
            stamp_now("1700000000,W,WARNING: a, b"),
            format!("{now},W,WARNING: a, b")
        );
        for other in ["SUCCESS: hold release succeeded", ">HOLD:Waiting:5", "END"] {
            assert_eq!(stamp_now(other), other);
        }
    }

    #[test]
    fn unquotes_management_values() {
        assert_eq!(unquote(r#""a\"b\\c""#), r#"a"b\c"#);
        assert_eq!(unquote("plain"), "plain");
    }
}
