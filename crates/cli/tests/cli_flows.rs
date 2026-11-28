//! The command line as a script or an AI agent drives it: no terminal, no
//! window, and a stand-in for the `openvpn` program
//! (`examples/fake_openvpn.rs`) that plays each way a connection can go.
//!
//! Every test gets its own settings file and runtime folder, and always
//! gives the user name itself: ovpn-otp never assumes one.

#![cfg(unix)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::Value;

const PASSWORD: &str = "s3cret-Pw";
const CODE: &str = "135790";
const USER: &str = "name-given-by-the-test";

/// The stand-in `openvpn`, built by `cargo test` next to the test programs.
fn fake_openvpn() -> PathBuf {
    // The examples are built next to the `ovpn-otp` binary. The test program
    // itself may live in a separate build directory, so do not start from it.
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_ovpn-otp"));
    let fake = bin.parent().unwrap().join("examples").join("fake_openvpn");
    assert!(
        fake.is_file(),
        "{} is missing. Run the whole test suite of the package (`cargo test -p ovpn-otp`), \
         which also builds the examples.",
        fake.display()
    );
    fake
}

struct Sandbox {
    dir: tempfile::TempDir,
    /// The script for the stand-in openvpn (`OVPN_OTP_FAKE`).
    fake: String,
}

struct Ran {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Ran {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}):\n{}", self.stdout))
    }
}

impl Sandbox {
    /// `plan` is what the stand-in server does with each login, such as
    /// `login`, `reset` or `unreachable`. `extra` is added to the settings.
    fn with_settings(plan: &str, extra: &str) -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        let settings = format!(
            r#"name = "cli-test"
[profile]
inline = """
client
dev tun
proto tcp
remote 198.51.100.7 8443 tcp-client
remote 10.255.0.1 8443 tcp-client
cipher AES-128-CBC
auth SHA256
auth-user-pass
"""
[keepalive]
backoff_initial = 1
backoff_max = 1
[openvpn.linux]
path = "{}"
command_prefix = []
{extra}
"#,
            fake_openvpn().display()
        );
        std::fs::write(dir.path().join("settings.toml"), settings).unwrap();
        Sandbox {
            dir,
            fake: format!("accept={PASSWORD}{CODE};plan={plan}"),
        }
    }

    fn new(plan: &str) -> Sandbox {
        Sandbox::with_settings(plan, "")
    }

    fn runtime_dir(&self) -> PathBuf {
        self.dir.path().join("run")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ovpn-otp"));
        cmd.args(args)
            .env("OVPN_OTP_CONFIG", self.dir.path().join("settings.toml"))
            .env("OVPN_OTP_RUNTIME_DIR", self.runtime_dir())
            .env("OVPN_OTP_FAKE", &self.fake)
            // No desktop keyring in tests: the login always comes from the test.
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    /// Run a command to its end, with `stdin` as its standard input.
    fn run(&self, args: &[&str], stdin: &str) -> Ran {
        let mut child = self.command(args).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out: Output = child.wait_with_output().unwrap();
        Ran {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    /// `connect --background` the way an agent calls it: password and code on
    /// standard input, the outcome as JSON.
    fn connect_background(&self) -> Ran {
        self.run(
            &[
                "connect",
                "--username",
                USER,
                "--password-stdin",
                "--code-stdin",
                "--background",
                "--json",
            ],
            &format!("{PASSWORD}\n{CODE}\n"),
        )
    }

    fn status(&self) -> Value {
        let ran = self.run(&["status", "--json"], "");
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        ran.json()
    }

    /// The log as `logs --json` prints it, one object per line.
    fn logs(&self, args: &[&str]) -> Vec<Value> {
        let mut all = vec!["logs", "--json"];
        all.extend_from_slice(args);
        let ran = self.run(&all, "");
        assert_eq!(ran.code, 0, "{}", ran.stderr);
        ran.stdout
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON ({e}): {l}")))
            .collect()
    }
}

impl Drop for Sandbox {
    /// Stop a background session the test left running.
    fn drop(&mut self) {
        let _ = self.run(&["disconnect"], "");
    }
}

/// The password is in nothing that was printed or written, and the code is
/// in no message.
fn assert_no_secrets(sandbox: &Sandbox, printed: &[&Ran]) {
    for ran in printed {
        for text in [&ran.stdout, &ran.stderr] {
            assert!(!text.contains(PASSWORD), "password printed:\n{text}");
        }
        // A background start prints only the outcome, never the code.
        assert!(!ran.stderr.contains(CODE), "code printed:\n{}", ran.stderr);
    }
    for entry in std::fs::read_dir(sandbox.runtime_dir()).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            !text.contains(PASSWORD),
            "password written to {}",
            path.display()
        );
    }
    assert!(
        !sandbox.runtime_dir().join("code").exists(),
        "the code file was left behind"
    );
    for record in sandbox.logs(&["--wire"]) {
        let message = record["message"].as_str().unwrap();
        assert!(!message.contains(CODE), "code in the log: {message}");
        assert!(
            !message.contains(PASSWORD),
            "password in the log: {message}"
        );
    }
    let status = sandbox.status();
    assert!(
        !status["last_error"].as_str().unwrap_or("").contains(CODE),
        "code in the status"
    );
}

#[test]
fn elevate_connect_runs_here_when_there_is_nothing_to_elevate() {
    // On this system (no desktop window with administrator rights) --elevate
    // says so and runs the connect itself, like a background one.
    let sandbox = Sandbox::new("login");
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code-stdin",
            "--elevate",
            "--json",
        ],
        &format!("{PASSWORD}\n{CODE}\n"),
    );
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    assert!(ran.stderr.contains("Connected."), "{}", ran.stderr);
    assert_eq!(ran.json()["phase"], "connected");
    assert_no_secrets(&sandbox, &[&ran]);
}

#[test]
fn background_connect_returns_when_the_tunnel_is_up() {
    let sandbox = Sandbox::new("login");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    assert!(ran.stderr.contains("Connected."), "{}", ran.stderr);
    let report = ran.json();
    assert_eq!(report["running"], true);
    assert_eq!(report["phase"], "connected");
    assert_eq!(report["needs_code"], false);
    assert!(report["failure_reason"].is_null());
    assert!(report["last_error"].is_null());
    assert_eq!(report["remote"], "198.51.100.7:8443");
    assert_eq!(report["local_ip"], "10.8.0.6");
    assert!(report["since"].is_string());
    assert!(report["bytes_in"].is_u64() && report["bytes_out"].is_u64());

    // The session is its own process and goes on after `connect` returned.
    let status = sandbox.status();
    assert_eq!(status["phase"], "connected");
    assert_eq!(status["running"], true);
    assert_eq!(status["name"], "cli-test");
    let pid = status["pid"].as_u64().unwrap();
    // The login is not on the command line of the session process.
    let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    assert!(cmdline.contains("--detached"), "{cmdline}");
    assert!(!cmdline.contains(PASSWORD) && !cmdline.contains(CODE) && !cmdline.contains(USER));

    // The profile OpenVPN got: the old cipher line is made to work, and the
    // private server address is left out.
    let prepared = std::fs::read_to_string(sandbox.runtime_dir().join("cli-test.ovpn")).unwrap();
    assert!(
        prepared.contains("data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC\n")
    );
    assert!(prepared.contains("data-ciphers-fallback AES-128-CBC\n"));
    assert!(prepared.contains("# skipped by ovpn-otp (private address): remote 10.255.0.1 8443"));

    // `logs --json`: one object per line with the same fields every time.
    let logs = sandbox.logs(&[]);
    assert!(!logs.is_empty());
    for record in &logs {
        assert!(record["at"].is_string(), "{record}");
        assert!(record["message"].is_string(), "{record}");
        let source = record["source"].as_str().unwrap();
        assert!(
            ["app", "openvpn", "state", "check"].contains(&source),
            "{record}"
        );
        let level = record["level"].as_str().unwrap();
        assert!(
            ["debug", "info", "warning", "error", "fatal"].contains(&level),
            "{record}"
        );
    }
    let messages: Vec<&str> = logs
        .iter()
        .map(|r| r["message"].as_str().unwrap())
        .collect();
    assert!(messages.iter().any(|m| m.starts_with("CONNECTED")));
    assert!(messages
        .iter()
        .any(|m| m.contains("data-ciphers-fallback AES-128-CBC")));
    assert!(messages.iter().any(|m| m.contains("10.255.0.1:8443")));
    // The management transcript only comes with --wire, and says which way a line went.
    let wire = sandbox.logs(&["--wire"]);
    assert!(wire
        .iter()
        .any(|r| r["source"] == "wire" && r["dir"] == "out"));
    assert!(wire
        .iter()
        .any(|r| r["source"] == "wire" && r["dir"] == "in"));
    let text = sandbox.run(&["logs", "-n", "3"], "");
    assert_eq!(text.stdout.lines().count(), 3);

    let waited = sandbox.run(&["wait", "--until", "connected", "--timeout", "5"], "");
    assert_eq!(waited.code, 0, "{}", waited.stderr);
    // A wait that cannot come true ends with the timeout code.
    let waited = sandbox.run(&["wait", "--until", "disconnected", "--timeout", "1"], "");
    assert_eq!(waited.code, 7, "{}", waited.stderr);
    // A second session is refused while this one runs.
    let second = sandbox.connect_background();
    assert_eq!(second.code, 1);
    assert!(
        second.stderr.contains("already running"),
        "{}",
        second.stderr
    );

    assert_no_secrets(&sandbox, &[&ran]);
    let ended = sandbox.run(&["disconnect"], "");
    assert_eq!(ended.code, 0, "{}", ended.stderr);
    let waited = sandbox.run(&["wait", "--until", "disconnected", "--timeout", "10"], "");
    assert_eq!(waited.code, 0);
    let status = sandbox.status();
    assert_eq!(status["running"], false);
    assert_eq!(status["phase"], "disconnected");
    assert!(status["failure_reason"].is_null());
    // The private copy of the profile is gone with the session.
    assert!(!sandbox.runtime_dir().join("cli-test.ovpn").exists());
}

#[test]
fn server_reset_during_login_exits_4_with_the_likely_causes() {
    let sandbox = Sandbox::new("reset");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 4, "stderr: {}", ran.stderr);
    for cause in [
        "closed the connection during login",
        "code was wrong",
        "cipher mismatch",
    ] {
        assert!(
            ran.stderr.contains(cause),
            "`{cause}` not in: {}",
            ran.stderr
        );
    }
    let report = ran.json();
    assert_eq!(report["failure_reason"], "server_reset");
    assert_eq!(report["phase"], "failed");
    assert_eq!(report["running"], false);
    assert_eq!(
        report["needs_code"], false,
        "it must not ask for another code"
    );
    assert_eq!(report["remote"], "198.51.100.7:8443");
    assert!(report["last_error"]
        .as_str()
        .unwrap()
        .contains("closed the connection during login"));
    // Nothing is left running, and `status` and `wait` say the same afterwards.
    assert_eq!(sandbox.status()["failure_reason"], "server_reset");
    let waited = sandbox.run(&["wait", "--until", "connected", "--timeout", "5"], "");
    assert_eq!(waited.code, 4);
    assert!(sandbox
        .logs(&[])
        .iter()
        .any(|r| r["level"] == "error"
            && r["message"].as_str().unwrap().starts_with("server_reset:")));
    assert_no_secrets(&sandbox, &[&ran]);
}

#[test]
fn unreachable_server_exits_5() {
    let sandbox = Sandbox::new("unreachable");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 5, "stderr: {}", ran.stderr);
    assert!(
        ran.stderr.contains("Could not reach the VPN server"),
        "{}",
        ran.stderr
    );
    let report = ran.json();
    assert_eq!(report["failure_reason"], "unreachable");
    assert_eq!(report["running"], false);
}

#[test]
fn rejected_login_exits_3() {
    let sandbox = Sandbox::new("login");
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code-stdin",
            "--background",
            "--json",
        ],
        &format!("{PASSWORD}\n000000\n"),
    );
    assert_eq!(ran.code, 3, "stderr: {}", ran.stderr);
    assert!(ran.stderr.contains("rejected the login"), "{}", ran.stderr);
    let report = ran.json();
    assert_eq!(report["failure_reason"], "auth_failed");
    assert_eq!(report["phase"], "failed");
    assert_eq!(report["running"], false);
}

#[test]
fn no_shared_cipher_exits_4_as_a_cipher_mismatch() {
    let sandbox = Sandbox::new("no-shared-cipher");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 4, "stderr: {}", ran.stderr);
    assert_eq!(ran.json()["failure_reason"], "cipher_mismatch");
    assert!(ran.stderr.contains("extra_options"), "{}", ran.stderr);
}

#[test]
fn a_session_without_a_code_exits_6_and_takes_one_from_the_code_command() {
    let sandbox = Sandbox::new("login");
    // No code given, and nobody to ask.
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--background",
            "--json",
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(ran.code, 6, "stderr: {}", ran.stderr);
    assert!(ran.stderr.contains("ovpn-otp code"), "{}", ran.stderr);
    let report = ran.json();
    assert_eq!(report["running"], true);
    assert_eq!(report["phase"], "need_code");
    assert_eq!(report["needs_code"], true);
    assert_eq!(report["code_reason"], "initial");

    // Waiting does not help while the code is missing: it says so at once.
    let waited = sandbox.run(&["wait", "--until", "connected", "--timeout", "30"], "");
    assert_eq!(waited.code, 6, "{}", waited.stderr);
    // A code that cannot be right is refused before it reaches the session.
    let bad = sandbox.run(&["code", "12ab"], "");
    assert_eq!(bad.code, 2, "{}", bad.stderr);
    assert_eq!(sandbox.status()["needs_code"], true);

    let given = sandbox.run(&["code", "--stdin"], &format!("{CODE}\n"));
    assert_eq!(given.code, 0, "{}", given.stderr);
    let waited = sandbox.run(
        &["wait", "--until", "connected", "--timeout", "20", "--json"],
        "",
    );
    assert_eq!(waited.code, 0, "{}", waited.stderr);
    let report = waited.json();
    assert_eq!(report["phase"], "connected");
    assert_eq!(report["needs_code"], false);
    assert!(report["code_reason"].is_null());
    assert_no_secrets(&sandbox, &[&ran, &given, &waited]);
}

#[test]
fn background_connect_times_out_with_7_and_stops_the_session() {
    let sandbox = Sandbox::new("hang");
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code-stdin",
            "--background",
            "--timeout",
            "2",
        ],
        &format!("{PASSWORD}\n{CODE}\n"),
    );
    assert_eq!(ran.code, 7, "stderr: {}", ran.stderr);
    assert!(
        ran.stderr.contains("Not connected within 2 seconds"),
        "{}",
        ran.stderr
    );
    assert_eq!(sandbox.status()["running"], false);
}

#[test]
fn foreground_connect_ends_by_itself_with_the_code_for_the_failure() {
    // The code as an option, the password on standard input.
    let sandbox = Sandbox::new("reset");
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code",
            CODE,
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(ran.code, 4, "stderr: {}", ran.stderr);
    assert!(
        ran.stderr.contains("closed the connection during login"),
        "{}",
        ran.stderr
    );
    assert!(
        !ran.stderr.contains("Type the"),
        "asked for a code after the reset: {}",
        ran.stderr
    );
    assert_eq!(sandbox.status()["failure_reason"], "server_reset");

    // A wrong code, with nobody at a terminal to ask again.
    let sandbox = Sandbox::new("login");
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--otp",
            "000000",
        ],
        &format!("{PASSWORD}\n"),
    );
    assert_eq!(ran.code, 3, "stderr: {}", ran.stderr);
}

#[test]
fn nothing_running_is_said_plainly() {
    let sandbox = Sandbox::new("login");
    let status = sandbox.status();
    assert_eq!(status["running"], false);
    assert_eq!(status["phase"], "idle");
    assert_eq!(status["needs_code"], false);
    assert!(status["failure_reason"].is_null());
    let waited = sandbox.run(&["wait", "--until", "disconnected"], "");
    assert_eq!(waited.code, 0);
    let waited = sandbox.run(&["wait", "--until", "connected", "--timeout", "5"], "");
    assert_eq!(waited.code, 1);
    assert!(
        waited.stderr.contains("No session is running"),
        "{}",
        waited.stderr
    );
    let given = sandbox.run(&["code", CODE], "");
    assert_eq!(given.code, 1);
    assert!(
        given.stderr.contains("no session is running"),
        "{}",
        given.stderr
    );
    assert!(!sandbox.runtime_dir().join("code").exists());
    let logs = sandbox.run(&["logs", "--json"], "");
    assert_eq!((logs.code, logs.stdout.as_str()), (0, ""));
}

#[test]
fn wrong_command_lines_exit_2() {
    let sandbox = Sandbox::new("login");
    let login = format!("{PASSWORD}\n");
    for (args, stdin) in [
        (vec!["wait", "--until", "nonsense"], ""),
        (vec!["wait"], ""),
        (vec!["code"], ""),
        (vec!["code", CODE, "--stdin"], ""),
        (vec!["no-such-command"], ""),
        // --timeout and --json belong to --background.
        (vec!["connect", "--timeout", "5"], ""),
        (vec!["connect", "--code", CODE, "--code-stdin"], ""),
        // A code that is not six digits.
        (
            vec![
                "connect",
                "--username",
                USER,
                "--password-stdin",
                "--code",
                "12ab",
            ],
            login.as_str(),
        ),
        // --code-stdin with no code on standard input.
        (
            vec![
                "connect",
                "--username",
                USER,
                "--password-stdin",
                "--code-stdin",
            ],
            login.as_str(),
        ),
    ] {
        let ran = sandbox.run(&args, stdin);
        assert_eq!(ran.code, 2, "{args:?} gave {}: {}", ran.code, ran.stderr);
    }
    assert_eq!(sandbox.status()["phase"], "idle", "nothing was started");
}

/// The user name is never assumed: without one the command stops and says so.
#[test]
fn connect_without_a_user_name_is_refused() {
    let sandbox = Sandbox::new("login");
    for background in [false, true] {
        let mut args = vec!["connect", "--password-stdin", "--code", CODE];
        if background {
            args.push("--background");
        }
        let ran = sandbox.run(&args, &format!("{PASSWORD}\n"));
        assert_eq!(ran.code, 1, "{}", ran.stderr);
        assert!(ran.stderr.contains("--username"), "{}", ran.stderr);
    }
    assert_eq!(sandbox.status()["phase"], "idle", "nothing was started");
}

#[test]
fn extra_options_are_checked_by_doctor_and_refused_by_connect_when_malformed() {
    // Command-line tokens are read as one option per line.
    let sandbox = Sandbox::with_settings(
        "login",
        r#"[openvpn]
extra_options = ["--data-ciphers", "AES-256-GCM:AES-128-GCM:AES-128-CBC", "--data-ciphers-fallback", "AES-128-CBC", "--disable-dco"]
"#,
    );
    let doctor = sandbox.run(&["doctor"], "");
    assert!(
        doctor.stdout.contains(
            "ok   extra options: given to OpenVPN as: data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC; \
             data-ciphers-fallback AES-128-CBC; disable-dco"
        ),
        "{}",
        doctor.stdout
    );
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    let prepared = std::fs::read_to_string(sandbox.runtime_dir().join("cli-test.ovpn")).unwrap();
    assert!(
        prepared.ends_with(
            "data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC\ndata-ciphers-fallback AES-128-CBC\ndisable-dco\n"
        ),
        "{prepared}"
    );
    assert!(!prepared.contains("--data-ciphers"));
    drop(sandbox);

    // A parameter before any option: nothing says what it belongs to.
    let sandbox = Sandbox::with_settings(
        "login",
        "[openvpn]\nextra_options = [\"AES-128-CBC\", \"--disable-dco\"]\n",
    );
    let message = "extra_options item 1 (\"AES-128-CBC\") comes before the first item that starts with \"--\".";
    let doctor = sandbox.run(&["doctor"], "");
    assert_eq!(doctor.code, 1);
    assert!(
        doctor
            .stdout
            .contains(&format!("FAIL extra options: {message}")),
        "{}",
        doctor.stdout
    );
    // The profile itself is still checked.
    assert!(doctor.stdout.contains("ok   profile:"), "{}", doctor.stdout);
    for background in [false, true] {
        let mut args = vec![
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code",
            CODE,
        ];
        if background {
            args.push("--background");
        }
        let ran = sandbox.run(&args, &format!("{PASSWORD}\n"));
        assert_eq!(ran.code, 1, "{}", ran.stderr);
        assert!(ran.stderr.contains(message), "{}", ran.stderr);
    }
}

/// The stall first seen on Windows, through the real command: the stand-in
/// OpenVPN reads its management socket the way OpenVPN does on Windows, and
/// the connect still comes up.
#[test]
fn connects_to_an_openvpn_that_reads_while_it_answers() {
    let mut sandbox = Sandbox::new("login");
    sandbox.fake.push_str(";windows-reentry=1");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    let report = ran.json();
    assert_eq!(report["phase"], "connected");
    assert_eq!(report["openvpn_state"], "CONNECTED");
    // No log line was taken for a state.
    for record in sandbox.logs(&[]) {
        if record["source"] == "state" {
            let message = record["message"].as_str().unwrap();
            let name = message.split(' ').next().unwrap();
            assert!(name.len() >= 4, "a log line as a state: {message}");
        }
    }
    assert_no_secrets(&sandbox, &[&ran]);
}

/// `status` says which profile, server, connection and user name are in
/// use, and the state in words: before a session, while one connects, when
/// it is up, and after it failed.
#[test]
fn status_shows_what_is_in_use_and_the_state_in_words() {
    // Before any session: what the next connect would use.
    let sandbox = Sandbox::new("login");
    let idle = sandbox.status();
    assert_eq!(idle["state"], "Disconnected");
    assert_eq!(idle["name"], "cli-test");
    assert_eq!(idle["profile"], "inside the settings file");
    assert_eq!(idle["servers"][0], "198.51.100.7:8443 (tcp)");
    assert_eq!(idle["servers"].as_array().unwrap().len(), 1);
    assert!(idle["username"].is_null(), "no login is saved in the tests");
    let text = sandbox.run(&["status"], "");
    assert_eq!(text.code, 0, "{}", text.stderr);
    for line in [
        "State:      Disconnected",
        "Connection: cli-test",
        "Profile:    inside the settings file",
        "Server:     198.51.100.7:8443 (tcp)",
        "User:       no saved login",
    ] {
        assert!(
            text.stdout.contains(line),
            "`{line}` not in:\n{}",
            text.stdout
        );
    }

    // Connected.
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    let up = sandbox.status();
    assert_eq!(up["state"], "Connected");
    assert!(
        up["state_detail"]
            .as_str()
            .unwrap()
            .starts_with("address 10.8.0.6, since "),
        "{up}"
    );
    assert_eq!(up["username"], USER);
    assert_eq!(up["profile"], "inside the settings file");
    assert_eq!(up["servers"][0], "198.51.100.7:8443 (tcp)");
    assert!(up["step"].is_null());
    let text = sandbox.run(&["status"], "");
    for line in [
        "State:      Connected: address 10.8.0.6, since ",
        "Connection: cli-test",
        "Server:     198.51.100.7:8443 (tcp)\n",
        &format!("User:       {USER}"),
    ] {
        assert!(
            text.stdout.contains(line),
            "`{line}` not in:\n{}",
            text.stdout
        );
    }
    // No colour codes when the output is not a terminal.
    assert!(!text.stdout.contains('\x1b'));
    let ended = sandbox.run(&["disconnect", "--json"], "");
    assert_eq!(ended.code, 0, "{}", ended.stderr);
    let after = ended.json();
    assert_eq!(after["running"], false);
    assert_eq!(after["state"], "Disconnected");
    drop(sandbox);

    // Connecting, with the step and how long it has been.
    let sandbox = Sandbox::new("hang");
    let ran = sandbox.run(
        &[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code-stdin",
            "--background",
            "--timeout",
            "1",
        ],
        &format!("{PASSWORD}\n{CODE}\n"),
    );
    assert_eq!(ran.code, 7, "stderr: {}", ran.stderr);
    drop(sandbox);
    let sandbox = Sandbox::new("hang");
    let mut child = sandbox
        .command(&[
            "connect",
            "--username",
            USER,
            "--password-stdin",
            "--code",
            CODE,
        ])
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(format!("{PASSWORD}\n").as_bytes()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let busy = loop {
        let now = sandbox.status();
        if now["openvpn_state"] == "TCP_CONNECT" {
            break now;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never connecting: {now}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert_eq!(busy["state"], "Connecting…");
    assert_eq!(busy["step"], "opening a connection to the server");
    assert!(
        busy["state_detail"]
            .as_str()
            .unwrap()
            .starts_with("opening a connection to the server ("),
        "{busy}"
    );
    assert_eq!(busy["username"], USER);
    let text = sandbox.run(&["status"], "");
    assert!(
        text.stdout
            .contains("State:      Connecting…: opening a connection to the server ("),
        "{}",
        text.stdout
    );
    let ended = sandbox.run(&["disconnect"], "");
    assert_eq!(ended.code, 0, "{}", ended.stderr);
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    // The foreground connect said what it uses before it tried.
    let said = String::from_utf8_lossy(&out.stderr);
    for line in [
        "Connection: cli-test",
        "Server:     198.51.100.7:8443 (tcp)",
    ] {
        assert!(said.contains(line), "`{line}` not in:\n{said}");
    }
    assert!(said.contains(&format!("User:       {USER}")), "{said}");
    drop(sandbox);

    // Failed, with the reason.
    let sandbox = Sandbox::new("unreachable");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 5);
    let failed = sandbox.status();
    assert_eq!(failed["state"], "Failed");
    assert!(
        failed["state_detail"]
            .as_str()
            .unwrap()
            .contains("Could not reach the VPN server"),
        "{failed}"
    );
    let text = sandbox.run(&["status"], "");
    assert!(
        text.stdout
            .contains("State:      Failed: Could not reach the VPN server"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("Reason:     unreachable"),
        "{}",
        text.stdout
    );
    assert!(text.stdout.contains("Profile:    inside the settings file"));
}

/// A connect that makes no progress ends by itself after `connect.timeout`,
/// with exit code 7 and the step it was stuck in, instead of staying on
/// "Connecting" until someone gives up.
#[test]
fn a_connect_without_progress_ends_with_7_and_says_where_it_stuck() {
    let sandbox = Sandbox::with_settings("hang", "[connect]\ntimeout = 1\n");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 7, "stderr: {}", ran.stderr);
    assert!(
        ran.stderr.contains("after 1 seconds without progress")
            && ran.stderr.contains("the server did not answer"),
        "{}",
        ran.stderr
    );
    let report = ran.json();
    assert_eq!(report["failure_reason"], "timeout");
    assert_eq!(report["phase"], "failed");
    assert_eq!(report["state"], "Failed");
    assert_eq!(report["running"], false);
    assert_eq!(report["needs_code"], false);
    // OpenVPN got the same limit for a server that does not answer.
    assert!(sandbox
        .logs(&[])
        .iter()
        .any(|r| r["message"].as_str().unwrap().starts_with("timeout:")));
    let waited = sandbox.run(&["wait", "--until", "connected", "--timeout", "5"], "");
    assert_eq!(waited.code, 7);
    assert_no_secrets(&sandbox, &[&ran]);

    let sandbox = Sandbox::with_settings("login", "[connect]\ntimeout = 25\n");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    let prepared = std::fs::read_to_string(sandbox.runtime_dir().join("cli-test.ovpn")).unwrap();
    assert!(prepared.contains("\nconnect-timeout 25\n"), "{prepared}");
}

/// A `verb` in the extra options used to lose against the `--verb 3` that
/// ovpn-otp put on the command line. Now OpenVPN gets one `--verb`, with
/// the level from the extra options, or else from `openvpn.verb`.
#[test]
fn the_log_level_from_the_settings_reaches_openvpn_once() {
    for (extra, verb) in [
        (
            "[openvpn]\nextra_options = [\"verb 5\", \"mute 10\"]\n",
            "5",
        ),
        (
            "[openvpn]\nextra_options = [\"--verb\", \"6\"]\nverb = 4\n",
            "6",
        ),
        ("[openvpn]\nverb = 4\n", "4"),
        ("", "3"),
    ] {
        let sandbox = Sandbox::with_settings("login", extra);
        let ran = sandbox.connect_background();
        assert_eq!(ran.code, 0, "{extra}: {}", ran.stderr);
        let logs = sandbox.logs(&[]);
        let started = logs
            .iter()
            .filter_map(|r| r["message"].as_str())
            .find(|m| m.starts_with("Started: "))
            .unwrap_or_else(|| panic!("{extra}: no start line"));
        assert!(
            started.ends_with(&format!("--verb {verb}")),
            "{extra}: {started}"
        );
        assert_eq!(started.matches("--verb").count(), 1, "{extra}: {started}");
        let prepared =
            std::fs::read_to_string(sandbox.runtime_dir().join("cli-test.ovpn")).unwrap();
        let added = prepared.split("added by ovpn-otp").nth(1).unwrap();
        assert!(!added.contains("verb"), "{extra}: {added}");
        if extra.contains("mute") {
            assert!(added.contains("mute 10\n"), "{added}");
        }
        let doctor = sandbox.run(&["doctor"], "");
        assert_eq!(
            doctor.stdout.contains(&format!("--verb {verb}")),
            verb != "3",
            "{extra}: {}",
            doctor.stdout
        );
    }
}

/// Every setting can be read and changed by name, the way the window lets
/// you change it.
#[test]
fn config_reads_and_changes_each_setting_by_name() {
    let sandbox = Sandbox::new("login");
    let get = |key: &str| sandbox.run(&["config", "get", key], "");
    assert_eq!(get("name").stdout, "cli-test\n");
    assert_eq!(get("keepalive.ping").stdout, "10\n");
    assert_eq!(get("keepalive.auto_reconnect").stdout, "true\n");
    assert_eq!(get("connect.timeout").stdout, "60\n");
    let unset = get("openvpn.verb");
    assert_eq!((unset.code, unset.stdout.as_str()), (0, ""));
    assert!(unset.stderr.contains("not set"), "{}", unset.stderr);
    assert!(sandbox
        .run(&["config", "get", "openvpn.verb", "--json"], "")
        .json()
        .is_null());

    for (key, values, expect) in [
        ("keepalive.ping", vec!["25"], "25\n"),
        ("keepalive.auto_reconnect", vec!["off"], "false\n"),
        ("check.host", vec!["10.0.0.1:443"], "10.0.0.1:443\n"),
        ("code.digits", vec!["8"], "8\n"),
        ("connect.timeout", vec!["30"], "30\n"),
        ("openvpn.verb", vec!["5"], "5\n"),
        (
            "profile.remote",
            vec!["vpn.example.org:1194"],
            "vpn.example.org:1194\n",
        ),
        (
            "openvpn.extra_options",
            vec!["--mute", "10", "--disable-dco"],
            "--mute\n10\n--disable-dco\n",
        ),
        (
            "openvpn.linux.command_prefix",
            vec!["sudo", "-n"],
            "sudo\n-n\n",
        ),
        ("name", vec!["renamed"], "renamed\n"),
    ] {
        let mut args = vec!["config", "set", key];
        args.extend(values);
        let ran = sandbox.run(&args, "");
        assert_eq!(ran.code, 0, "{args:?}: {}", ran.stderr);
        assert_eq!(get(key).stdout, expect, "{key}");
    }
    // The file on disk is what changed, and nothing else moved.
    let shown = sandbox.run(&["config", "show", "--json"], "").json();
    assert_eq!(shown["name"], "renamed");
    assert_eq!(shown["keepalive"]["ping"], 25);
    assert_eq!(shown["keepalive"]["ping_restart"], 60);
    assert_eq!(shown["keepalive"]["backoff_initial"], 1);
    assert_eq!(shown["connect"]["timeout"], 30);
    assert_eq!(shown["openvpn"]["verb"], 5);
    assert_eq!(shown["openvpn"]["extra_options"][2], "--disable-dco");
    assert_eq!(
        sandbox
            .run(&["config", "get", "openvpn.extra_options", "--json"], "")
            .json(),
        serde_json::json!(["--mute", "10", "--disable-dco"])
    );
    let text = sandbox.run(&["config", "show"], "");
    assert!(text.stdout.contains("ping = 25"), "{}", text.stdout);
    // The profile and the server follow the changed settings at once.
    let status = sandbox.status();
    assert_eq!(status["name"], "renamed");
    assert_eq!(status["servers"][0], "vpn.example.org:1194 (tcp)");

    for key in [
        "keepalive.ping",
        "openvpn.verb",
        "openvpn.linux.command_prefix",
    ] {
        let ran = sandbox.run(&["config", "unset", key], "");
        assert_eq!(ran.code, 0, "{}", ran.stderr);
    }
    assert_eq!(get("keepalive.ping").stdout, "10\n");
    assert_eq!(get("openvpn.verb").stdout, "");
    assert_eq!(get("openvpn.linux.command_prefix").stdout, "");

    // Mistakes end with exit code 2 and change nothing.
    for (args, said) in [
        (
            vec!["config", "get", "ping"],
            "Did you mean keepalive.ping?",
        ),
        (
            vec!["config", "set", "keepalive.ping", "soon"],
            "not a whole number",
        ),
        (
            vec!["config", "set", "openvpn.verb", "99"],
            "highest value is 11",
        ),
        (
            vec!["config", "set", "no.such.key", "1"],
            "there is no setting",
        ),
        (
            vec!["config", "set", "openvpn.extra_options", "-v"],
            "option name",
        ),
        (vec!["config", "unset", "nope"], "there is no setting"),
    ] {
        let ran = sandbox.run(&args, "");
        assert_eq!(ran.code, 2, "{args:?}: {}", ran.stderr);
        assert!(ran.stderr.contains(said), "{args:?}: {}", ran.stderr);
    }
    assert_eq!(get("keepalive.ping").stdout, "10\n");

    // The list of every setting, for people and for scripts.
    let keys = sandbox.run(&["config", "keys"], "");
    for line in [
        "keepalive.ping = 10",
        "connect.timeout = 30",
        "openvpn.verb = (not set)",
    ] {
        assert!(
            keys.stdout.contains(line),
            "`{line}` not in:\n{}",
            keys.stdout
        );
    }
    let keys = sandbox.run(&["config", "keys", "--json"], "").json();
    let names: Vec<&str> = keys
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["key"].as_str().unwrap())
        .collect();
    for name in [
        "name",
        "profile.path",
        "check.host",
        "connect.timeout",
        "openvpn.windows.launch",
    ] {
        assert!(names.contains(&name), "{name} not in {names:?}");
    }
    assert!(keys[0]["help"].is_string() && keys[0]["kind"].is_string());
}

#[test]
fn config_edit_opens_the_editor_and_checks_the_file_afterwards() {
    let sandbox = Sandbox::new("login");
    let ran = sandbox
        .command(&["config", "edit"])
        .env("VISUAL", "")
        .env("EDITOR", "true")
        .output()
        .unwrap();
    assert_eq!(
        ran.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
    assert!(String::from_utf8_lossy(&ran.stderr).contains("is fine"));

    // An editor that leaves a mistake behind: it is said now, not at connect.
    let script = sandbox.dir.path().join("break.sh");
    std::fs::write(&script, "#!/bin/sh\necho 'pasword = \"x\"' >> \"$1\"\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let ran = sandbox
        .command(&["config", "edit"])
        .env("VISUAL", &script)
        .output()
        .unwrap();
    assert_eq!(ran.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&ran.stderr).contains("is not valid"),
        "{}",
        String::from_utf8_lossy(&ran.stderr)
    );
}

#[test]
fn profile_shows_sets_and_lists_the_profile_in_use() {
    let sandbox = Sandbox::new("login");
    let dir = sandbox.dir.path();
    let shown = sandbox.run(&["profile", "show", "--json"], "").json();
    assert_eq!(shown["inline"], true);
    assert!(shown["path"].is_null());
    assert_eq!(shown["servers"][0], "198.51.100.7:8443 (tcp)");
    assert_eq!(shown["static_challenge"], false);
    assert_eq!(shown["notes"].as_array().unwrap().len(), 2);
    let text = sandbox.run(&["profile", "show"], "");
    assert!(
        text.stdout.contains("Profile:    inside the settings file"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("Server:     198.51.100.7:8443 (tcp)"),
        "{}",
        text.stdout
    );

    std::fs::create_dir_all(dir.join("vpn")).unwrap();
    std::fs::write(
        dir.join("vpn/home.ovpn"),
        "client\nremote home.example.org 1194\nremote backup.example.org 443 tcp\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("office.ovpn"),
        "client\nproto tcp\nremote office.example.org 8443\n",
    )
    .unwrap();

    let list = sandbox.run(&["profile", "list", "--json"], "").json();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2, "{list:?}");
    assert!(list.iter().all(|p| p["in_use"] == false));
    assert_eq!(list[0]["servers"][0], "office.example.org:8443 (tcp)");

    let set = sandbox.run(
        &[
            "profile",
            "set",
            dir.join("vpn/home.ovpn").to_str().unwrap(),
        ],
        "",
    );
    assert_eq!(set.code, 0, "{}", set.stderr);
    assert!(
        set.stderr.contains("home.example.org:1194 (udp)"),
        "{}",
        set.stderr
    );
    // Next to the settings file, so the path is kept relative to it.
    assert_eq!(
        sandbox.run(&["config", "get", "profile.path"], "").stdout,
        "vpn/home.ovpn\n"
    );
    let shown = sandbox.run(&["profile", "show", "--json"], "").json();
    assert!(
        shown["path"].as_str().unwrap().ends_with("vpn/home.ovpn"),
        "{shown}"
    );
    assert_eq!(shown["inline"], false);
    assert_eq!(
        shown["servers"],
        serde_json::json!([
            "home.example.org:1194 (udp)",
            "backup.example.org:443 (tcp)"
        ])
    );
    let status = sandbox.status();
    assert!(status["profile"]
        .as_str()
        .unwrap()
        .ends_with("vpn/home.ovpn"));
    assert_eq!(status["servers"][0], "home.example.org:1194 (udp)");

    let list = sandbox.run(&["profile", "list"], "");
    assert_eq!(list.code, 0);
    let lines: Vec<&str> = list.stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{}", list.stdout);
    assert!(
        lines[0].starts_with("  ") && lines[0].contains("office.ovpn"),
        "{}",
        lines[0]
    );
    assert!(
        lines[1].starts_with("* ")
            && lines[1].ends_with("home.example.org:1194 (udp), backup.example.org:443 (tcp)"),
        "{}",
        lines[1]
    );
    // A folder named on the command line is the only one searched.
    let only = sandbox.run(
        &[
            "profile",
            "list",
            dir.join("vpn").to_str().unwrap(),
            "--json",
        ],
        "",
    );
    assert_eq!(only.json().as_array().unwrap().len(), 1);
    assert_eq!(only.json()[0]["in_use"], true);

    let missing = sandbox.run(&["profile", "set", "/nowhere/x.ovpn"], "");
    assert_eq!(missing.code, 1);
    assert!(
        missing.stderr.contains("cannot find the profile"),
        "{}",
        missing.stderr
    );
    // A profile that went missing: `show` says so and ends with 1.
    std::fs::remove_file(dir.join("vpn/home.ovpn")).unwrap();
    let gone = sandbox.run(&["profile", "show"], "");
    assert_eq!(gone.code, 1);
    assert!(gone.stdout.contains("Problem:"), "{}", gone.stdout);
}

/// `reconnect` stops the running session and starts a new one.
#[test]
fn reconnect_replaces_the_running_session() {
    let sandbox = Sandbox::new("login");
    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    let first = sandbox.status()["pid"].as_u64().unwrap();
    let again = sandbox.run(
        &[
            "reconnect",
            "--username",
            USER,
            "--password-stdin",
            "--code-stdin",
            "--background",
            "--json",
        ],
        &format!("{PASSWORD}\n{CODE}\n"),
    );
    assert_eq!(again.code, 0, "stderr: {}", again.stderr);
    assert!(
        again.stderr.contains("Connecting again"),
        "{}",
        again.stderr
    );
    let report = again.json();
    assert_eq!(report["phase"], "connected");
    assert_ne!(report["pid"].as_u64().unwrap(), first, "the same session");
    assert!(!std::path::Path::new(&format!("/proc/{first}")).exists());
    assert_no_secrets(&sandbox, &[&ran, &again]);
    drop(sandbox);

    // With nothing running it is a plain connect.
    let sandbox = Sandbox::new("login");
    let ran = sandbox.run(
        &[
            "reconnect",
            "--username",
            USER,
            "--password-stdin",
            "--code-stdin",
            "--background",
        ],
        &format!("{PASSWORD}\n{CODE}\n"),
    );
    assert_eq!(ran.code, 0, "stderr: {}", ran.stderr);
    assert!(!ran.stderr.contains("Connecting again"));
}

#[test]
fn doctor_and_logs_have_json_and_a_level_filter() {
    let sandbox = Sandbox::new("unreachable");
    let doctor = sandbox.run(&["doctor", "--json"], "");
    // No login is saved in the tests, so one check fails.
    assert_eq!(doctor.code, 1);
    let report = doctor.json();
    assert_eq!(report["ok"], false);
    let checks = report["checks"].as_array().unwrap();
    let check = |name: &str| {
        checks
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("no check `{name}` in {checks:?}"))
    };
    assert_eq!(check("settings")["ok"], true);
    assert_eq!(check("profile")["ok"], true);
    assert!(check("profile")["detail"]
        .as_str()
        .unwrap()
        .contains("198.51.100.7:8443 (tcp)"));
    assert_eq!(check("openvpn")["ok"], true);
    assert_eq!(check("saved login")["ok"], false);
    assert_eq!(report["notes"].as_array().unwrap().len(), 2);

    let ran = sandbox.connect_background();
    assert_eq!(ran.code, 5);
    let all = sandbox.logs(&[]);
    let errors = sandbox.logs(&["--level", "error"]);
    assert!(!errors.is_empty() && errors.len() < all.len());
    assert!(errors
        .iter()
        .all(|r| r["level"] == "error" || r["level"] == "fatal"));
    let warnings = sandbox.logs(&["--level", "warning"]);
    assert!(warnings.len() >= errors.len());
}

/// The saved login is managed without a window too. The tests have no
/// credential store, so only what does not need one is checked here; the
/// rest is tested inside the program with a store in memory.
#[test]
fn login_commands_never_take_the_password_as_an_option() {
    let sandbox = Sandbox::new("login");
    let ran = sandbox.run(&["login", "set", "--password", PASSWORD], "");
    assert_eq!(ran.code, 2, "{}", ran.stderr);
    let ran = sandbox.run(
        &["login", "set", "--password-stdin"],
        &format!("{PASSWORD}\n"),
    );
    assert_ne!(ran.code, 0);
    assert!(!ran.stderr.contains(PASSWORD) && !ran.stdout.contains(PASSWORD));
    let shown = sandbox.run(&["login", "show"], "");
    assert!(!shown.stdout.contains(PASSWORD) && !shown.stderr.contains(PASSWORD));
}
