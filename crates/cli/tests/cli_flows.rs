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
    let test_exe = std::env::current_exe().unwrap();
    let debug_dir = test_exe.parent().unwrap().parent().unwrap();
    let fake = debug_dir.join("examples").join("fake_openvpn");
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
