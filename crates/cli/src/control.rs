//! Commands that look at or steer a running session from outside:
//! `status`, `logs`, `wait`, `code` and `disconnect`.

use std::io::{IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use chrono::Local;

use ovpn_otp_core::connect;
use ovpn_otp_core::credentials::{CredentialStore, KeyringStore};
use ovpn_otp_core::mgmt::LogLevel;
use ovpn_otp_core::report::{exit_code, outcome_text, wait_verdict, StatusReport, WaitTarget};
use ovpn_otp_core::runtime::{LogRecord, RuntimeDir, StatusFile, Using};
use ovpn_otp_core::session::validate_code;
use ovpn_otp_core::settings;
use ovpn_otp_core::snapshot::{format_bytes, format_duration, Phase, Tone};

use crate::{runtime, stdin_line, usage_error, Until};

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

/// The report of the session, without a look at the settings.
fn report(rt: &RuntimeDir) -> StatusReport {
    StatusReport::from_status(rt.read_status().as_ref(), None)
}

/// What the settings say a connect would use right now. The saved user name
/// is read from the credential store; the password is not kept.
fn current_using(path: &Path) -> Option<Using> {
    let loaded = match settings::load(path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("warning: {e}");
            return None;
        }
    };
    let username = KeyringStore
        .load(&loaded.settings.name)
        .ok()
        .flatten()
        .map(|l| l.username)
        .unwrap_or_default();
    Some(connect::describe(&loaded, &username))
}

/// The report with the profile, servers and user name in use filled in.
fn full_report(rt: &RuntimeDir, path: &Path) -> (Option<StatusFile>, StatusReport) {
    let st = rt.read_status();
    // A running session says itself what it uses; the settings and the
    // credential store are only asked when there is none.
    let current = match &st {
        Some(s) if s.is_live() => None,
        _ => current_using(path),
    };
    let report = StatusReport::from_status(st.as_ref(), current.as_ref());
    (st, report)
}

/// Ask the running session to stop and wait until it has. Gives false when
/// there was none.
fn stop_session(rt: &RuntimeDir) -> Result<bool> {
    let Some(live) = rt.live_session() else {
        return Ok(false);
    };
    rt.request_stop()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match rt.read_status() {
            Some(s) if s.pid == live.pid && s.is_live() => {}
            _ => return Ok(true),
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    bail!("the session (process {}) did not stop within 20s", live.pid)
}

pub fn cmd_disconnect(path: &Path, json: bool) -> Result<u8> {
    let rt = runtime()?;
    let said = if stop_session(&rt)? {
        "Disconnected."
    } else {
        "No session is running."
    };
    if json {
        eprintln!("{said}");
        println!("{}", full_report(&rt, path).1.to_json());
    } else {
        println!("{said}");
    }
    Ok(exit_code::OK)
}

/// The first half of `reconnect`: stop what runs, so `connect` can start anew.
pub fn stop_for_reconnect() -> Result<()> {
    let rt = runtime()?;
    if stop_session(&rt)? {
        eprintln!("Disconnected. Connecting again.");
    }
    Ok(())
}

/// Colour for the state word, when a person reads it in a terminal.
fn paint(tone: Tone, text: &str) -> String {
    let colours = std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        // The old Windows console shows the colour codes as text.
        && (!cfg!(windows) || std::env::var_os("WT_SESSION").is_some());
    if !colours {
        return text.to_string();
    }
    let code = match tone {
        Tone::Good => "32",
        Tone::Busy => "36",
        Tone::Attention => "33",
        Tone::Bad => "31",
        Tone::Idle => "2",
    };
    format!("\x1b[1;{code}m{text}\x1b[0m")
}

/// The first lines of `status`: the state, and what is in use.
pub fn status_head(report: &StatusReport, colour: impl Fn(Tone, &str) -> String) -> String {
    let headline = report.headline();
    let mut out = String::new();
    let mut line = |label: &str, value: &str| {
        out.push_str(&format!("{label:<11} {value}\n"));
    };
    let state = colour(headline.tone, &headline.title);
    if headline.detail.is_empty() {
        line("State:", &state);
    } else {
        line("State:", &format!("{state}: {}", headline.detail));
    }
    if let (Some(kind), false) = (report.failure_reason, report.phase == Phase::Connected) {
        line("Reason:", kind.name());
    }
    line("Connection:", report.name.as_deref().unwrap_or("-"));
    line("Settings:", report.settings.as_deref().unwrap_or("-"));
    line(
        "Profile:",
        report
            .profile
            .as_deref()
            .unwrap_or("none yet; choose one with `ovpn-otp profile set FILE`"),
    );
    let mut servers = report.servers.join(", ");
    // The address OpenVPN is talking to, when the profile names the server
    // another way (by name, or several of them).
    if let Some(remote) = report.remote.as_deref().filter(|_| report.running) {
        if !report.servers.iter().any(|s| s.starts_with(remote)) {
            servers = if servers.is_empty() {
                remote.to_string()
            } else {
                format!("{servers}, now at {remote}")
            };
        }
    }
    line("Server:", or_dash(&servers));
    line(
        "User:",
        report
            .username
            .as_deref()
            .unwrap_or("no saved login; save one with `ovpn-otp login set`"),
    );
    out
}

fn print_status(st: Option<&StatusFile>, report: &StatusReport) {
    print!("{}", status_head(report, paint));
    let Some(st) = st.filter(|_| report.running) else {
        if let Some(updated) = report.updated {
            println!(
                "Last session ended: {}",
                updated.format("%Y-%m-%d %H:%M:%S")
            );
        }
        return;
    };
    let s = &st.snapshot;
    let now = Local::now();
    println!("OpenVPN:    {} {}", or_dash(&s.state), s.state_detail);
    println!(
        "Received:   {} ({}/s)",
        format_bytes(s.bytes_in),
        format_bytes(s.rate_in as u64)
    );
    println!(
        "Sent:       {} ({}/s)",
        format_bytes(s.bytes_out),
        format_bytes(s.rate_out as u64)
    );
    if let Some(idle) = s.idle_secs(now) {
        println!("Last data:  {} ago", format_duration(idle));
    }
    if !s.routes.is_empty() {
        println!("Routes:     {}", s.routes.join(", "));
    }
    if !s.dns.is_empty() {
        println!("DNS:        {}", s.dns.join(", "));
    }
    if let Some(r) = &s.reach {
        match (r.ok, r.latency_ms) {
            (true, Some(ms)) => println!("Check:      {} ok, {ms:.1} ms", r.target),
            _ => println!(
                "Check:      {} failed: {}",
                r.target,
                r.error.clone().unwrap_or_default()
            ),
        }
    }
    if s.phase == Phase::NeedCode {
        println!(
            "Waiting for a new code: type it in the window or terminal that started the session, \
             or run `ovpn-otp code --stdin`."
        );
    }
    if let (Some(e), true) = (&s.last_error, s.phase != Phase::Connected) {
        println!("Last error: {e}");
    }
}

pub fn cmd_status(path: &Path, json: bool) -> Result<u8> {
    let rt = runtime()?;
    let (st, report) = full_report(&rt, path);
    if json {
        println!("{}", report.to_json());
    } else {
        print_status(st.as_ref(), &report);
    }
    Ok(exit_code::OK)
}

pub fn cmd_wait(until: Until, timeout: u64, json: bool) -> Result<u8> {
    let rt = runtime()?;
    let target = match until {
        Until::Connected => WaitTarget::Connected,
        Until::Disconnected => WaitTarget::Disconnected,
    };
    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        let now = report(&rt);
        let verdict = wait_verdict(&now, target);
        let timed_out = verdict.is_none() && Instant::now() >= deadline;
        if verdict.is_some() || timed_out {
            let text = outcome_text(&now, target);
            if timed_out {
                eprintln!("Timed out after {timeout} seconds. {text}");
            } else {
                eprintln!("{text}");
            }
            if json {
                println!("{}", now.to_json());
            }
            return Ok(verdict.unwrap_or(exit_code::TIMEOUT));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// How long `code` waits for the session to pick the code up, and then to
/// act on it.
const CODE_WAIT: Duration = Duration::from_secs(8);

pub fn cmd_code(path: &Path, code: Option<String>, from_stdin: bool) -> Result<u8> {
    let code = match (code, from_stdin) {
        (Some(c), _) => c,
        (None, true) => stdin_line()?.unwrap_or_default(),
        (None, false) => {
            return Err(usage_error(
                "give the code as `ovpn-otp code 123456`, or on standard input with --stdin",
            ))
        }
    };
    // The settings say how many digits a code has; without them any length goes.
    let digits = settings::load(path)
        .map(|l| l.settings.code.digits)
        .unwrap_or(0);
    let code = validate_code(&code, digits).map_err(usage_error)?;
    let rt = runtime()?;
    if rt.live_session().is_none() {
        bail!("no session is running, so there is nobody to give the code to. Start one with `ovpn-otp connect`.");
    }
    let was_waiting = report(&rt).needs_code;
    rt.submit_code(&code)?;
    let deadline = Instant::now() + CODE_WAIT;
    while rt.code_waiting() {
        if Instant::now() >= deadline {
            // Never leave a code lying around for a later session to find.
            let _ = rt.take_code();
            bail!(
                "the session did not take the code within {} seconds",
                CODE_WAIT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !was_waiting {
        eprintln!(
            "Code handed to the session. It is used for the next login, if that comes within 90 seconds."
        );
        return Ok(exit_code::OK);
    }
    // The session was waiting: it logs in with the code now. Wait until it has
    // started to, so that a `wait` right after this command sees the new state.
    let deadline = Instant::now() + CODE_WAIT;
    while report(&rt).needs_code {
        if Instant::now() >= deadline {
            eprintln!("The session still asks for a code. See `ovpn-otp status`.");
            return Ok(exit_code::NEEDS_CODE);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("Code handed to the session. Follow it with `ovpn-otp wait --until connected`.");
    Ok(exit_code::OK)
}

/// Print one log line, as text or as the JSON object it is stored as.
/// Gives `false` when nobody reads the output any more (a closed pipe, as
/// with `ovpn-otp logs | head`), which is the moment to stop without an error.
fn print_record(r: &LogRecord, json: bool) -> bool {
    let line = if json {
        serde_json::to_string(r).unwrap_or_default()
    } else {
        r.to_text()
    };
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").and_then(|_| out.flush()).is_ok()
}

pub fn cmd_logs(
    follow: bool,
    wire: bool,
    lines: Option<usize>,
    level: Option<LogLevel>,
    json: bool,
) -> Result<u8> {
    let rt = runtime()?;
    let path = rt.log_path();
    let keep = |r: &LogRecord| keep_record(r, wire, level);
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            // Nothing on standard output, so that `logs --json` stays valid JSON lines.
            eprintln!("No log yet ({}).", path.display());
            return Ok(exit_code::OK);
        }
    };
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let all: Vec<LogRecord> = text
        .lines()
        .filter_map(LogRecord::from_json)
        .filter(|r| keep(r))
        .collect();
    let skip = lines.map(|n| all.len().saturating_sub(n)).unwrap_or(0);
    for r in &all[skip..] {
        if !print_record(r, json) {
            return Ok(exit_code::OK);
        }
    }
    if !follow {
        return Ok(exit_code::OK);
    }
    let mut pos = file.stream_position()?;
    let mut partial = String::new();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len < pos {
            // A new session started a fresh log.
            file = std::fs::File::open(&path)?;
            pos = 0;
        }
        file.seek(SeekFrom::Start(pos))?;
        let mut more = String::new();
        file.read_to_string(&mut more)?;
        pos += more.len() as u64;
        partial.push_str(&more);
        while let Some(i) = partial.find('\n') {
            let line: String = partial.drain(..=i).collect();
            if let Some(r) = LogRecord::from_json(line.trim_end()).filter(|r| keep(r)) {
                if !print_record(&r, json) {
                    return Ok(exit_code::OK);
                }
            }
        }
    }
}

/// Whether `logs` prints a line: the management transcript only with
/// `--wire`, and with `--level` only lines of that level or worse.
fn keep_record(r: &LogRecord, wire: bool, level: Option<LogLevel>) -> bool {
    if r.is_wire() {
        // The transcript has no levels of its own; it is all or nothing.
        return wire;
    }
    level.is_none_or(|min| r.level >= min)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovpn_otp_core::session::FailureKind;

    fn plain(_: Tone, text: &str) -> String {
        text.to_string()
    }

    fn report(edit: impl FnOnce(&mut StatusReport)) -> StatusReport {
        let mut r = StatusReport::idle();
        r.name = Some("work".into());
        r.settings = Some("/x/settings.toml".into());
        r.profile = Some("/x/work.ovpn".into());
        r.servers = vec!["vpn.example.org:8443 (tcp)".into()];
        r.username = Some("alice".into());
        edit(&mut r);
        r
    }

    /// `status` always says which profile, server, connection and user name
    /// are in use, whatever the state.
    #[test]
    fn status_always_shows_what_is_in_use() {
        let idle = status_head(&report(|_| {}), plain);
        assert_eq!(
            idle,
            "State:      Disconnected\n\
             Connection: work\n\
             Settings:   /x/settings.toml\n\
             Profile:    /x/work.ovpn\n\
             Server:     vpn.example.org:8443 (tcp)\n\
             User:       alice\n"
        );

        let connecting = status_head(
            &report(|r| {
                r.running = true;
                r.phase = Phase::Connecting;
                r.state = "Connecting…".into();
                r.state_detail = Some("logging in (12s)".into());
                r.remote = Some("203.0.113.10:8443".into());
            }),
            plain,
        );
        assert!(
            connecting.starts_with("State:      Connecting…: logging in (12s)\n"),
            "{connecting}"
        );
        assert!(
            connecting
                .contains("Server:     vpn.example.org:8443 (tcp), now at 203.0.113.10:8443\n"),
            "{connecting}"
        );
        assert!(connecting.contains("Profile:    /x/work.ovpn\n"));
        assert!(connecting.contains("User:       alice\n"));

        let connected = status_head(
            &report(|r| {
                r.running = true;
                r.phase = Phase::Connected;
                r.state = "Connected".into();
                r.state_detail = Some("address 10.8.0.6, since 14:02:11 (12m 3s)".into());
                r.servers = vec!["203.0.113.10:8443 (tcp)".into()];
                r.remote = Some("203.0.113.10:8443".into());
            }),
            plain,
        );
        assert!(
            connected
                .starts_with("State:      Connected: address 10.8.0.6, since 14:02:11 (12m 3s)\n"),
            "{connected}"
        );
        // The address is the one in the profile: it is not said twice.
        assert!(
            connected.contains("Server:     203.0.113.10:8443 (tcp)\n"),
            "{connected}"
        );

        let failed = status_head(
            &report(|r| {
                r.phase = Phase::Failed;
                r.state = "Failed".into();
                r.state_detail = Some("Could not reach the VPN server.".into());
                r.failure_reason = Some(FailureKind::Unreachable);
            }),
            plain,
        );
        assert!(
            failed.starts_with(
                "State:      Failed: Could not reach the VPN server.\nReason:     unreachable\n"
            ),
            "{failed}"
        );
    }

    #[test]
    fn status_says_what_is_missing_before_the_first_connect() {
        let head = status_head(&StatusReport::idle(), plain);
        assert!(head.contains("Profile:    none yet; choose one with `ovpn-otp profile set FILE`"));
        assert!(head.contains("User:       no saved login; save one with `ovpn-otp login set`"));
        assert!(head.contains("Server:     -\n"));
    }

    #[test]
    fn the_state_word_carries_the_colour_and_the_text() {
        let mark = |tone: Tone, text: &str| format!("<{tone:?}>{text}</>");
        let head = status_head(
            &report(|r| {
                r.running = true;
                r.phase = Phase::Connected;
                r.state = "Connected".into();
            }),
            mark,
        );
        assert!(
            head.starts_with("State:      <Good>Connected</>\n"),
            "{head}"
        );
        let head = status_head(
            &report(|r| {
                r.phase = Phase::Failed;
                r.state = "Failed".into();
            }),
            mark,
        );
        assert!(head.starts_with("State:      <Bad>Failed</>\n"), "{head}");
    }

    #[test]
    fn logs_can_be_cut_down_to_a_level() {
        let record = |source: &str, level: LogLevel| {
            LogRecord::from_json(&format!(
                r#"{{"at":"2026-01-01T10:00:00+00:00","source":"{source}","level":"{level}","message":"m"}}"#
            ))
            .unwrap()
        };
        let info = record("openvpn", LogLevel::Info);
        let error = record("app", LogLevel::Error);
        let wire = record("wire", LogLevel::Debug);
        assert!(keep_record(&info, false, None));
        assert!(!keep_record(&wire, false, None));
        assert!(keep_record(&wire, true, None));
        assert!(!keep_record(&info, false, Some(LogLevel::Warning)));
        assert!(keep_record(&error, false, Some(LogLevel::Warning)));
        // The transcript comes whole when asked for.
        assert!(keep_record(&wire, true, Some(LogLevel::Error)));
    }
}
