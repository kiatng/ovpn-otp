//! Commands that look at or steer a running session from outside:
//! `status`, `logs`, `wait`, `code` and `disconnect`.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use chrono::Local;

use ovpn_otp_core::report::{exit_code, outcome_text, wait_verdict, StatusReport, WaitTarget};
use ovpn_otp_core::runtime::{LogRecord, RuntimeDir, StatusFile};
use ovpn_otp_core::session::validate_code;
use ovpn_otp_core::settings;
use ovpn_otp_core::snapshot::{format_bytes, format_duration, Phase};

use crate::{runtime, stdin_line, usage_error, Until};

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

fn report(rt: &RuntimeDir) -> StatusReport {
    StatusReport::from_status(rt.read_status().as_ref())
}

pub fn cmd_disconnect() -> Result<u8> {
    let rt = runtime()?;
    let Some(live) = rt.live_session() else {
        println!("No session is running.");
        return Ok(exit_code::OK);
    };
    rt.request_stop()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match rt.read_status() {
            Some(s) if s.pid == live.pid && s.is_live() => {}
            _ => {
                println!("Disconnected.");
                return Ok(exit_code::OK);
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    bail!("the session (process {}) did not stop within 20s", live.pid)
}

fn print_status(st: &StatusFile) {
    let s = &st.snapshot;
    let now = Local::now();
    let live = st.is_live();
    let phase = if live {
        s.phase.label().to_string()
    } else if s.phase.is_active() {
        "Not running (the session ended without cleaning up)".to_string()
    } else {
        s.phase.label().to_string()
    };
    println!("Connection: {} ({})", st.name, st.settings);
    println!("Status:     {phase}");
    if !live {
        if let Some(kind) = s.failure {
            println!("Reason:     {}", kind.name());
        }
        if let Some(e) = &s.last_error {
            println!("Last error: {e}");
        }
        println!("Updated:    {}", st.updated.format("%Y-%m-%d %H:%M:%S"));
        return;
    }
    println!("OpenVPN:    {} {}", or_dash(&s.state), s.state_detail);
    println!("Server:     {}", or_dash(&s.server));
    println!("Address:    {}", or_dash(&s.local_ip));
    if let Some(since) = s.connected_since {
        println!(
            "Up for:     {}",
            format_duration((now - since).num_seconds())
        );
    }
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
    if let Some(kind) = s.failure {
        println!("Reason:     {}", kind.name());
    }
    if let Some(e) = &s.last_error {
        println!("Last error: {e}");
    }
}

pub fn cmd_status(json: bool) -> Result<u8> {
    let rt = runtime()?;
    let st = rt.read_status();
    if json {
        println!("{}", StatusReport::from_status(st.as_ref()).to_json());
    } else {
        match &st {
            Some(st) => print_status(st),
            None => println!("Status:     Not connected (no session has run yet)"),
        }
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

pub fn cmd_logs(follow: bool, wire: bool, lines: Option<usize>, json: bool) -> Result<u8> {
    let rt = runtime()?;
    let path = rt.log_path();
    let keep = |r: &LogRecord| wire || !r.is_wire();
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
