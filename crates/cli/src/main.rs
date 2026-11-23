//! `ovpn-otp`: command-line client.
//!
//! `connect` runs the session in the foreground (Ctrl+C disconnects). From
//! another terminal, `status`, `logs` and `disconnect` work on that session
//! (or on one started by the desktop window) through the runtime files.

use std::io::{BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::Local;
use clap::{Parser, Subcommand};

use ovpn_otp_core::credentials::{CredentialStore, KeyringStore, Login, Secret};
use ovpn_otp_core::launch::{self, OpenVpnLauncher};
use ovpn_otp_core::mgmt::LogLevel;
use ovpn_otp_core::runtime::{Recorder, RuntimeDir, StatusFile};
use ovpn_otp_core::session::{validate_code, CodeReason, EndReason, Event};
use ovpn_otp_core::settings::{self, LoadedSettings};
use ovpn_otp_core::snapshot::{format_bytes, format_duration, Phase, Snapshot};
use ovpn_otp_core::{connect, diagnostics};

#[derive(Parser)]
#[command(
    name = "ovpn-otp",
    version,
    about = "Connect to OpenVPN servers that want a one-time code after the password",
    long_about = "Connect to OpenVPN servers (such as Sophos Firewall SSL VPN) that expect the \
6-digit authenticator code appended to the password. The login is kept in the OS credential \
store; the code is typed separately each time.\n\n\
Settings file: --config, else $OVPN_OTP_CONFIG, else the per-user config folder."
)]
struct Cli {
    /// Settings file to use.
    #[arg(long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect and stay connected until Ctrl+C or `ovpn-otp disconnect`.
    Connect {
        /// The authenticator code. Without it you are asked.
        #[arg(long, value_name = "CODE")]
        otp: Option<String>,
        /// Use this user name instead of the saved login.
        #[arg(long)]
        username: Option<String>,
        /// Read the password from the first line of standard input instead of
        /// the saved login (for scripts). New codes can follow on later lines.
        #[arg(long)]
        password_stdin: bool,
        /// Also print OpenVPN's log and app details.
        #[arg(short, long)]
        verbose: bool,
    },
    /// Stop the running session.
    Disconnect,
    /// Show the running session (or how the last one ended).
    Status {
        /// Print the full status as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print the session log.
    Logs {
        /// Keep printing new lines as they come.
        #[arg(short, long)]
        follow: bool,
        /// Include the management interface transcript (secrets are hidden).
        #[arg(long)]
        wire: bool,
        /// Only the last N lines.
        #[arg(short = 'n', long)]
        lines: Option<usize>,
    },
    /// Save the user name and password in the OS credential store.
    Login {
        #[arg(long)]
        username: Option<String>,
    },
    /// Remove the saved login.
    Logout,
    /// Settings file helpers.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Print a report for troubleshooting, with secrets removed.
    Diagnostics,
    /// Check that everything needed to connect is in place.
    Doctor,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print where the settings file is.
    Path,
    /// Print the settings in use.
    Show,
    /// Create a settings file pointing at a profile.
    Init {
        /// The .ovpn profile to use.
        #[arg(long, value_name = "FILE")]
        profile: PathBuf,
        /// A short name for this connection.
        #[arg(long, default_value = "default")]
        name: String,
        /// Overwrite an existing settings file.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let path = settings::settings_path(cli.config.as_deref());
    match cli.command {
        Cmd::Connect {
            otp,
            username,
            password_stdin,
            verbose,
        } => cmd_connect(&path, otp, username, password_stdin, verbose),
        Cmd::Disconnect => cmd_disconnect(),
        Cmd::Status { json } => cmd_status(json),
        Cmd::Logs {
            follow,
            wire,
            lines,
        } => cmd_logs(follow, wire, lines),
        Cmd::Login { username } => cmd_login(&path, username),
        Cmd::Logout => {
            let loaded = settings::load(&path)?;
            KeyringStore.delete(&loaded.settings.name)?;
            println!("Removed the saved login for '{}'.", loaded.settings.name);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Config { action } => cmd_config(&path, action),
        Cmd::Diagnostics => cmd_diagnostics(&path),
        Cmd::Doctor => cmd_doctor(&path),
    }
}

fn runtime() -> Result<RuntimeDir> {
    RuntimeDir::open().context("cannot create the runtime folder")
}

fn prompt_line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Ask for the code with visible input until it looks right.
fn prompt_code(digits: u8) -> Result<String> {
    loop {
        let code = prompt_line(&format!("Authenticator code ({digits} digits, shown as you type): "))?;
        match validate_code(&code, digits) {
            Ok(c) => return Ok(c),
            Err(e) => eprintln!("{e}"),
        }
    }
}

fn get_login(
    loaded: &LoadedSettings,
    username: Option<String>,
    password_stdin: bool,
) -> Result<Login> {
    let name = &loaded.settings.name;
    if password_stdin {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let password = Secret::new(line.trim_end_matches(['\r', '\n']));
        let username = match username {
            Some(u) => u,
            None => match KeyringStore.load(name) {
                Ok(Some(l)) => l.username,
                _ => bail!("--password-stdin needs --username (no saved login for '{name}')"),
            },
        };
        return Ok(Login { username, password });
    }
    if username.is_none() {
        match KeyringStore.load(name) {
            Ok(Some(l)) => return Ok(l),
            Ok(None) => {}
            Err(e) => eprintln!("warning: cannot read the saved login: {e}"),
        }
    }
    if !std::io::stdin().is_terminal() {
        bail!("no saved login for '{name}'. Run `ovpn-otp login` first, or use --username with --password-stdin.");
    }
    let username = match username {
        Some(u) => u,
        None => prompt_line("User name: ")?,
    };
    let password = Secret::new(rpassword::prompt_password("Password (hidden): ")?);
    let login = Login { username, password };
    let answer = prompt_line("Save this login in the OS credential store? [Y/n] ")?;
    if !answer.eq_ignore_ascii_case("n") && !answer.eq_ignore_ascii_case("no") {
        match KeyringStore.save(name, &login) {
            Ok(()) => eprintln!("Saved."),
            Err(e) => eprintln!("warning: could not save the login: {e}"),
        }
    }
    Ok(login)
}

fn cmd_login(path: &Path, username: Option<String>) -> Result<ExitCode> {
    let loaded = settings::load(path)?;
    let username = match username {
        Some(u) => u,
        None => prompt_line("User name: ")?,
    };
    if username.is_empty() {
        bail!("the user name is empty");
    }
    let password = Secret::new(rpassword::prompt_password("Password (hidden): ")?);
    KeyringStore.save(
        &loaded.settings.name,
        &Login {
            username,
            password,
        },
    )?;
    println!(
        "Saved the login for '{}' in the OS credential store.",
        loaded.settings.name
    );
    Ok(ExitCode::SUCCESS)
}

enum Ui {
    Line(String),
    Interrupt,
}

fn cmd_connect(
    path: &Path,
    otp: Option<String>,
    username: Option<String>,
    password_stdin: bool,
    verbose: bool,
) -> Result<ExitCode> {
    let loaded = settings::load(path)?;
    let digits = loaded.settings.code.digits;
    let rt = runtime()?;
    if let Some(live) = rt.live_session() {
        bail!(
            "a session is already running (process {}, {}). Use `ovpn-otp status` or `ovpn-otp disconnect`.",
            live.pid,
            live.snapshot.phase.label()
        );
    }
    let login = get_login(&loaded, username, password_stdin)?;
    let code = match otp {
        Some(c) => Some(validate_code(&c, digits).map_err(anyhow::Error::msg)?),
        None if std::io::stdin().is_terminal() => Some(prompt_code(digits)?),
        None => None,
    };
    let prepared = connect::prepare(&loaded, &rt, login, code)?;
    if let Some(r) = prepared.remotes.first() {
        eprintln!("Connecting to {r} (settings: {})", loaded.path.display());
    }
    let (h, config_path) = prepared.start();

    let (ui_tx, ui_rx) = mpsc::channel();
    let tx = ui_tx.clone();
    ctrlc::set_handler(move || {
        let _ = tx.send(Ui::Interrupt);
    })
    .ok();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if ui_tx.send(Ui::Line(line)).is_err() {
                break;
            }
        }
    });

    let mut rec = Recorder::new(rt.clone(), &loaded.settings.name, &loaded.path);
    let mut snap = Snapshot::default();
    let mut interrupted = false;
    let end = loop {
        match h.events().recv_timeout(Duration::from_millis(300)) {
            Ok(ev) => {
                rec.record(&ev);
                snap.apply(&ev);
                print_event(&ev, &snap, digits, verbose);
                if let Event::Ended { reason } = ev {
                    break reason;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break EndReason::Failed("the session stopped unexpectedly".into())
            }
        }
        while let Ok(msg) = ui_rx.try_recv() {
            match msg {
                Ui::Line(l) if !l.trim().is_empty() => h.send_code(l.trim()),
                Ui::Line(_) => {}
                Ui::Interrupt => {
                    if interrupted {
                        eprintln!("Still stopping; press Ctrl+C again to give up waiting.");
                    }
                    interrupted = true;
                    h.disconnect();
                }
            }
        }
        if rt.take_stop_request() {
            eprintln!("Disconnect requested.");
            h.disconnect();
        }
        rec.write_status(&snap, true, false);
    };
    rec.write_status(&snap, false, true);
    let _ = std::fs::remove_file(config_path);
    h.join();
    Ok(match end {
        EndReason::Disconnected => ExitCode::SUCCESS,
        EndReason::Dropped(_) => ExitCode::from(2),
        EndReason::Failed(_) => ExitCode::from(1),
    })
}

fn hms(t: &chrono::DateTime<Local>) -> String {
    t.format("%H:%M:%S").to_string()
}

fn print_event(ev: &Event, snap: &Snapshot, digits: u8, verbose: bool) {
    match ev {
        Event::Launching { at, attempt } => {
            if *attempt == 0 {
                eprintln!("{}  starting OpenVPN", hms(at));
            } else {
                eprintln!("{}  starting OpenVPN again (try {attempt})", hms(at));
            }
        }
        Event::State { at, info } => {
            let detail = [info.detail.as_str(), info.local_ip.as_str()].join(" ");
            eprintln!("{}  {:<12} {}", hms(at), info.name, detail.trim());
            if info.name == "CONNECTED" {
                eprintln!(
                    "Connected. Tunnel address {}, server {}. Press Ctrl+C to disconnect.",
                    or_dash(&snap.local_ip),
                    or_dash(&snap.server)
                );
                if !snap.routes.is_empty() {
                    eprintln!("Routes from the server: {}", snap.routes.join(", "));
                }
            }
        }
        Event::Log(e) => {
            if verbose || e.level >= LogLevel::Error {
                eprintln!("          openvpn {}: {}", e.level, e.message);
            }
        }
        Event::Note { at, level, text } => {
            if verbose || *level >= LogLevel::Warning {
                eprintln!("{}  {}: {text}", hms(at), level);
            }
        }
        Event::Wire { at, dir, text } => {
            if verbose {
                let arrow = match dir {
                    ovpn_otp_core::session::Direction::In => "<-",
                    ovpn_otp_core::session::Direction::Out => "->",
                };
                eprintln!("{}  {arrow} {text}", hms(at));
            }
        }
        Event::NeedCode { reason } => {
            let why = match reason {
                CodeReason::Initial => "The server is waiting for your code.",
                CodeReason::Reconnect => "Reconnecting: the server wants a new code.",
                CodeReason::Rejected => "Login rejected. Check the code (and the saved password).",
                CodeReason::Expired => "The code waiting to be used is too old.",
            };
            eprintln!("{why}");
            eprint!("Type the {digits}-digit code and press Enter: ");
            std::io::stderr().flush().ok();
        }
        Event::LoginSent { at } => eprintln!("{}  login sent", hms(at)),
        Event::AuthFailed { reason } => eprintln!("Login rejected: {reason}"),
        Event::Reconnecting {
            at,
            attempt,
            delay,
            reason,
        } => eprintln!(
            "{}  connection lost ({reason}); reconnecting in {}s (try {attempt})",
            hms(at),
            delay.as_secs()
        ),
        Event::Reach(r) => {
            if verbose || !r.ok {
                match (r.ok, r.latency_ms) {
                    (true, Some(ms)) => eprintln!("{}  {} reachable, {ms:.1} ms", hms(&r.at), r.target),
                    _ => eprintln!(
                        "{}  {} not reachable: {}",
                        hms(&r.at),
                        r.target,
                        r.error.clone().unwrap_or_default()
                    ),
                }
            }
        }
        Event::Ended { reason } => match reason {
            EndReason::Disconnected => eprintln!("Disconnected."),
            EndReason::Dropped(r) => eprintln!("Connection dropped: {r}"),
            EndReason::Failed(r) => eprintln!("Failed: {r}"),
        },
        Event::Bytes { .. } | Event::Pushed(_) | Event::Version(_) => {}
    }
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

fn cmd_disconnect() -> Result<ExitCode> {
    let rt = runtime()?;
    let Some(live) = rt.live_session() else {
        println!("No session is running.");
        return Ok(ExitCode::SUCCESS);
    };
    rt.request_stop()?;
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match rt.read_status() {
            Some(s) if s.pid == live.pid && s.is_live() => {}
            _ => {
                println!("Disconnected.");
                return Ok(ExitCode::SUCCESS);
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
        println!("Up for:     {}", format_duration((now - since).num_seconds()));
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
        println!("Waiting for a new code in the window or terminal that started the session.");
    }
    if let Some(e) = &s.last_error {
        println!("Last error: {e}");
    }
}

fn cmd_status(json: bool) -> Result<ExitCode> {
    let rt = runtime()?;
    let Some(st) = rt.read_status() else {
        if json {
            println!("{}", serde_json::json!({ "running": false }));
        } else {
            println!("Status:     Not connected (no session has run yet)");
        }
        return Ok(ExitCode::SUCCESS);
    };
    if json {
        let mut v = serde_json::to_value(&st)?;
        v["live"] = serde_json::Value::Bool(st.is_live());
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print_status(&st);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_logs(follow: bool, wire: bool, lines: Option<usize>) -> Result<ExitCode> {
    let rt = runtime()?;
    let path = rt.log_path();
    let keep = |l: &str| wire || !l.contains(" wire    ");
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            println!("No log yet ({}).", path.display());
            return Ok(ExitCode::SUCCESS);
        }
    };
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let all: Vec<&str> = text.lines().filter(|l| keep(l)).collect();
    let skip = lines.map(|n| all.len().saturating_sub(n)).unwrap_or(0);
    for l in &all[skip..] {
        println!("{l}");
    }
    if !follow {
        return Ok(ExitCode::SUCCESS);
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
            let line = line.trim_end();
            if keep(line) {
                println!("{line}");
            }
        }
    }
}

fn cmd_config(path: &Path, action: ConfigCmd) -> Result<ExitCode> {
    match action {
        ConfigCmd::Path => {
            println!("{}", path.display());
            if !path.exists() {
                eprintln!("(the file does not exist yet; create it with `ovpn-otp config init --profile FILE`)");
            }
        }
        ConfigCmd::Show => {
            let loaded = settings::load(path)?;
            println!("# {}", path.display());
            print!("{}", loaded.settings.to_toml());
        }
        ConfigCmd::Init {
            profile,
            name,
            force,
        } => {
            if path.exists() && !force {
                bail!("{} already exists (use --force to replace it)", path.display());
            }
            let profile = std::fs::canonicalize(&profile)
                .with_context(|| format!("cannot find the profile {}", profile.display()))?;
            let mut s = settings::Settings {
                name,
                ..Default::default()
            };
            // Keep the profile path relative when it sits next to the settings file.
            let dir = path.parent().unwrap_or(Path::new("."));
            s.profile.path = match std::fs::canonicalize(dir)
                .ok()
                .and_then(|d| profile.strip_prefix(&d).ok().map(Path::to_path_buf))
            {
                Some(rel) => rel.display().to_string(),
                None => profile.display().to_string(),
            };
            settings::save(path, &s)?;
            println!("Wrote {}", path.display());
            println!("Next: `ovpn-otp login` to save your user name and password.");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_diagnostics(path: &Path) -> Result<ExitCode> {
    let loaded = settings::load(path)?;
    let rt = runtime()?;
    let snap = rt.read_status().map(|s| s.snapshot).unwrap_or_default();
    let username = KeyringStore
        .load(&loaded.settings.name)
        .ok()
        .flatten()
        .map(|l| l.username)
        .unwrap_or_default();
    let mut text = diagnostics::bundle(&snap, &loaded.settings, &path.display().to_string(), &username);
    if let Ok(log) = std::fs::read_to_string(rt.log_path()) {
        let lines: Vec<&str> = log.lines().collect();
        let skip = lines.len().saturating_sub(400);
        text.push_str("\n== session log (last 400 lines) ==\n");
        text.push_str(&diagnostics::redact(&lines[skip..].join("\n"), &username));
        text.push('\n');
    }
    print!("{text}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_doctor(path: &Path) -> Result<ExitCode> {
    let mut ok = true;
    let mut check = |good: bool, what: &str, detail: String| {
        println!("{} {what}: {detail}", if good { "ok  " } else { "FAIL" });
        ok &= good;
    };
    let loaded = settings::load(path);
    match &loaded {
        Ok(l) => check(true, "settings", l.path.display().to_string()),
        Err(e) => check(false, "settings", e.to_string()),
    }
    let Ok(loaded) = loaded else {
        return Ok(ExitCode::from(1));
    };
    match loaded.profile_text() {
        Ok((text, _)) => {
            let p = ovpn_otp_core::profile::prepare(&text, &loaded.settings);
            check(
                true,
                "profile",
                format!(
                    "{} (server {})",
                    loaded
                        .profile_path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "inline".into()),
                    p.remotes.join(", ")
                ),
            );
        }
        Err(e) => check(false, "profile", e.to_string()),
    }
    match OpenVpnLauncher::from_settings(&loaded.settings) {
        Ok(l) => match &l.mode {
            launch::LaunchMode::Service => check(true, "openvpn", "OpenVPN interactive service is running".into()),
            launch::LaunchMode::Direct { program, prefix } => {
                let version = std::process::Command::new(program)
                    .arg("--version")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().next().map(str::to_string))
                    .unwrap_or_else(|| "version unknown".into());
                let how = if prefix.is_empty() {
                    String::new()
                } else {
                    format!(", run with `{}`", prefix.join(" "))
                };
                check(true, "openvpn", format!("{} ({version}{how})", program.display()));
                if prefix.first().map(String::as_str) == Some("sudo") {
                    let sudo_ok = std::process::Command::new("sudo")
                        .args(["-n", "-l", &program.display().to_string()])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    check(
                        sudo_ok,
                        "sudo",
                        if sudo_ok {
                            "openvpn may run without a password prompt".into()
                        } else {
                            "sudo would ask for a password; see the README section \"Linux: let openvpn create the tunnel\"".into()
                        },
                    );
                }
            }
        },
        Err(e) => check(false, "openvpn", e.to_string()),
    }
    match KeyringStore.load(&loaded.settings.name) {
        Ok(Some(l)) => check(true, "saved login", format!("user name '{}'", l.username)),
        Ok(None) => check(false, "saved login", "none yet; run `ovpn-otp login`".into()),
        Err(e) => check(false, "saved login", e.to_string()),
    }
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::from(1) })
}
