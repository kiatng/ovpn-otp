//! `ovpn-otp connect`: in the foreground, or as a background process.
//!
//! With `--background` this command starts a second `ovpn-otp` process that
//! runs the session, hands it the login through a pipe (never on the command
//! line), and waits until the session is connected or has failed. The second
//! process keeps running after this one returns.

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::Local;

use ovpn_otp_core::connect::{self, Prepared};
use ovpn_otp_core::credentials::{CredentialStore, KeyringStore, Login, Secret};
use ovpn_otp_core::launch;
use ovpn_otp_core::mgmt::LogLevel;
use ovpn_otp_core::report::{
    exit_code, failure_exit_code, outcome_text, wait_verdict, StatusReport, WaitTarget,
};
use ovpn_otp_core::runtime::{ConnectRequest, Recorder, RuntimeDir};
use ovpn_otp_core::session::{validate_code, CodeReason, Direction, EndReason, Event};
use ovpn_otp_core::settings::{self, LoadedSettings};
use ovpn_otp_core::snapshot::Snapshot;

use crate::{prompt_line, runtime, stdin_line, usage_error, ConnectArgs};

/// How long `connect --background` waits when `--timeout` is not given.
/// Longer than the 120 seconds OpenVPN itself waits on a server that does
/// not answer, so that such a server ends as "unreachable" and not as a timeout.
const BACKGROUND_TIMEOUT: u64 = 150;

/// Ask for the code with visible input until it looks right.
fn prompt_code(digits: u8) -> Result<String> {
    loop {
        let code = prompt_line(&format!(
            "Authenticator code ({digits} digits, shown as you type): "
        ))?;
        match validate_code(&code, digits) {
            Ok(c) => return Ok(c),
            Err(e) => eprintln!("{e}"),
        }
    }
}

/// The login to use. The user name is always the one the user gave, with
/// `--username` or when they saved the login; it is never guessed.
fn get_login(
    loaded: &LoadedSettings,
    username: Option<String>,
    password_stdin: bool,
) -> Result<Login> {
    let name = &loaded.settings.name;
    if password_stdin {
        let line = stdin_line()?.unwrap_or_default();
        let password = Secret::new(line);
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

pub fn cmd_connect(path: &Path, args: ConnectArgs) -> Result<u8> {
    if args.detached {
        return run_detached(path);
    }
    if args.timeout.is_some() && !args.background && !args.elevate {
        return Err(usage_error(
            "--timeout belongs to --background or --elevate",
        ));
    }
    if args.json && !args.background && !args.elevate {
        return Err(usage_error("--json belongs to --background or --elevate"));
    }
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
    // Warn before the try, not only after the route failure it leads to.
    let advice = launch::rights_advice(&loaded.settings);
    if !advice.is_empty() && !args.elevate {
        eprintln!("warning: {advice}");
    }
    if args.elevate {
        return connect_elevated(path, &loaded, &rt, &args);
    }
    // A person at a terminal can be asked again; a script cannot.
    let asks_a_person = std::io::stdin().is_terminal() && !args.password_stdin && !args.code_stdin;
    let login = get_login(&loaded, args.username, args.password_stdin)?;
    let code = match (args.code, args.code_stdin) {
        (Some(c), _) => Some(validate_code(&c, digits).map_err(usage_error)?),
        (None, true) => {
            let line = stdin_line()?.unwrap_or_default();
            Some(validate_code(&line, digits).map_err(|e| {
                usage_error(format!(
                    "--code-stdin: {e} (no valid code on standard input)"
                ))
            })?)
        }
        (None, false) if asks_a_person => Some(prompt_code(digits)?),
        (None, false) => None,
    };
    if args.background {
        let timeout = Duration::from_secs(args.timeout.unwrap_or(BACKGROUND_TIMEOUT));
        return connect_background(path, &loaded, &rt, &login, code, timeout, args.json);
    }
    let mut prepared = connect::prepare(&loaded, &rt, login, code)?;
    prepared.options.retry_login = asks_a_person;
    let ui = Ui {
        verbose: args.verbose,
        quiet: false,
        codes_from_stdin: true,
        asks_a_person,
    };
    run_session(prepared, rt, &loaded, ui)
}

/// Read the code the way the command line asked for it.
fn code_from_args(args: &ConnectArgs, digits: u8) -> Result<Option<String>> {
    match (&args.code, args.code_stdin) {
        (Some(c), _) => Ok(Some(validate_code(c, digits).map_err(usage_error)?)),
        (None, true) => {
            let line = stdin_line()?.unwrap_or_default();
            Ok(Some(validate_code(&line, digits).map_err(|e| {
                usage_error(format!(
                    "--code-stdin: {e} (no valid code on standard input)"
                ))
            })?))
        }
        (None, false) => Ok(None),
    }
}

/// `connect --elevate`: run the session with the administrator rights the
/// network routes need. On Windows this hands the connect to the desktop
/// window, started elevated when it is not running; the caller then waits for
/// the outcome. Anywhere else, or when this process is already elevated, the
/// session runs right here, like `--background` does.
fn connect_elevated(
    path: &Path,
    loaded: &LoadedSettings,
    rt: &RuntimeDir,
    args: &ConnectArgs,
) -> Result<u8> {
    let digits = loaded.settings.code.digits;
    let timeout = Duration::from_secs(args.timeout.unwrap_or(BACKGROUND_TIMEOUT));
    if !cfg!(windows) {
        eprintln!("note: --elevate is for Windows; on this system the connect runs right here.");
        let login = get_login(loaded, args.username.clone(), args.password_stdin)?;
        let code = code_from_args(args, digits)?;
        return connect_background(path, loaded, rt, &login, code, timeout, args.json);
    }
    if launch::elevated() {
        // Already elevated: a session here has the rights it needs.
        let login = get_login(loaded, args.username.clone(), args.password_stdin)?;
        let code = code_from_args(args, digits)?;
        return connect_background(path, loaded, rt, &login, code, timeout, args.json);
    }
    if !launch::needs_admin(&loaded.settings) {
        // The OpenVPN interactive service runs OpenVPN with the rights it
        // needs, so nothing here has to be elevated.
        eprintln!("note: the OpenVPN interactive service runs the tunnel, so no elevation is needed; connecting right here.");
        let login = get_login(loaded, args.username.clone(), args.password_stdin)?;
        let code = code_from_args(args, digits)?;
        return connect_background(path, loaded, rt, &login, code, timeout, args.json);
    }
    // The window connects with its saved login: the password never passes
    // through another process, and --password-stdin could not reach it anyway.
    if args.password_stdin {
        return Err(usage_error(
            "--elevate uses the saved login; give the password with `ovpn-otp login` first",
        ));
    }
    let code = code_from_args(args, digits)?;
    let saved = KeyringStore
        .load(&loaded.settings.name)
        .map_err(|e| anyhow::anyhow!("cannot read the saved login: {e}"))?;
    let Some(saved) = saved else {
        bail!(
            "the elevated window connects with its saved login, and there is none for '{}'. Run `ovpn-otp login` first.",
            loaded.settings.name
        );
    };
    if let Some(given) = &args.username {
        if !given.trim().is_empty() && given.trim() != saved.username {
            bail!(
                "--elevate uses the saved login for '{}' (user {}), not --username {}.",
                loaded.settings.name,
                saved.username,
                given.trim()
            );
        }
    }
    // A window that runs decides whether the session would be elevated.
    let mut info = rt.read_gui_info().filter(|i| i.pid_alive());
    if let Some(i) = &info {
        if !i.elevated {
            bail!(
                "the ovpn-otp window that runs (process {}) does not have administrator rights, so its session would fail on the network routes. Quit it (in its tray menu), then run this command again: it starts an elevated one.",
                i.pid
            );
        }
    }
    let started = Local::now();
    if info.is_none() {
        start_elevated_window()?;
        info = rt.wait_for_gui_info(Duration::from_secs(15));
        let Some(i) = &info else {
            bail!("the ovpn-otp window did not start within 15 seconds.");
        };
        if !i.elevated {
            bail!(
                "the ovpn-otp window started without administrator rights, so its session would fail on the network routes. Run `ovpn-otp install` once as administrator: it creates the scheduled task that starts the window elevated without asking again."
            );
        }
    }
    let gui_pid = info.map(|i| i.pid).unwrap_or(0);
    rt.submit_connect_request(&ConnectRequest {
        code: code.unwrap_or_default(),
        username: saved.username.clone(),
    })?;
    let own_status = || {
        rt.read_status()
            .filter(|s| s.pid == gui_pid && s.updated >= started)
    };
    let deadline = Instant::now() + timeout;
    loop {
        std::thread::sleep(Duration::from_millis(200));
        if let Some(st) = own_status() {
            let report = StatusReport::from_status(Some(&st), None);
            if let Some(c) = wait_verdict(&report, WaitTarget::Connected) {
                eprintln!("{}", outcome_text(&report, WaitTarget::Connected));
                if args.json {
                    println!("{}", report.to_json());
                }
                return Ok(c);
            }
        }
        if Instant::now() >= deadline {
            // The session belongs to the window; ask it to stop, like
            // `connect --background` stops its own.
            rt.request_stop()?;
            let stop_by = Instant::now() + Duration::from_secs(15);
            while Instant::now() < stop_by {
                match own_status() {
                    Some(st) if !st.running => break,
                    _ => std::thread::sleep(Duration::from_millis(200)),
                }
            }
            eprintln!(
                "Not connected within {} seconds. The window was asked to stop the session.",
                timeout.as_secs()
            );
            if args.json {
                println!(
                    "{}",
                    StatusReport::from_status(own_status().as_ref(), None).to_json()
                );
            }
            return Ok(exit_code::TIMEOUT);
        }
    }
}

/// Start the desktop window with administrator rights: through the scheduled
/// task that `ovpn-otp install` creates (no prompt), or with one UAC prompt.
#[cfg(windows)]
fn start_elevated_window() -> Result<()> {
    if Command::new("schtasks")
        .args(["/Run", "/TN", crate::install_cmd::APP_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return Ok(());
    }
    let gui = find_gui()?;
    let script = format!(
        "Start-Process -FilePath {} -Verb RunAs",
        crate::install_cmd::ps_quote(&gui.display().to_string())
    );
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .context("cannot run PowerShell to ask Windows for administrator rights")?;
    if !out.status.success() {
        bail!(
            "Windows refused to start the window as administrator (was the UAC prompt accepted?). Run `ovpn-otp install` once as administrator so the scheduled task exists."
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn start_elevated_window() -> Result<()> {
    bail!("--elevate is for Windows")
}

/// The desktop window next to this program, or the installed one.
#[cfg(windows)]
fn find_gui() -> Result<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("ovpn-otp-gui.exe");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let installed = std::path::PathBuf::from(local)
            .join("Programs")
            .join(crate::install_cmd::APP_NAME)
            .join("ovpn-otp-gui.exe");
        if installed.is_file() {
            return Ok(installed);
        }
    }
    bail!(
        "no ovpn-otp-gui.exe was found. Run `ovpn-otp install` first: it puts the programs in place and creates the scheduled task that starts the window without a UAC prompt."
    )
}

/// How the session talks to whoever started it.
struct Ui {
    verbose: bool,
    /// Print nothing: nobody reads the output of a background session.
    quiet: bool,
    /// Take new codes from the lines of standard input.
    codes_from_stdin: bool,
    /// Someone sits at the terminal and can type a code when asked.
    asks_a_person: bool,
}

enum Input {
    Line(String),
    Interrupt,
}

/// Run a session until it ends. Gives the exit code for how it ended.
fn run_session(prepared: Prepared, rt: RuntimeDir, loaded: &LoadedSettings, ui: Ui) -> Result<u8> {
    let digits = loaded.settings.code.digits;
    if !ui.quiet {
        // Say what is used before anything is tried.
        let using = &prepared.using;
        eprintln!("Connection: {} ({})", using.name, using.settings);
        eprintln!("Profile:    {}", using.profile);
        eprintln!("Server:     {}", using.servers.join(", "));
        eprintln!("User:       {}", using.username);
    }
    let mut rec = Recorder::new(rt.clone(), prepared.using.clone());
    let (h, config_path) = prepared.start();

    let (ui_tx, ui_rx) = mpsc::channel();
    let tx = ui_tx.clone();
    // Ctrl+C, and also a polite stop from outside (SIGTERM, SIGHUP), so that
    // OpenVPN is stopped with the session instead of left running.
    ctrlc::set_handler(move || {
        let _ = tx.send(Input::Interrupt);
    })
    .ok();
    if ui.codes_from_stdin {
        std::thread::spawn(move || {
            while let Ok(Some(line)) = stdin_line() {
                if ui_tx.send(Input::Line(line)).is_err() {
                    break;
                }
            }
        });
    }

    let mut snap = Snapshot::default();
    let mut interrupted = false;
    let end = loop {
        match h.events().recv_timeout(Duration::from_millis(300)) {
            Ok(ev) => {
                rec.record(&ev);
                snap.apply(&ev);
                if !ui.quiet {
                    print_event(&ev, &snap, digits, &ui);
                }
                if let Event::Ended { reason } = ev {
                    break reason;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break EndReason::Failed(ovpn_otp_core::session::Failure::other(
                    "the session stopped unexpectedly",
                ))
            }
        }
        while let Ok(msg) = ui_rx.try_recv() {
            match msg {
                Input::Line(l) if !l.trim().is_empty() => h.send_code(l.trim()),
                Input::Line(_) => {}
                Input::Interrupt => {
                    if interrupted && !ui.quiet {
                        eprintln!("Still stopping; press Ctrl+C again to give up waiting.");
                    }
                    interrupted = true;
                    h.disconnect();
                }
            }
        }
        // A code from `ovpn-otp code`.
        if let Some(code) = rt.take_code() {
            h.send_code(&code);
        }
        if rt.take_stop_request() {
            if !ui.quiet {
                eprintln!("Disconnect requested.");
            }
            h.disconnect();
        }
        rec.write_status(&snap, true, false);
    };
    rec.write_status(&snap, false, true);
    let _ = std::fs::remove_file(config_path);
    h.join();
    Ok(match end {
        EndReason::Disconnected => exit_code::OK,
        EndReason::Dropped(_) => exit_code::DROPPED,
        EndReason::Failed(f) => failure_exit_code(f.kind),
    })
}

/// The session process behind `connect --background`.
///
/// The login arrives on standard input, one value per line: user name,
/// password, code (an empty line when there is none yet).
fn run_detached(path: &Path) -> Result<u8> {
    let username = stdin_line()?.unwrap_or_default();
    let password = Secret::new(stdin_line()?.unwrap_or_default());
    let code = stdin_line()?.filter(|c| !c.is_empty());
    let loaded = settings::load(path)?;
    let rt = runtime()?;
    let mut prepared = connect::prepare(&loaded, &rt, Login { username, password }, code)?;
    prepared.options.retry_login = false;
    let ui = Ui {
        verbose: false,
        quiet: true,
        codes_from_stdin: false,
        asks_a_person: false,
    };
    run_session(prepared, rt, &loaded, ui)
}

/// Keep the session process running after this command, and out of reach of
/// Ctrl+C typed in this terminal.
fn detach(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
}

fn connect_background(
    path: &Path,
    loaded: &LoadedSettings,
    rt: &RuntimeDir,
    login: &Login,
    code: Option<String>,
    timeout: Duration,
    json: bool,
) -> Result<u8> {
    if login.username.trim().is_empty() {
        bail!(
            "no user name for '{}'; give one with --username or save the login with `ovpn-otp login`",
            loaded.settings.name
        );
    }
    // Find mistakes in the settings now, while there is a terminal to say so.
    connect::check(loaded)?;

    let exe = std::env::current_exe().context("cannot find the ovpn-otp program itself")?;
    let settings_path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    // What the session process prints if it cannot start; the folder is private.
    let err_path = rt.path.join("background.err");
    let err_file = std::fs::File::create(&err_path)
        .with_context(|| format!("cannot write {}", err_path.display()))?;
    let mut cmd = Command::new(exe);
    cmd.arg("--config")
        .arg(&settings_path)
        .args(["connect", "--detached"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(err_file);
    detach(&mut cmd);
    // The child gets every inheritable handle this process holds; keep the
    // terminal's pipes out of it, or WSL would wait for the whole session.
    launch::detach_stdio();
    let started = Local::now();
    let mut child = cmd.spawn().context("cannot start the background session")?;
    {
        // The login goes through a pipe, so it is in no process list and no file.
        let mut pipe = child.stdin.take().expect("the pipe was asked for");
        let lines = Secret::new(format!(
            "{}\n{}\n{}\n",
            login.username.trim(),
            login.password.expose(),
            code.as_deref().unwrap_or("")
        ));
        pipe.write_all(lines.expose().as_bytes())
            .context("cannot hand the login to the background session")?;
    }
    let pid = child.id();
    // Only the status this session wrote counts, not one left by an earlier session.
    let own_status = || {
        rt.read_status()
            .filter(|s| s.pid == pid && s.updated >= started)
    };
    let finish = |report: &StatusReport, code: u8| {
        eprintln!("{}", outcome_text(report, WaitTarget::Connected));
        if json {
            println!("{}", report.to_json());
        }
        Ok(code)
    };

    let deadline = Instant::now() + timeout;
    loop {
        if let Some(st) = own_status() {
            let report = StatusReport::from_status(Some(&st), None);
            if let Some(code) = wait_verdict(&report, WaitTarget::Connected) {
                return finish(&report, code);
            }
        }
        if child.try_wait()?.is_some() {
            // It ended: the last status it wrote says how.
            if let Some(st) = own_status() {
                let report = StatusReport::from_status(Some(&st), None);
                let code =
                    wait_verdict(&report, WaitTarget::Connected).unwrap_or(exit_code::FAILED);
                return finish(&report, code);
            }
            let said = std::fs::read_to_string(&err_path).unwrap_or_default();
            bail!(
                "the background session ended before it could start. {}",
                said.trim().trim_start_matches("error: ")
            );
        }
        if Instant::now() >= deadline {
            rt.request_stop()?;
            let stop_by = Instant::now() + Duration::from_secs(15);
            while child.try_wait()?.is_none() && Instant::now() < stop_by {
                std::thread::sleep(Duration::from_millis(150));
            }
            let stopped = child.try_wait()?.is_some();
            eprintln!(
                "Not connected within {} seconds. {}",
                timeout.as_secs(),
                if stopped {
                    "The session was stopped."
                } else {
                    "The session did not stop; run `ovpn-otp disconnect`."
                }
            );
            if json {
                println!(
                    "{}",
                    StatusReport::from_status(own_status().as_ref(), None).to_json()
                );
            }
            return Ok(exit_code::TIMEOUT);
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

fn hms(t: &chrono::DateTime<Local>) -> String {
    t.format("%H:%M:%S").to_string()
}

fn or_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

fn print_event(ev: &Event, snap: &Snapshot, digits: u8, ui: &Ui) {
    let verbose = ui.verbose;
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
                    Direction::In => "<-",
                    Direction::Out => "->",
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
                CodeReason::Retry => {
                    "The last try failed, and the code it used cannot be used again."
                }
            };
            eprintln!("{why}");
            if ui.asks_a_person {
                eprint!("Type the {digits}-digit code and press Enter: ");
                std::io::stderr().flush().ok();
            } else {
                eprintln!(
                    "Waiting for a {digits}-digit code: run `ovpn-otp code --stdin`, or send it on standard input."
                );
            }
        }
        Event::LoginSent { at } => eprintln!("{}  login sent", hms(at)),
        Event::AuthFailed { reason } => eprintln!("Login rejected: {reason}"),
        Event::ConnectFailed { failure, .. } => eprintln!("{}", failure.message),
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
                    (true, Some(ms)) => {
                        eprintln!("{}  {} reachable, {ms:.1} ms", hms(&r.at), r.target)
                    }
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
            // A failed try already printed its message.
            EndReason::Failed(f) if snap.timeline.iter().any(|t| t.state == "FAILED") => {
                eprintln!("Failed ({}).", f.kind.name())
            }
            EndReason::Failed(f) => eprintln!("Failed: {}", f.message),
        },
        Event::Bytes { .. } | Event::Pushed(_) | Event::Version(_) => {}
    }
}
