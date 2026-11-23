//! `ovpn-otp`: command-line client.
//!
//! `connect` runs the session in the foreground (Ctrl+C disconnects), or with
//! `--background` starts it as its own process and returns once it is
//! connected or has failed. From another terminal, `status`, `logs`, `wait`,
//! `code` and `disconnect` work on that session (or on one started by the
//! desktop window) through the runtime files.
//!
//! The exit codes are in [`ovpn_otp_core::report::exit_code`].

mod connect_cmd;
mod control;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use ovpn_otp_core::credentials::{CredentialStore, KeyringStore, Login, Secret};
use ovpn_otp_core::launch::{self, OpenVpnLauncher};
use ovpn_otp_core::report::exit_code;
use ovpn_otp_core::runtime::RuntimeDir;
use ovpn_otp_core::settings::{self};
use ovpn_otp_core::{diagnostics, profile};

#[derive(Parser)]
#[command(
    name = "ovpn-otp",
    version,
    about = "Connect to OpenVPN servers that want a one-time code after the password",
    long_about = "Connect to OpenVPN servers (such as Sophos Firewall SSL VPN) that expect the \
6-digit authenticator code appended to the password. The login is kept in the OS credential \
store; the code is typed separately each time.\n\n\
Settings file: --config, else $OVPN_OTP_CONFIG, else the per-user config folder.",
    after_help = "Exit codes: 0 ok, 1 failed, 2 wrong command line, 3 login rejected, \
4 the server closed the connection during login or shares no cipher, 5 server not reachable, \
6 an authenticator code is needed, 7 timed out, 8 connection dropped."
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
    Connect(ConnectArgs),
    /// Give the authenticator code to a session that is waiting for one.
    Code {
        /// The code. Other users of this machine can see it in the process
        /// list while the command runs; scripts should use --stdin.
        #[arg(value_name = "CODE", conflicts_with = "stdin")]
        code: Option<String>,
        /// Read the code from the first line of standard input.
        #[arg(long)]
        stdin: bool,
    },
    /// Wait until the session is connected, or until it is gone.
    Wait {
        /// What to wait for.
        #[arg(long, value_enum)]
        until: Until,
        /// Give up after this many seconds (exit code 7).
        #[arg(long, value_name = "SECONDS", default_value_t = 60)]
        timeout: u64,
        /// Print the status as JSON when done.
        #[arg(long)]
        json: bool,
    },
    /// Stop the running session.
    Disconnect,
    /// Show the running session (or how the last one ended).
    Status {
        /// Print the status as JSON, with fixed field names.
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
        /// Print each line as a JSON object.
        #[arg(long)]
        json: bool,
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

#[derive(Args)]
struct ConnectArgs {
    /// The authenticator code. Without it you are asked. Other users of this
    /// machine can see it in the process list; scripts should use --code-stdin.
    #[arg(
        long,
        visible_alias = "otp",
        value_name = "CODE",
        conflicts_with = "code_stdin"
    )]
    code: Option<String>,
    /// Read the code from standard input: the first line, or the second line
    /// when --password-stdin is also given.
    #[arg(long)]
    code_stdin: bool,
    /// Use this user name instead of the saved login.
    #[arg(long)]
    username: Option<String>,
    /// Read the password from the first line of standard input instead of
    /// the saved login (for scripts). New codes can follow on later lines.
    #[arg(long)]
    password_stdin: bool,
    /// Start the session as its own process and return when it is connected
    /// or has failed. The exit code says which.
    #[arg(long)]
    background: bool,
    /// With --background: give up after this many seconds, stop the session
    /// and exit with code 7. Default 150.
    #[arg(long, value_name = "SECONDS", requires = "background")]
    timeout: Option<u64>,
    /// With --background: print the status as JSON when done.
    #[arg(long, requires = "background")]
    json: bool,
    /// Also print OpenVPN's log and app details.
    #[arg(short, long)]
    verbose: bool,
    /// Run the session for `connect --background`; the login comes on standard input.
    #[arg(long, hide = true)]
    detached: bool,
}

#[derive(Clone, Copy, ValueEnum)]
enum Until {
    /// The tunnel is up.
    Connected,
    /// No session is running.
    Disconnected,
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

/// A mistake on the command line, such as a code that is not digits. Ends
/// the command with exit code 2, like an unknown option does.
#[derive(Debug)]
struct UsageError(String);

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

fn usage_error(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(UsageError(msg.into()))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) if e.downcast_ref::<UsageError>().is_some() => {
            eprintln!("error: {e}");
            ExitCode::from(exit_code::USAGE)
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(exit_code::FAILED)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    let path = settings::settings_path(cli.config.as_deref());
    match cli.command {
        Cmd::Connect(args) => connect_cmd::cmd_connect(&path, args),
        Cmd::Code { code, stdin } => control::cmd_code(&path, code, stdin),
        Cmd::Wait {
            until,
            timeout,
            json,
        } => control::cmd_wait(until, timeout, json),
        Cmd::Disconnect => control::cmd_disconnect(),
        Cmd::Status { json } => control::cmd_status(json),
        Cmd::Logs {
            follow,
            wire,
            lines,
            json,
        } => control::cmd_logs(follow, wire, lines, json),
        Cmd::Login { username } => cmd_login(&path, username),
        Cmd::Logout => {
            let loaded = settings::load(&path)?;
            KeyringStore.delete(&loaded.settings.name)?;
            println!("Removed the saved login for '{}'.", loaded.settings.name);
            Ok(exit_code::OK)
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

/// One line from standard input, without its line ending. `None` at the end of input.
fn stdin_line() -> Result<Option<String>> {
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        return Ok(None);
    }
    Ok(Some(line.trim_end_matches(['\r', '\n']).to_string()))
}

fn cmd_login(path: &Path, username: Option<String>) -> Result<u8> {
    let loaded = settings::load(path)?;
    let username = match username {
        Some(u) => u,
        None => prompt_line("User name: ")?,
    };
    if username.is_empty() {
        bail!("the user name is empty");
    }
    let password = Secret::new(rpassword::prompt_password("Password (hidden): ")?);
    KeyringStore.save(&loaded.settings.name, &Login { username, password })?;
    println!(
        "Saved the login for '{}' in the OS credential store.",
        loaded.settings.name
    );
    Ok(exit_code::OK)
}

fn cmd_config(path: &Path, action: ConfigCmd) -> Result<u8> {
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
                bail!(
                    "{} already exists (use --force to replace it)",
                    path.display()
                );
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
    Ok(exit_code::OK)
}

fn cmd_diagnostics(path: &Path) -> Result<u8> {
    let loaded = settings::load(path)?;
    let rt = runtime()?;
    let snap = rt.read_status().map(|s| s.snapshot).unwrap_or_default();
    let username = KeyringStore
        .load(&loaded.settings.name)
        .ok()
        .flatten()
        .map(|l| l.username)
        .unwrap_or_default();
    let mut text = diagnostics::bundle(
        &snap,
        &loaded.settings,
        &path.display().to_string(),
        &username,
    );
    let log = rt.read_log();
    if !log.is_empty() {
        let skip = log.len().saturating_sub(400);
        let lines: Vec<String> = log[skip..].iter().map(|r| r.to_text()).collect();
        text.push_str("\n== session log (last 400 lines) ==\n");
        text.push_str(&diagnostics::redact(&lines.join("\n"), &username));
        text.push('\n');
    }
    print!("{text}");
    Ok(exit_code::OK)
}

fn cmd_doctor(path: &Path) -> Result<u8> {
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
        return Ok(exit_code::FAILED);
    };
    // The extra options first: a bad one stops OpenVPN before it connects.
    let extra = profile::extra_option_lines(&loaded.settings.openvpn.extra_options);
    match &extra {
        Ok(lines) if lines.is_empty() => {}
        Ok(lines) => check(
            true,
            "extra options",
            format!("given to OpenVPN as: {}", lines.join("; ")),
        ),
        Err(e) => check(false, "extra options", e.to_string()),
    }
    match loaded.profile_text() {
        Ok((text, _)) => {
            // Read the profile without the extra options, so a mistake in
            // them does not hide what the profile says.
            let mut plain = loaded.settings.clone();
            if extra.is_err() {
                plain.openvpn.extra_options.clear();
            }
            match profile::prepare(&text, &plain) {
                Ok(p) => {
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
                    for note in &p.notes {
                        println!("note profile: {note}");
                    }
                }
                Err(e) => check(false, "profile", e.to_string()),
            }
        }
        Err(e) => check(false, "profile", e.to_string()),
    }
    match OpenVpnLauncher::from_settings(&loaded.settings) {
        Ok(l) => match &l.mode {
            launch::LaunchMode::Service => check(
                true,
                "openvpn",
                "OpenVPN interactive service is running".into(),
            ),
            launch::LaunchMode::Direct { program, prefix } => {
                let version = std::process::Command::new(program)
                    .arg("--version")
                    .output()
                    .ok()
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .lines()
                            .next()
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| "version unknown".into());
                let how = if prefix.is_empty() {
                    String::new()
                } else {
                    format!(", run with `{}`", prefix.join(" "))
                };
                check(
                    true,
                    "openvpn",
                    format!("{} ({version}{how})", program.display()),
                );
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
        Ok(None) => check(
            false,
            "saved login",
            "none yet; run `ovpn-otp login`".into(),
        ),
        Err(e) => check(false, "saved login", e.to_string()),
    }
    Ok(if ok { exit_code::OK } else { exit_code::FAILED })
}
