//! `ovpn-otp`: command-line client.
//!
//! `connect` runs the session in the foreground (Ctrl+C disconnects), or with
//! `--background` starts it as its own process and returns once it is
//! connected or has failed. From another terminal, `status`, `logs`, `wait`,
//! `code`, `disconnect` and `reconnect` work on that session (or on one
//! started by the desktop window) through the runtime files.
//!
//! Everything the window can do or set is a command here: `config` reads and
//! changes every setting, `profile` chooses the profile, `login` keeps the
//! saved login.
//!
//! The exit codes are in [`ovpn_otp_core::report::exit_code`].

mod connect_cmd;
mod control;
mod install_cmd;
mod settings_cmd;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

use ovpn_otp_core::credentials::{CredentialStore, KeyringStore};
use ovpn_otp_core::launch::{self, OpenVpnLauncher};
use ovpn_otp_core::mgmt::LogLevel;
use ovpn_otp_core::report::exit_code;
use ovpn_otp_core::runtime::RuntimeDir;
use ovpn_otp_core::settings::{self};
use ovpn_otp_core::{connect, diagnostics, profile};

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
6 an authenticator code is needed, 7 timed out or no progress, 8 connection dropped."
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
    /// Install the latest verified release.
    Update,
    /// Put the programs where the system and other programs find them.
    Install(install_cmd::InstallArgs),
    /// Remove what `install` put in place.
    Uninstall,
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
    Disconnect {
        /// Print the status as JSON when done.
        #[arg(long)]
        json: bool,
    },
    /// Stop the running session, if there is one, and connect again. Takes
    /// the same options as `connect`.
    Reconnect(ConnectArgs),
    /// Show the state, and the profile, server and user name in use.
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
        /// Only lines of this level or worse.
        #[arg(long, value_enum, value_name = "LEVEL")]
        level: Option<Level>,
        /// Print each line as a JSON object.
        #[arg(long)]
        json: bool,
    },
    /// The saved login: `login set`, `login show`, `login clear`. Without a
    /// word after it, `login` saves a login.
    #[command(args_conflicts_with_subcommands = true)]
    Login {
        #[command(subcommand)]
        action: Option<LoginCmd>,
        /// The user name to save.
        #[arg(long)]
        username: Option<String>,
        /// Read the password from the first line of standard input.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove the saved login (the same as `login clear`).
    Logout,
    /// The profile in use: `profile show`, `profile set FILE`, `profile list`.
    Profile {
        #[command(subcommand)]
        action: ProfileCmd,
    },
    /// The settings: show them, or read and change one by its name.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Print a report for troubleshooting, with secrets removed.
    Diagnostics,
    /// Check that everything needed to connect is in place.
    Doctor {
        /// Print the checks as JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum LoginCmd {
    /// Save the user name and password in the OS credential store.
    Set {
        /// The user name. Without it you are asked.
        #[arg(long)]
        username: Option<String>,
        /// Read the password from the first line of standard input (for
        /// scripts). Without it you are asked, and the typing is hidden.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show the saved user name. The password is never shown.
    Show {
        /// Print it as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove the saved login.
    Clear,
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Show the profile in use and the servers it points at.
    Show {
        /// Print it as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Use this .ovpn file from now on.
    Set {
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
    /// List the .ovpn files next to the settings file and where OpenVPN
    /// keeps its own, or in the folders you name.
    List {
        #[arg(value_name = "FOLDER")]
        folders: Vec<PathBuf>,
        /// Print the list as JSON.
        #[arg(long)]
        json: bool,
    },
}

/// The levels of a log line, for `logs --level`.
#[derive(Clone, Copy, ValueEnum)]
enum Level {
    Debug,
    Info,
    Warning,
    Error,
}

impl Level {
    fn at_least(self) -> LogLevel {
        match self {
            Level::Debug => LogLevel::Debug,
            Level::Info => LogLevel::Info,
            Level::Warning => LogLevel::Warning,
            Level::Error => LogLevel::Error,
        }
    }
}

#[derive(Args, Clone)]
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
    /// Windows: run the session in the desktop window instead, started with
    /// the administrator rights the network routes need. The login must be
    /// saved (`ovpn-otp login`); the code still comes from --code or
    /// --code-stdin. The window is started when it is not running, through
    /// the scheduled task that `ovpn-otp install` creates, or with one UAC
    /// prompt.
    #[arg(long, conflicts_with = "background")]
    elevate: bool,
    /// With --background or --elevate: give up after this many seconds, stop
    /// the session and exit with code 7. Default 150.
    #[arg(long, value_name = "SECONDS")]
    timeout: Option<u64>,
    /// With --background or --elevate: print the status as JSON when done.
    #[arg(long)]
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
    Show {
        /// Print them as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print one setting, such as `keepalive.ping`.
    Get {
        #[arg(value_name = "KEY")]
        key: String,
        /// Print the value as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Change one setting: `config set keepalive.ping 20`. A list takes one
    /// word per item: `config set openvpn.extra_options "mute 10" "disable-dco"`.
    Set {
        #[arg(value_name = "KEY")]
        key: String,
        #[arg(value_name = "VALUE", allow_hyphen_values = true)]
        values: Vec<String>,
    },
    /// Put one setting back to its default.
    Unset {
        #[arg(value_name = "KEY")]
        key: String,
    },
    /// List every setting with its value and what it does.
    Keys {
        /// Print the list as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Open the settings file in your editor ($VISUAL, then $EDITOR), and
    /// check it when you close the editor.
    Edit,
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
        Cmd::Update => {
            match ovpn_otp_core::update::check().map_err(anyhow::Error::msg)? {
                Some(release) => {
                    println!("Installing version {}...", release.version);
                    ovpn_otp_core::update::install(&release).map_err(anyhow::Error::msg)?;
                    println!("Updated to version {}.", release.version);
                }
                None => println!("Already up to date."),
            }
            Ok(exit_code::OK)
        }
        Cmd::Connect(args) => connect_cmd::cmd_connect(&path, args),
        Cmd::Install(args) => install_cmd::cmd_install(args),
        Cmd::Uninstall => install_cmd::cmd_uninstall(),
        Cmd::Code { code, stdin } => control::cmd_code(&path, code, stdin),
        Cmd::Wait {
            until,
            timeout,
            json,
        } => control::cmd_wait(until, timeout, json),
        Cmd::Disconnect { json } => control::cmd_disconnect(&path, json),
        Cmd::Reconnect(args) => {
            control::stop_for_reconnect()?;
            connect_cmd::cmd_connect(&path, args)
        }
        Cmd::Status { json } => control::cmd_status(&path, json),
        Cmd::Logs {
            follow,
            wire,
            lines,
            level,
            json,
        } => control::cmd_logs(follow, wire, lines, level.map(Level::at_least), json),
        Cmd::Login {
            action,
            username,
            password_stdin,
        } => settings_cmd::cmd_login(
            &KeyringStore,
            &path,
            action.unwrap_or(LoginCmd::Set {
                username,
                password_stdin,
            }),
        ),
        Cmd::Logout => settings_cmd::cmd_login(&KeyringStore, &path, LoginCmd::Clear),
        Cmd::Profile { action } => settings_cmd::cmd_profile(&path, action),
        Cmd::Config { action } => settings_cmd::cmd_config(&path, action),
        Cmd::Diagnostics => cmd_diagnostics(&path),
        Cmd::Doctor { json } => cmd_doctor(&path, json),
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

/// The checks `doctor` made, in order.
#[derive(Default)]
struct Doctor {
    /// What was checked, whether it is fine, and what was found.
    checks: Vec<(String, bool, String)>,
    /// Things worth knowing that are not a problem.
    notes: Vec<String>,
}

impl Doctor {
    fn check(&mut self, good: bool, what: &str, detail: String) {
        self.checks.push((what.to_string(), good, detail));
    }

    fn ok(&self) -> bool {
        self.checks.iter().all(|(_, good, _)| *good)
    }

    fn print(&self, json: bool) {
        if json {
            let checks: Vec<_> = self
                .checks
                .iter()
                .map(|(name, ok, detail)| {
                    serde_json::json!({"name": name, "ok": ok, "detail": detail})
                })
                .collect();
            let all = serde_json::json!({"ok": self.ok(), "checks": checks, "notes": self.notes});
            println!(
                "{}",
                serde_json::to_string_pretty(&all).expect("JSON values always print")
            );
            return;
        }
        for (what, good, detail) in &self.checks {
            println!("{} {what}: {detail}", if *good { "ok  " } else { "FAIL" });
        }
        for note in &self.notes {
            println!("note {note}");
        }
    }
}

fn cmd_doctor(path: &Path, json: bool) -> Result<u8> {
    let mut doctor = Doctor::default();
    run_doctor(path, &mut doctor);
    doctor.print(json);
    Ok(if doctor.ok() {
        exit_code::OK
    } else {
        exit_code::FAILED
    })
}

fn run_doctor(path: &Path, doctor: &mut Doctor) {
    let loaded = settings::load(path);
    match &loaded {
        Ok(l) => doctor.check(true, "settings", l.path.display().to_string()),
        Err(e) => doctor.check(false, "settings", e.to_string()),
    }
    let Ok(loaded) = loaded else {
        return;
    };
    // The extra options first: a bad one stops OpenVPN before it connects.
    let extra = profile::extra_option_lines(&loaded.settings.openvpn.extra_options);
    match &extra {
        Ok(lines) if lines.is_empty() => {}
        Ok(lines) => doctor.check(
            true,
            "extra options",
            format!("given to OpenVPN as: {}", lines.join("; ")),
        ),
        Err(e) => doctor.check(false, "extra options", e.to_string()),
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
                    doctor.check(
                        true,
                        "profile",
                        format!(
                            "{} (server {})",
                            loaded
                                .profile_path()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "inline".into()),
                            p.server_labels().join(", ")
                        ),
                    );
                    for note in &p.notes {
                        doctor.notes.push(format!("profile: {note}"));
                    }
                    let verb = connect::effective_verb(&plain, &p);
                    if verb != 3 {
                        doctor.notes.push(format!(
                            "log level: OpenVPN runs with --verb {verb} (from {})",
                            if p.verb.is_some() {
                                "a verb in extra_options"
                            } else {
                                "the setting openvpn.verb"
                            }
                        ));
                    }
                }
                Err(e) => doctor.check(false, "profile", e.to_string()),
            }
        }
        Err(e) => doctor.check(false, "profile", e.to_string()),
    }
    match OpenVpnLauncher::from_settings(&loaded.settings) {
        Ok(l) => match &l.mode {
            launch::LaunchMode::Service => doctor.check(
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
                doctor.check(
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
                    doctor.check(
                        sudo_ok,
                        "sudo",
                        if sudo_ok {
                            "openvpn may run without a password prompt".into()
                        } else {
                            "sudo would ask for a password; see the README section \"Linux: let openvpn create the tunnel\"".into()
                        },
                    );
                }
                if cfg!(windows) {
                    if launch::elevated() {
                        doctor.check(
                            true,
                            "rights",
                            "ovpn-otp runs as administrator, so OpenVPN may add the network routes"
                                .into(),
                        );
                    } else {
                        doctor.check(
                            false,
                            "rights",
                            "ovpn-otp does not run as administrator, and OpenVPN is started directly: adding the network routes will fail. Start ovpn-otp as administrator, or let the OpenVPN Interactive Service start OpenVPN (see the README).".into(),
                        );
                    }
                }
            }
        },
        Err(e) => doctor.check(false, "openvpn", e.to_string()),
    }
    match KeyringStore.load(&loaded.settings.name) {
        Ok(Some(l)) => doctor.check(true, "saved login", format!("user name '{}'", l.username)),
        Ok(None) => doctor.check(
            false,
            "saved login",
            "none yet; run `ovpn-otp login`".into(),
        ),
        Err(e) => doctor.check(false, "saved login", e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("ovpn-otp").chain(args.iter().copied()))
    }

    /// Every command the README promises is there, with the options it names.
    #[test]
    fn every_documented_command_parses() {
        for args in [
            vec!["profile", "show"],
            vec!["profile", "show", "--json"],
            vec!["profile", "set", "work.ovpn"],
            vec!["profile", "list"],
            vec!["profile", "list", "/etc/openvpn/client", "--json"],
            vec!["config", "path"],
            vec!["config", "show", "--json"],
            vec!["config", "get", "keepalive.ping", "--json"],
            vec!["config", "set", "keepalive.ping", "20"],
            vec![
                "config",
                "set",
                "openvpn.extra_options",
                "mute 10",
                "--disable-dco",
            ],
            vec![
                "config",
                "set",
                "openvpn.linux.command_prefix",
                "sudo",
                "-n",
            ],
            vec!["config", "set", "openvpn.extra_options"],
            vec!["config", "unset", "openvpn.verb"],
            vec!["config", "keys", "--json"],
            vec!["config", "edit"],
            vec!["config", "init", "--profile", "work.ovpn"],
            vec!["login"],
            vec!["login", "--username", "alice", "--password-stdin"],
            vec!["login", "set", "--username", "alice", "--password-stdin"],
            vec!["login", "show", "--json"],
            vec!["login", "clear"],
            vec!["logout"],
            vec![
                "connect",
                "--code-stdin",
                "--background",
                "--json",
                "--timeout",
                "30",
            ],
            vec!["reconnect", "--code-stdin", "--background", "--json"],
            vec!["disconnect", "--json"],
            vec!["status", "--json"],
            vec![
                "logs", "-f", "--wire", "-n", "50", "--level", "warning", "--json",
            ],
            vec!["doctor", "--json"],
            vec!["diagnostics"],
            vec!["code", "--stdin"],
            vec!["wait", "--until", "connected", "--timeout", "5", "--json"],
            vec!["--config", "/x/settings.toml", "status"],
        ] {
            if let Err(e) = parse(&args) {
                panic!("`ovpn-otp {}` is refused: {e}", args.join(" "));
            }
        }
    }

    #[test]
    fn wrong_command_lines_are_refused() {
        for args in [
            vec!["profile"],
            vec!["profile", "set"],
            vec!["config", "get"],
            vec!["config", "set"],
            vec!["login", "show", "--username", "alice"],
            vec!["login", "--username", "alice", "show"],
            vec!["logs", "--level", "loud"],
            vec!["reconnect", "--elevate", "--background"],
            vec!["connect", "--elevate", "--background"],
        ] {
            assert!(
                parse(&args).is_err(),
                "`ovpn-otp {}` was taken",
                args.join(" ")
            );
        }
    }

    #[test]
    fn config_set_takes_the_values_as_they_are() {
        let cli = parse(&["config", "set", "openvpn.extra_options", "--mute", "10"]).unwrap();
        let Cmd::Config {
            action: ConfigCmd::Set { key, values },
        } = cli.command
        else {
            panic!("not config set")
        };
        assert_eq!(key, "openvpn.extra_options");
        assert_eq!(values, vec!["--mute", "10"]);
    }

    #[test]
    fn doctor_prints_its_checks_as_text_and_knows_when_one_failed() {
        let mut doctor = Doctor::default();
        doctor.check(true, "settings", "/x/settings.toml".into());
        assert!(doctor.ok());
        doctor.check(false, "saved login", "none yet".into());
        doctor.notes.push("profile: something was changed".into());
        assert!(!doctor.ok());
        assert_eq!(doctor.checks.len(), 2);
    }
}
