//! `ovpn-otp install` and `ovpn-otp uninstall`: put the programs where the
//! operating system and other programs find them.
//!
//! Windows: the programs go to `%LOCALAPPDATA%\Programs\ovpn-otp`, the CLI is
//! put on the user PATH, and a scheduled task named `ovpn-otp` is created that
//! starts the window with administrator rights (the network routes need them).
//! The Start-menu shortcut runs that task, so one `install` as administrator
//! is enough and starting the app never asks again.
//!
//! Linux: the programs go to `~/.local/bin` and a `.desktop` entry is written,
//! so the app launcher finds the window.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// The name of the scheduled task and of the Start-menu entry (Windows).
pub const APP_NAME: &str = "ovpn-otp";

#[derive(clap::Args, Debug, Default)]
pub struct InstallArgs {
    /// Create only what needs administrator rights: the scheduled task that
    /// starts the window elevated. Used by `install` itself when it relaunches
    /// itself with the UAC prompt.
    #[arg(long, hide = true)]
    pub elevated_part: bool,
}

pub fn cmd_install(args: InstallArgs) -> Result<u8> {
    if cfg!(windows) {
        windows::install(args.elevated_part)
    } else if args.elevated_part {
        // The elevated part only exists on Windows.
        Ok(0)
    } else {
        unix::install()
    }
}

pub fn cmd_uninstall() -> Result<u8> {
    if cfg!(windows) {
        windows::uninstall()
    } else {
        unix::uninstall()
    }
}

/// The folder the programs are installed to.
fn install_dir() -> Result<PathBuf> {
    if cfg!(windows) {
        let local = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .context("cannot find the local app-data folder (LOCALAPPDATA)")?;
        Ok(local.join("Programs").join(APP_NAME))
    } else {
        Ok(home_dir()?.join(".local").join("bin"))
    }
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("cannot find the home folder ($HOME)")
}

/// The programs to install: the one running now, and its sibling of the other
/// kind (`ovpn-otp` next to `ovpn-otp-gui.exe`, or the other way round).
fn programs() -> Result<Vec<PathBuf>> {
    let exe = std::env::current_exe().context("cannot find the ovpn-otp program itself")?;
    let mut names = vec![exe.file_name().unwrap_or_default().to_os_string()];
    let other = if cfg!(windows) {
        if exe.file_stem().is_some_and(|s| s == "ovpn-otp") {
            "ovpn-otp-gui.exe"
        } else {
            "ovpn-otp.exe"
        }
    } else if exe.file_name().is_some_and(|s| s == "ovpn-otp") {
        "ovpn-otp-gui"
    } else {
        "ovpn-otp"
    };
    names.push(other.into());
    Ok(names
        .into_iter()
        .map(|n| exe.with_file_name(n))
        .filter(|p| p.is_file())
        .collect())
}

/// Copy the programs into `dir`. Files already at their target (running from
/// the install folder itself) are left alone.
fn copy_programs(dir: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let mut copied = Vec::new();
    for src in programs()? {
        let dst = dir.join(src.file_name().unwrap_or_default());
        if src == dst {
            continue;
        }
        std::fs::copy(&src, &dst)
            .with_context(|| format!("cannot copy {} to {}", src.display(), dst.display()))?;
        copied.push(dst);
    }
    Ok(copied)
}

/// Run a command, give back its stdout when it succeeded.
fn run(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("cannot run {what}"))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        bail!("{what} failed: {}", if err.is_empty() { text } else { err });
    }
    Ok(text)
}

/// Run a PowerShell script that ends with a marker when it truly worked.
///
/// PowerShell often exits 0 even when a command failed (a cancelled UAC
/// prompt, a denied task registration), so the exit code alone proves
/// nothing; the script's last word does.
fn run_ps(script: &str, marker: &str, what: &str) -> Result<String> {
    let text = run(
        Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]),
        what,
    )?;
    if !text.contains(marker) {
        bail!("{what} did not complete (it said: {text})");
    }
    Ok(text)
}

/// Quote one value for a PowerShell single-quoted string.
pub(crate) fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

mod unix {
    use super::*;

    pub fn install() -> Result<u8> {
        let dir = install_dir()?;
        let copied = copy_programs(&dir)?;
        let desktop_dir = home_dir()?.join(".local/share/applications");
        std::fs::create_dir_all(&desktop_dir).ok();
        let entry = format!(
            "[Desktop Entry]\nType=Application\nName={APP_NAME}\n\
             Comment=OpenVPN with a separate authenticator code box\n\
             Exec=ovpn-otp-gui\nIcon=ovpn-otp\nCategories=Network;\nTerminal=false\n"
        );
        let desktop = desktop_dir.join(format!("{APP_NAME}.desktop"));
        std::fs::write(&desktop, &entry)
            .with_context(|| format!("cannot write {}", desktop.display()))?;
        // Refresh the launcher database when it is there; not an error if not.
        let _ = Command::new("update-desktop-database")
            .arg(&desktop_dir)
            .output();
        println!("Installed to {}", dir.display());
        for p in &copied {
            println!("  {}", p.display());
        }
        println!("Menu entry: {}", desktop.display());
        println!(
            "The app launcher now finds ovpn-otp, and scripts and AI agents call \
             `ovpn-otp` (in ~/.local/bin)."
        );
        println!(
            "OpenVPN still needs the network rights itself; see the README section \
             \"Linux: let openvpn create the tunnel\" (or run `ovpn-otp doctor`)."
        );
        Ok(0)
    }

    pub fn uninstall() -> Result<u8> {
        let desktop = home_dir()?
            .join(".local/share/applications")
            .join(format!("{APP_NAME}.desktop"));
        match std::fs::remove_file(&desktop) {
            Ok(()) => println!("Removed {}", desktop.display()),
            Err(_) => println!("No menu entry to remove."),
        }
        println!(
            "The programs in {} are left in place; delete them by hand.",
            install_dir()?.display()
        );
        Ok(0)
    }
}

mod windows {
    use super::*;

    const TASK_HELP: &str = "Creating the scheduled task needs administrator rights. \
Run this once in an administrator PowerShell:\
\n  ovpn-otp install --elevated-part";

    pub fn install(elevated_part: bool) -> Result<u8> {
        if elevated_part {
            return install_elevated_part();
        }
        let dir = install_dir()?;
        let copied = copy_programs(&dir)?;
        let gui = dir.join("ovpn-otp-gui.exe");
        if !gui.is_file() {
            bail!("no ovpn-otp-gui.exe next to this program; unpack the release archive first");
        }
        add_to_user_path(&dir)?;
        make_shortcut(&dir, &gui, false)?;
        println!("Installed to {}", dir.display());
        for p in &copied {
            println!("  {}", p.display());
        }
        println!("Start-menu entry \"ovpn-otp\" created.");
        println!("The CLI is on your PATH in new terminals.");
        let mut task_ok = ensure_task(false).is_ok();
        if !task_ok {
            println!();
            println!("{TASK_HELP}");
            // One UAC prompt from here creates the task without a terminal.
            print!("Asking Windows for administrator rights now? [Y/n] ");
            std::io::stdout().flush().ok();
            let mut answer = String::new();
            let _ = std::io::stdin().read_line(&mut answer);
            let answer = answer.trim().to_ascii_lowercase();
            if answer.is_empty() || answer == "y" || answer == "yes" {
                match self_elevate(&dir.join("ovpn-otp.exe"), &["install", "--elevated-part"]) {
                    Ok(()) => task_ok = true,
                    Err(e) => println!("The UAC prompt did not go through: {e}"),
                }
            }
        }
        if task_ok {
            // The shortcut runs the task, which starts the window elevated.
            make_shortcut(&dir, &gui, true)?;
            println!(
                "The Start-menu entry starts the window with administrator \
rights through the scheduled task."
            );
        } else {
            println!(
                "Until then, the Start-menu entry starts the window normally; \
the OpenVPN interactive service can still run the tunnel without it."
            );
        }
        println!();
        println!("To connect from a script or an AI agent:");
        println!(
            "  ovpn-otp connect --elevate --code-stdin   (code on stdin; login must be saved)"
        );
        Ok(0)
    }

    /// The administrator part: the scheduled task that starts the window
    /// elevated. Runs either from an administrator terminal, or through the
    /// one UAC prompt that `install` asks for.
    fn install_elevated_part() -> Result<u8> {
        ensure_task(true)?;
        let dir = install_dir()?;
        let gui = dir.join("ovpn-otp-gui.exe");
        if gui.is_file() {
            make_shortcut(&dir, &gui, true)?;
        }
        println!(
            "Scheduled task \"{APP_NAME}\" created: starts the window with administrator rights."
        );
        Ok(0)
    }

    /// Create the task unless one already points at the same program.
    /// `elevated` says whether this process may create it at all.
    fn ensure_task(elevated: bool) -> Result<()> {
        let dir = install_dir()?;
        let gui = dir.join("ovpn-otp-gui.exe");
        if task_points_at(&gui)? {
            return Ok(());
        }
        if !elevated {
            bail!("not running as administrator");
        }
        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             $a = New-ScheduledTaskAction -Execute {}; \
             Register-ScheduledTask -TaskName {} -Action $a -RunLevel Highest -Force | Out-Null; \
             Write-Output 'TASK-OK'",
            ps_quote(&gui.display().to_string()),
            ps_quote(APP_NAME),
        );
        run_ps(&script, "TASK-OK", "creating the scheduled task")?;
        Ok(())
    }

    /// Whether the task exists and already runs this program.
    fn task_points_at(gui: &Path) -> Result<bool> {
        let script = format!(
            "$t = Get-ScheduledTask -TaskName {} -ErrorAction SilentlyContinue; \
             if ($t) {{ ($t.Actions | ForEach-Object {{ $_.Execute }}) -join ';' }} else {{ 'NO-TASK' }}",
            ps_quote(APP_NAME),
        );
        let out = run(
            Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            "reading the scheduled task",
        );
        match out {
            Ok(text) => Ok(!text.contains("NO-TASK")
                && text
                    .lines()
                    .any(|l| l.trim().eq_ignore_ascii_case(&gui.display().to_string()))),
            Err(_) => Ok(false),
        }
    }

    /// Put the install folder on the user PATH (once).
    fn add_to_user_path(dir: &Path) -> Result<()> {
        let script = format!(
            "$p = [Environment]::GetEnvironmentVariable('Path', 'User'); \
             if ($null -eq $p) {{ $p = '' }}; \
             $parts = $p.Split(';') | Where-Object {{ $_ -ne '' }}; \
             if ($parts -notcontains {}) {{ \
                 [Environment]::SetEnvironmentVariable('Path', (($parts + {}) -join ';'), 'User'); \
                 'added' \
             }} else {{ 'present' }}",
            ps_quote(&dir.display().to_string()),
            ps_quote(&dir.display().to_string()),
        );
        run(
            Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            "adding the install folder to the user PATH",
        )?;
        Ok(())
    }

    /// The Start-menu shortcut. With `via_task` it runs the scheduled task
    /// (which starts the window elevated, and needs the task to exist);
    /// otherwise it starts the window directly.
    fn make_shortcut(dir: &Path, gui: &Path, via_task: bool) -> Result<()> {
        let start_menu = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .context("cannot find the roaming app-data folder (APPDATA)")?;
        let programs = start_menu
            .join("Microsoft")
            .join("Windows")
            .join("Start Menu")
            .join("Programs");
        std::fs::create_dir_all(&programs).ok();
        let lnk = programs.join(format!("{APP_NAME}.lnk"));
        let (target, arguments, description) = if via_task {
            (
                ps_quote(r"C:\Windows\System32\schtasks.exe"),
                "'/run /tn \"ovpn-otp\"'".to_string(),
                "ovpn-otp (runs with administrator rights)",
            )
        } else {
            (
                ps_quote(&gui.display().to_string()),
                String::new(),
                "ovpn-otp",
            )
        };
        let arguments_line = if arguments.is_empty() {
            String::new()
        } else {
            format!(
                " \
             $s.Arguments = {arguments};"
            )
        };
        let script = format!(
            "$ws = New-Object -ComObject WScript.Shell; \
             $s = $ws.CreateShortcut({}); \
             $s.TargetPath = {};{arguments_line} \
             $s.WorkingDirectory = {}; \
             $s.IconLocation = {}; \
             $s.Description = {}; \
             $s.Save()",
            ps_quote(&lnk.display().to_string()),
            target,
            ps_quote(&dir.display().to_string()),
            ps_quote(&gui.display().to_string()),
            ps_quote(description),
        );
        run(
            Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            "creating the Start-menu shortcut",
        )?;
        Ok(())
    }

    /// Relaunch this program with the UAC prompt, wait, and report.
    fn self_elevate(exe: &Path, args: &[&str]) -> Result<()> {
        let arglist: Vec<String> = args.iter().map(|a| ps_quote(a)).collect();
        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             try {{ \
                 $p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru; \
                 Write-Output ('EXITCODE=' + $p.ExitCode) \
             }} catch {{ \
                 Write-Output ('FAILED=' + $_.Exception.Message) \
             }}",
            ps_quote(&exe.display().to_string()),
            arglist.join(","),
        );
        let text = run(
            Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            "asking Windows for administrator rights (UAC)",
        )?;
        if let Some(code) = text.strip_prefix("EXITCODE=") {
            if code.trim() == "0" {
                return Ok(());
            }
            bail!("the elevated install ended with exit code {}", code.trim());
        }
        if let Some(rest) = text.strip_prefix("FAILED=") {
            bail!("Windows refused or the UAC prompt was not accepted ({rest})");
        }
        bail!("the elevated install could not be watched (it said: {text})");
    }

    pub fn uninstall() -> Result<u8> {
        for (what, script) in [
            (
                "scheduled task",
                format!(
                    "Unregister-ScheduledTask -TaskName {} -Confirm:$false",
                    ps_quote(APP_NAME)
                ),
            ),
            (
                "Start-menu shortcut",
                format!(
                    "Remove-Item -Path {} -ErrorAction SilentlyContinue",
                    ps_quote(&format!(
                        "{}\\Microsoft\\Windows\\Start Menu\\Programs\\{APP_NAME}.lnk",
                        std::env::var("APPDATA").unwrap_or_default()
                    ))
                ),
            ),
        ] {
            match run(
                Command::new("powershell").args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &script,
                ]),
                &format!("removing the {what}"),
            ) {
                Ok(_) => println!("Removed the {what}."),
                Err(e) => println!("The {what} could not be removed ({e})."),
            }
        }
        let dir = install_dir()?;
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => println!("Removed {}.", dir.display()),
            Err(e) => println!(
                "{} is left in place ({}). It is on your user PATH in new terminals.",
                dir.display(),
                e
            ),
        }
        Ok(0)
    }
}
