//! Starting the `openvpn` program.
//!
//! The app never speaks the VPN protocol itself. It starts the standard
//! OpenVPN 2.6+ program with its management interface on 127.0.0.1 and drives
//! it from there (see [`crate::session`]).
//!
//! * Linux: `openvpn` runs directly, usually behind `sudo -n` (see the
//!   `command_prefix` setting) because creating a tunnel needs network rights.
//! * Windows: by default the OpenVPN interactive service starts `openvpn.exe`
//!   for us, so no admin rights are needed per connect. Running
//!   `openvpn.exe` directly is also possible but needs an admin session.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::credentials::Secret;
use crate::settings::Settings;

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("{0}")]
    NotFound(String),
    #[error("could not start openvpn: {0}")]
    Spawn(String),
    #[error("OpenVPN interactive service refused to start openvpn: {0}")]
    Service(String),
}

/// What the session asks a launcher to start.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    /// The prepared config file (see [`crate::profile`]).
    pub config: PathBuf,
    /// Folder that relative paths in the profile refer to.
    pub work_dir: PathBuf,
    /// A private folder for short-lived files (the management password file).
    pub private_dir: PathBuf,
    /// OpenVPN log detail (`--verb`).
    pub verb: u8,
}

/// A started OpenVPN and how to reach its management interface.
pub struct Launched {
    pub process: Box<dyn VpnProcess>,
    pub mgmt_addr: SocketAddr,
    /// Password for the management interface, unique per launch.
    pub mgmt_password: Secret,
    /// The command line, for the log (no secrets in it).
    pub description: String,
}

/// A running OpenVPN.
pub trait VpnProcess: Send {
    /// `None` while running; `Some(code)` once it has exited (`code` may be unknown).
    fn try_wait(&mut self) -> Option<Option<i32>>;
    /// Stop it without the management interface (last resort).
    fn kill(&mut self);
    /// The last lines OpenVPN (or `sudo`) printed, to explain an early exit.
    fn output_tail(&self) -> Vec<String>;
}

/// Something that can start OpenVPN. The real one is [`OpenVpnLauncher`];
/// tests use a fake.
pub trait Launcher: Send + Sync {
    fn launch(&self, req: &LaunchRequest) -> Result<Launched, LaunchError>;
}

/// How OpenVPN is started on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchMode {
    /// Run the program directly, with an optional prefix such as `sudo -n`.
    Direct {
        program: PathBuf,
        prefix: Vec<String>,
    },
    /// Ask the Windows OpenVPN interactive service to run it.
    Service,
}

/// The real launcher.
#[derive(Debug, Clone)]
pub struct OpenVpnLauncher {
    pub mode: LaunchMode,
}

impl OpenVpnLauncher {
    /// Work out how to start OpenVPN from the settings, or explain what is missing.
    pub fn from_settings(settings: &Settings) -> Result<Self, LaunchError> {
        let p = settings.platform();
        let launch = p.launch.trim().to_ascii_lowercase();
        if cfg!(windows) && (launch == "service" || launch.is_empty() || launch == "auto") {
            if service_available() {
                return Ok(OpenVpnLauncher {
                    mode: LaunchMode::Service,
                });
            }
            if launch == "service" {
                return Err(LaunchError::NotFound(WINDOWS_HELP.into()));
            }
        }
        let program = find_openvpn(&p.path)?;
        let prefix = match &p.command_prefix {
            Some(v) => v.clone(),
            None => default_prefix(),
        };
        Ok(OpenVpnLauncher {
            mode: LaunchMode::Direct { program, prefix },
        })
    }
}

const WINDOWS_HELP: &str = "OpenVPN is not installed, or its interactive service is not running.\n\
Install the OpenVPN community client (2.6 or newer) from https://openvpn.net/community-downloads/ \
with the default options, which include the \"OpenVPN Interactive Service\". \
OpenVPN Connect is a different program and cannot be used.";

const LINUX_HELP: &str = "The openvpn program was not found.\n\
Install it with your package manager, for example `sudo pacman -S openvpn` (Arch) \
or `sudo apt install openvpn` (Debian/Ubuntu), or set [openvpn.linux] path in the settings.";

fn default_prefix() -> Vec<String> {
    if cfg!(windows) || is_root() {
        Vec::new()
    } else {
        vec!["sudo".into(), "-n".into()]
    }
}

#[cfg(unix)]
fn is_root() -> bool {
    // The effective user id is not in std; read it from /proc.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2).map(|u| u == "0"))
        })
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

/// Find the openvpn program: the configured path, then the usual places.
pub fn find_openvpn(configured: &str) -> Result<PathBuf, LaunchError> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let p = PathBuf::from(configured);
        if p.is_file() {
            return Ok(p);
        }
        if let Some(found) = search_path(configured) {
            return Ok(found);
        }
        return Err(LaunchError::NotFound(format!(
            "The configured openvpn program `{configured}` does not exist."
        )));
    }
    let name = if cfg!(windows) {
        "openvpn.exe"
    } else {
        "openvpn"
    };
    let mut candidates: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        for var in ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"] {
            if let Some(dir) = std::env::var_os(var) {
                candidates.push(Path::new(&dir).join("OpenVPN").join("bin").join(name));
            }
        }
    } else {
        candidates.push("/usr/sbin/openvpn".into());
        candidates.push("/usr/bin/openvpn".into());
        candidates.push("/usr/local/sbin/openvpn".into());
    }
    if let Some(found) = search_path(name) {
        return Ok(found);
    }
    candidates.into_iter().find(|p| p.is_file()).ok_or_else(|| {
        LaunchError::NotFound(
            if cfg!(windows) {
                WINDOWS_HELP
            } else {
                LINUX_HELP
            }
            .into(),
        )
    })
}

fn search_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Whether the Windows OpenVPN interactive service is listening.
pub fn service_available() -> bool {
    #[cfg(windows)]
    {
        windows::service_available()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Whether this program runs with administrator rights (Windows) or as root
/// (Linux). When the check cannot be made, this answers true: a wrong "not
/// elevated" warning is worse than a missing one.
pub fn elevated() -> bool {
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
    #[cfg(not(windows))]
    {
        is_root()
    }
}

/// Whether starting OpenVPN the way the settings describe needs administrator
/// rights: on Windows any direct start does (only the interactive service does
/// not), on Linux the `sudo`/`pkexec` prefix asks for them by itself.
pub fn needs_admin(settings: &Settings) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let launch = settings.platform().launch.trim().to_ascii_lowercase();
    if launch == "service" {
        // The user said the service runs OpenVPN; a moment where its pipe is
        // busy with another session does not change that.
        return false;
    }
    match OpenVpnLauncher::from_settings(settings) {
        Ok(l) => matches!(l.mode, LaunchMode::Direct { .. }),
        Err(_) => true,
    }
}

/// Keep the terminal's pipes out of the next child this process starts (see
/// [`windows::make_stdio_uninheritable`]). Nothing to do off Windows.
pub fn detach_stdio() {
    #[cfg(windows)]
    windows::make_stdio_uninheritable();
}

/// The advice for a connect that will fail for lack of rights, or an empty
/// string when the rights are there.
pub fn rights_advice(settings: &Settings) -> String {
    if !needs_admin(settings) || elevated() {
        return String::new();
    }
    if cfg!(windows) {
        "OpenVPN will be started directly, and adding the network routes needs \
         administrator rights. Start ovpn-otp as administrator, or let the \
         OpenVPN Interactive Service start OpenVPN (see the README)."
            .to_string()
    } else {
        String::new()
    }
}

/// A free TCP port on 127.0.0.1 for the management interface.
fn free_port() -> std::io::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// A random password for the management interface.
fn random_password() -> Secret {
    use rand::distr::{Alphanumeric, SampleString};
    Secret::new(Alphanumeric.sample_string(&mut rand::rng(), 32))
}

/// Options given on the OpenVPN command line. The Windows interactive service
/// only allows a short list of options for ordinary users, so everything else
/// goes in the prepared config file instead.
fn management_args(port: u16, password_source: &str, verb: u8) -> Vec<String> {
    vec![
        "--management".into(),
        "127.0.0.1".into(),
        port.to_string(),
        password_source.into(),
        "--management-query-passwords".into(),
        "--management-hold".into(),
        "--auth-retry".into(),
        "interact".into(),
        "--verb".into(),
        verb.to_string(),
    ]
}

impl Launcher for OpenVpnLauncher {
    fn launch(&self, req: &LaunchRequest) -> Result<Launched, LaunchError> {
        match &self.mode {
            LaunchMode::Direct { program, prefix } => launch_direct(program, prefix, req),
            LaunchMode::Service => {
                #[cfg(windows)]
                {
                    windows::launch_service(req)
                }
                #[cfg(not(windows))]
                {
                    let _ = req;
                    Err(LaunchError::Service(
                        "the interactive service exists only on Windows".into(),
                    ))
                }
            }
        }
    }
}

fn launch_direct(
    program: &Path,
    prefix: &[String],
    req: &LaunchRequest,
) -> Result<Launched, LaunchError> {
    let port = free_port().map_err(|e| LaunchError::Spawn(e.to_string()))?;
    let password = random_password();
    // OpenVPN reads the management password from a file. It lives in the
    // private folder and is deleted when this OpenVPN process handle is dropped.
    let pw_file = req.private_dir.join(format!("mgmt-{port}.pw"));
    write_private(&pw_file, format!("{}\n", password.expose()).as_bytes())
        .map_err(|e| LaunchError::Spawn(format!("cannot write {}: {e}", pw_file.display())))?;

    let mut args: Vec<String> = Vec::new();
    args.push("--config".into());
    args.push(req.config.display().to_string());
    args.extend(management_args(
        port,
        &pw_file.display().to_string(),
        req.verb,
    ));

    let (exe, all_args): (String, Vec<String>) = match prefix.split_first() {
        Some((first, rest)) => {
            let mut a: Vec<String> = rest.to_vec();
            a.push(program.display().to_string());
            a.extend(args);
            (first.clone(), a)
        }
        None => (program.display().to_string(), args),
    };
    let description = format!("{exe} {}", all_args.join(" "));

    let mut cmd = Command::new(&exe);
    cmd.args(&all_args)
        .current_dir(&req.work_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let mut child = cmd.spawn().map_err(|e| {
        let _ = std::fs::remove_file(&pw_file);
        LaunchError::Spawn(format!("{exe}: {e}"))
    })?;
    let tail = Arc::new(Mutex::new(VecDeque::new()));
    if let Some(out) = child.stdout.take() {
        drain(out, tail.clone());
    }
    if let Some(err) = child.stderr.take() {
        drain(err, tail.clone());
    }
    Ok(Launched {
        process: Box::new(ChildProcess {
            child,
            tail,
            pw_file: Some(pw_file),
        }),
        mgmt_addr: SocketAddr::from(([127, 0, 0, 1], port)),
        mgmt_password: password,
        description,
    })
}

/// Read a pipe to the end, keeping the last lines. OpenVPN blocks if its
/// output pipe fills up, so it must always be drained.
fn drain(pipe: impl Read + Send + 'static, tail: Arc<Mutex<VecDeque<String>>>) {
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { break };
            let mut t = tail.lock().unwrap();
            if t.len() >= 40 {
                t.pop_front();
            }
            t.push_back(line);
        }
    });
}

/// Write a file only the current user can read.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    f.write_all(data)
}

struct ChildProcess {
    child: Child,
    tail: Arc<Mutex<VecDeque<String>>>,
    pw_file: Option<PathBuf>,
}

impl VpnProcess for ChildProcess {
    fn try_wait(&mut self) -> Option<Option<i32>> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code()),
            Ok(None) => None,
            Err(_) => Some(None),
        }
    }

    fn kill(&mut self) {
        #[cfg(unix)]
        {
            // With a `sudo` prefix the child is sudo, which passes SIGTERM on to
            // openvpn but cannot pass on SIGKILL. Ask nicely first.
            let pid = self.child.id().to_string();
            let _ = Command::new("kill")
                .args(["-TERM", &pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            for _ in 0..30 {
                if self.try_wait().is_some() {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn output_tail(&self) -> Vec<String> {
        self.tail.lock().unwrap().iter().cloned().collect()
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        if let Some(p) = self.pw_file.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(windows)]
mod windows {
    //! Talking to the OpenVPN interactive service (`openvpnserv.exe`).
    //!
    //! This is the same handshake the official OpenVPN GUI uses: open the
    //! service's named pipe and write one message of three NUL-terminated
    //! UTF-16 strings — working folder, openvpn options, and text for
    //! openvpn's standard input (here the management password). The service
    //! replies `0x00000000\n0x<pid>\n...` on success, or an error code and
    //! message. The pipe stays open while OpenVPN runs.

    use super::*;
    use std::fs::{File, OpenOptions};
    use std::io::Write;

    const PIPE: &str = r"\\.\pipe\openvpn\service";

    /// Whether this process runs with administrator rights (an elevated token).
    pub fn is_elevated() -> bool {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return true;
            }
            let mut elevation: u32 = 0;
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut u32).cast(),
                std::mem::size_of::<u32>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            ok == 0 || elevation != 0
        }
    }

    /// Stop this process's own stdio handles from being inherited by the next
    /// child it starts.
    ///
    /// A child is started with every inheritable handle of its parent, not
    /// only the three stdio ones it is given. The terminal's pipes are such
    /// handles (WSL marks them inheritable), and WSL waits for every process
    /// that holds one. A detached session process would then keep `connect
    /// --background` from returning for as long as the session runs. Clearing
    /// the inherit flag on our stdio keeps the pipes out of the child.
    pub fn make_stdio_uninheritable() {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::System::Console::GetStdHandle;
        const STD_HANDLES: [u32; 3] = [
            windows_sys::Win32::System::Console::STD_INPUT_HANDLE,
            windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE,
            windows_sys::Win32::System::Console::STD_ERROR_HANDLE,
        ];
        unsafe {
            for which in STD_HANDLES {
                let handle = GetStdHandle(which);
                if !handle.is_null() && handle != -1isize as _ {
                    SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
                }
            }
        }
    }

    pub fn service_available() -> bool {
        // Opening and closing the pipe without writing does not start anything.
        // When every pipe instance is busy (another session is connecting right
        // now), the service is still there: that error means available too.
        match OpenOptions::new().read(true).write(true).open(PIPE) {
            Ok(_) => true,
            Err(e) => e.raw_os_error() == Some(231), // ERROR_PIPE_BUSY
        }
    }

    pub fn launch_service(req: &LaunchRequest) -> Result<Launched, LaunchError> {
        let port = free_port().map_err(|e| LaunchError::Spawn(e.to_string()))?;
        let password = random_password();
        let mut args = vec![
            "--config".to_string(),
            quote_arg(&req.config.display().to_string()),
        ];
        args.extend(management_args(port, "stdin", req.verb));
        let options = args.join(" ");

        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE)
            .map_err(|e| LaunchError::NotFound(format!("{WINDOWS_HELP}\n({e})")))?;

        let mut msg: Vec<u16> = Vec::new();
        for part in [
            req.work_dir.display().to_string(),
            options.clone(),
            format!("{}\n", password.expose()),
        ] {
            msg.extend(part.encode_utf16());
            msg.push(0);
        }
        let bytes: Vec<u8> = msg.iter().flat_map(|u| u.to_le_bytes()).collect();
        pipe.write_all(&bytes)
            .map_err(|e| LaunchError::Service(e.to_string()))?;

        let reply = read_reply(&mut pipe)?;
        let mut lines = reply.lines();
        let code = lines.next().unwrap_or("").trim();
        if code != "0x00000000" {
            let rest: Vec<&str> = lines.collect();
            return Err(LaunchError::Service(explain_service_error(
                code,
                &rest.join(" "),
            )));
        }
        Ok(Launched {
            process: Box::new(ServiceProcess {
                pipe: Some(pipe),
                exited: false,
            }),
            mgmt_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            mgmt_password: password,
            description: format!("OpenVPN interactive service: openvpn {options}"),
        })
    }

    fn quote_arg(s: &str) -> String {
        format!("\"{s}\"")
    }

    fn read_reply(pipe: &mut File) -> Result<String, LaunchError> {
        let mut buf = vec![0u8; 4096];
        let n = pipe
            .read(&mut buf)
            .map_err(|e| LaunchError::Service(e.to_string()))?;
        let units: Vec<u16> = buf[..n - n % 2]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Ok(String::from_utf16_lossy(&units)
            .trim_end_matches('\0')
            .to_string())
    }

    fn explain_service_error(code: &str, text: &str) -> String {
        let mut msg = format!("{code} {text}");
        if text.contains("options") || text.contains("config") || text.contains("not allowed") {
            msg.push_str(
                "\nThe service only runs configs from its own config folder for ordinary users. \
                 Add your Windows user to the \"OpenVPN Administrators\" group \
                 (the OpenVPN installer does this for the user who installed it), then sign out and in again.",
            );
        }
        msg
    }

    struct ServiceProcess {
        pipe: Option<File>,
        exited: bool,
    }

    impl VpnProcess for ServiceProcess {
        fn try_wait(&mut self) -> Option<Option<i32>> {
            // The session notices the exit when the management connection closes.
            if self.exited {
                Some(None)
            } else {
                None
            }
        }
        fn kill(&mut self) {
            // Closing the pipe tells the service we are gone; it stops openvpn.
            self.pipe = None;
            self.exited = true;
        }
        fn output_tail(&self) -> Vec<String> {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_args_use_only_service_allowed_options() {
        let allowed = [
            "--management",
            "--management-query-passwords",
            "--management-hold",
            "--auth-retry",
            "--verb",
        ];
        for a in management_args(1234, "stdin", 3) {
            if a.starts_with("--") {
                assert!(allowed.contains(&a.as_str()), "{a} is not service-allowed");
            }
        }
    }

    #[test]
    fn configured_path_must_exist() {
        let e = find_openvpn("/definitely/not/here/openvpn").unwrap_err();
        assert!(e.to_string().contains("does not exist"));
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x");
        write_private(&p, b"s").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
