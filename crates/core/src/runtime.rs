//! Files a running session keeps so other commands can see and stop it.
//!
//! There is no background service. Whoever runs the session (the GUI or
//! `ovpn-otp connect`) writes the files below into a private folder, and
//! `ovpn-otp status`, `logs` and `disconnect` read or drop files there:
//!
//! * `status.json` — the current [`Snapshot`], rewritten every second and at
//!   once when the phase changes;
//! * `session.jsonl` — the log (OpenVPN, app messages, and the management
//!   transcript with secrets removed), one [`LogRecord`] as JSON per line;
//! * `stop` — created by `ovpn-otp disconnect`; the session sees it and stops;
//! * `code` — created by `ovpn-otp code`; the session reads the code, deletes
//!   the file at once and uses the code for the next login;
//! * `<name>.ovpn` — the prepared profile, removed when the session ends.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::launch::write_private;
use crate::mgmt::LogLevel;
use crate::session::{Direction, EndReason, Event};
use crate::snapshot::{Phase, Snapshot};

/// Environment variable that overrides the runtime folder.
pub const RUNTIME_ENV: &str = "OVPN_OTP_RUNTIME_DIR";

/// After this long without an update, a status file is considered left over.
pub const STALE_AFTER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct RuntimeDir {
    pub path: PathBuf,
}

/// What a session uses: which connection, profile, server and user name.
///
/// The window and `ovpn-otp status` always show this, so nobody has to guess
/// what they are connecting to. Build it with [`crate::connect::describe`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Using {
    /// The name of the connection in the settings file.
    pub name: String,
    /// The settings file.
    pub settings: String,
    /// The profile file, or a note that the profile is inside the settings file.
    pub profile: String,
    /// The servers OpenVPN tries, in order, such as `vpn.example.org:8443 (tcp)`.
    pub servers: Vec<String>,
    /// The user name of the login. Never the password.
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusFile {
    pub pid: u32,
    pub name: String,
    pub settings: String,
    /// The profile file in use.
    #[serde(default)]
    pub profile: String,
    /// The servers the profile points at, with the protocol.
    #[serde(default)]
    pub servers: Vec<String>,
    /// The user name of the login.
    #[serde(default)]
    pub username: String,
    pub updated: DateTime<Local>,
    pub running: bool,
    pub snapshot: Snapshot,
}

impl StatusFile {
    /// What the session uses.
    pub fn using(&self) -> Using {
        Using {
            name: self.name.clone(),
            settings: self.settings.clone(),
            profile: self.profile.clone(),
            servers: self.servers.clone(),
            username: self.username.clone(),
        }
    }

    /// True when a session is still updating this file.
    pub fn is_live(&self) -> bool {
        self.running
            && pid_alive(self.pid)
            && (Local::now() - self.updated)
                .to_std()
                .map(|d| d < STALE_AFTER)
                .unwrap_or(true)
    }
}

/// Whether a process with this id exists. Only checked on Linux; elsewhere
/// the update time alone decides.
fn pid_alive(pid: u32) -> bool {
    if cfg!(target_os = "linux") {
        Path::new("/proc").join(pid.to_string()).exists()
    } else {
        true
    }
}

impl RuntimeDir {
    /// Open (and create) the runtime folder: `$OVPN_OTP_RUNTIME_DIR`, else
    /// `$XDG_RUNTIME_DIR/ovpn-otp` on Linux, else the local app-data folder.
    pub fn open() -> std::io::Result<RuntimeDir> {
        let path = match std::env::var_os(RUNTIME_ENV).filter(|v| !v.is_empty()) {
            Some(p) => PathBuf::from(p),
            None => match directories::ProjectDirs::from("", "", "ovpn-otp") {
                Some(d) => d
                    .runtime_dir()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| d.data_local_dir().join("run")),
                None => std::env::temp_dir().join("ovpn-otp"),
            },
        };
        Self::at(path)
    }

    pub fn at(path: PathBuf) -> std::io::Result<RuntimeDir> {
        std::fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(RuntimeDir { path })
    }

    pub fn status_path(&self) -> PathBuf {
        self.path.join("status.json")
    }
    pub fn log_path(&self) -> PathBuf {
        self.path.join("session.jsonl")
    }
    pub fn stop_path(&self) -> PathBuf {
        self.path.join("stop")
    }
    pub fn code_path(&self) -> PathBuf {
        self.path.join("code")
    }

    /// The log of the current (or last) session, oldest line first.
    pub fn read_log(&self) -> Vec<LogRecord> {
        std::fs::read_to_string(self.log_path())
            .map(|text| text.lines().filter_map(LogRecord::from_json).collect())
            .unwrap_or_default()
    }

    /// Hand an authenticator code to the running session.
    ///
    /// The code is written to a file only the current user can read, and the
    /// session deletes it as soon as it has read it.
    pub fn submit_code(&self, code: &str) -> std::io::Result<()> {
        let tmp = self.path.join("code.tmp");
        write_private(&tmp, code.as_bytes())?;
        std::fs::rename(&tmp, self.code_path())
    }

    /// The code someone handed in with [`RuntimeDir::submit_code`], once.
    pub fn take_code(&self) -> Option<String> {
        let path = self.code_path();
        let code = std::fs::read_to_string(&path).ok()?;
        let _ = std::fs::remove_file(&path);
        Some(code.trim().to_string()).filter(|c| !c.is_empty())
    }

    /// True while a handed-in code has not been read by the session yet.
    pub fn code_waiting(&self) -> bool {
        self.code_path().exists()
    }

    pub fn read_status(&self) -> Option<StatusFile> {
        let text = std::fs::read_to_string(self.status_path()).ok()?;
        serde_json::from_str(&text).ok()
    }

    /// A live session other than this process, if any.
    pub fn live_session(&self) -> Option<StatusFile> {
        self.read_status()
            .filter(|s| s.is_live() && s.pid != std::process::id())
    }

    /// Ask the running session to stop.
    pub fn request_stop(&self) -> std::io::Result<()> {
        File::create(self.stop_path()).map(|_| ())
    }

    /// True (once) if someone asked this session to stop.
    pub fn take_stop_request(&self) -> bool {
        std::fs::remove_file(self.stop_path()).is_ok()
    }
}

/// Writes the runtime files for one session.
pub struct Recorder {
    dir: RuntimeDir,
    using: Using,
    log: Option<File>,
    last_write: Option<Instant>,
    last_phase: Option<Phase>,
}

impl Recorder {
    /// Start recording. Clears any old stop request or code and starts a fresh log.
    pub fn new(dir: RuntimeDir, using: Using) -> Recorder {
        let _ = std::fs::remove_file(dir.stop_path());
        let _ = std::fs::remove_file(dir.code_path());
        let log = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.log_path())
            .ok();
        Recorder {
            dir,
            using,
            log,
            last_write: None,
            last_phase: None,
        }
    }

    pub fn dir(&self) -> &RuntimeDir {
        &self.dir
    }

    /// Append an event to the log file, if it is worth a line.
    pub fn record(&mut self, ev: &Event) {
        let Some(record) = log_record(ev) else { return };
        if let (Some(f), Ok(line)) = (self.log.as_mut(), serde_json::to_string(&record)) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Rewrite `status.json`: at once when the phase changed or with `force`,
    /// else at most once a second. Other commands wait on the phase, so a
    /// change must not sit unwritten.
    pub fn write_status(&mut self, snap: &Snapshot, running: bool, force: bool) {
        let phase_changed = self.last_phase != Some(snap.phase);
        self.last_phase = Some(snap.phase);
        if !force && !phase_changed {
            if let Some(t) = self.last_write {
                if t.elapsed() < Duration::from_secs(1) {
                    return;
                }
            }
        }
        self.last_write = Some(Instant::now());
        let status = StatusFile {
            pid: std::process::id(),
            name: self.using.name.clone(),
            settings: self.using.settings.clone(),
            profile: self.using.profile.clone(),
            servers: self.using.servers.clone(),
            username: self.using.username.clone(),
            updated: Local::now(),
            running,
            snapshot: snap.clone(),
        };
        if let Ok(text) = serde_json::to_string_pretty(&status) {
            let tmp = self.dir.path.join("status.json.tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, self.dir.status_path());
            }
        }
    }
}

/// One line of the session log.
///
/// This is also what `ovpn-otp logs --json` prints, so the field names are fixed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    pub at: DateTime<Local>,
    /// `openvpn` (the OpenVPN log), `app` (this program), `state` (an OpenVPN
    /// state change), `check` (the reach check) or `wire` (the management
    /// transcript).
    pub source: String,
    pub level: LogLevel,
    /// For `wire` lines: `in` from OpenVPN, `out` to OpenVPN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<Direction>,
    pub message: String,
}

impl LogRecord {
    fn new(at: DateTime<Local>, source: &str, level: LogLevel, message: String) -> LogRecord {
        LogRecord {
            at,
            source: source.to_string(),
            level,
            dir: None,
            message,
        }
    }

    pub fn from_json(line: &str) -> Option<LogRecord> {
        serde_json::from_str(line).ok()
    }

    pub fn is_wire(&self) -> bool {
        self.source == "wire"
    }

    /// The line as people read it: time, source, level, message.
    pub fn to_text(&self) -> String {
        let stamp = self.at.format("%Y-%m-%d %H:%M:%S");
        let level = match self.dir {
            Some(Direction::In) => "<-",
            Some(Direction::Out) => "->",
            None => self.level.label(),
        };
        format!("{stamp} {:<7} {level:<7} {}", self.source, self.message)
    }
}

/// The log line for an event, if it is worth one. Every text here is already
/// free of secrets.
pub fn log_record(ev: &Event) -> Option<LogRecord> {
    use LogLevel::{Error, Info, Warning};
    let now = Local::now;
    Some(match ev {
        Event::Launching { at, attempt } => LogRecord::new(
            *at,
            "app",
            Info,
            format!("starting OpenVPN (try {})", attempt + 1),
        ),
        Event::Wire { at, dir, text } => LogRecord {
            dir: Some(*dir),
            ..LogRecord::new(*at, "wire", LogLevel::Debug, text.clone())
        },
        Event::State { at, info } => LogRecord::new(
            *at,
            "state",
            Info,
            format!("{} {} {}", info.name, info.detail, info.local_ip)
                .trim_end()
                .to_string(),
        ),
        Event::Bytes { .. } | Event::Version(_) | Event::Pushed(_) => return None,
        Event::Log(e) => {
            let at = chrono::TimeZone::timestamp_opt(&Local, e.time, 0)
                .single()
                .filter(|_| e.time > 0)
                .unwrap_or_else(now);
            LogRecord::new(at, "openvpn", e.level, e.message.clone())
        }
        Event::Note { at, level, text } => LogRecord::new(*at, "app", *level, text.clone()),
        Event::NeedCode { reason } => LogRecord::new(
            now(),
            "app",
            Warning,
            format!("waiting for authenticator code ({reason:?})"),
        ),
        Event::LoginSent { at } => LogRecord::new(*at, "app", Info, "login sent".into()),
        Event::AuthFailed { reason } => {
            LogRecord::new(now(), "app", Error, format!("login rejected: {reason}"))
        }
        Event::ConnectFailed { at, failure } => LogRecord::new(
            *at,
            "app",
            Error,
            format!("{}: {}", failure.kind.name(), failure.message),
        ),
        Event::Reconnecting {
            at,
            attempt,
            delay,
            reason,
        } => LogRecord::new(
            *at,
            "app",
            Warning,
            format!(
                "connection lost ({reason}); try {attempt} in {}s",
                delay.as_secs()
            ),
        ),
        Event::Reach(r) => match (r.ok, r.latency_ms) {
            (true, Some(ms)) => LogRecord::new(
                r.at,
                "check",
                Info,
                format!("{} reachable in {ms:.1} ms", r.target),
            ),
            _ => LogRecord::new(
                r.at,
                "check",
                Warning,
                format!(
                    "{} not reachable: {}",
                    r.target,
                    r.error.clone().unwrap_or_default()
                ),
            ),
        },
        Event::Ended { reason } => {
            let text = match reason {
                EndReason::Disconnected => "disconnected".to_string(),
                EndReason::Dropped(r) => format!("dropped: {r}"),
                EndReason::Failed(f) => format!("{}: {}", f.kind.name(), f.message),
            };
            LogRecord::new(now(), "app", Info, format!("session ended, {text}"))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn using(name: &str) -> Using {
        Using {
            name: name.into(),
            settings: "/s.toml".into(),
            profile: "/vpn/work.ovpn".into(),
            servers: vec!["vpn.example.org:8443 (tcp)".into()],
            username: "alice".into(),
        }
    }

    #[test]
    fn status_round_trip_and_stop_request() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = RuntimeDir::at(tmp.path().join("run")).unwrap();
        let mut rec = Recorder::new(dir.clone(), using("work"));
        let mut snap = Snapshot::default();
        snap.phase = Phase::Connected;
        snap.local_ip = "10.8.0.6".into();
        rec.write_status(&snap, true, true);
        let st = dir.read_status().unwrap();
        assert_eq!(st.name, "work");
        assert_eq!(st.using(), using("work"));
        assert_eq!(st.snapshot.phase, Phase::Connected);
        assert!(st.is_live());
        // Our own process is not "another" session.
        assert!(dir.live_session().is_none());

        assert!(!dir.take_stop_request());
        dir.request_stop().unwrap();
        assert!(dir.take_stop_request());
        assert!(!dir.take_stop_request());
    }

    #[test]
    fn log_file_gets_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = RuntimeDir::at(tmp.path().to_path_buf()).unwrap();
        let mut rec = Recorder::new(dir.clone(), using("w"));
        rec.record(&Event::Note {
            at: Local::now(),
            level: crate::mgmt::LogLevel::Info,
            text: "hello".into(),
        });
        rec.record(&Event::Bytes {
            at: Local::now(),
            bytes_in: 1,
            bytes_out: 1,
        });
        rec.record(&Event::Wire {
            at: Local::now(),
            dir: Direction::Out,
            text: "hold release".into(),
        });
        drop(rec);
        let log = dir.read_log();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].source, "app");
        assert_eq!(log[0].level, crate::mgmt::LogLevel::Info);
        assert_eq!(log[0].message, "hello");
        assert!(log[0].to_text().ends_with("app     info    hello"));
        assert!(log[1].is_wire());
        assert!(log[1].to_text().ends_with("wire    ->      hold release"));

        // The file is one JSON object per line with fixed field names.
        let text = std::fs::read_to_string(dir.log_path()).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["source"], "app");
        assert_eq!(first["level"], "info");
        assert_eq!(first["message"], "hello");
        assert!(first["at"].is_string());
        assert!(first.get("dir").is_none());
        let second: serde_json::Value = serde_json::from_str(text.lines().nth(1).unwrap()).unwrap();
        assert_eq!(second["dir"], "out");
    }

    #[test]
    fn a_handed_in_code_is_read_once_and_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = RuntimeDir::at(tmp.path().to_path_buf()).unwrap();
        assert_eq!(dir.take_code(), None);
        dir.submit_code("135790").unwrap();
        assert!(dir.code_waiting());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.code_path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(dir.take_code().as_deref(), Some("135790"));
        assert!(!dir.code_waiting());
        assert_eq!(dir.take_code(), None);

        // A code left over from an earlier session is not used by the next one.
        dir.submit_code("246802").unwrap();
        let _rec = Recorder::new(dir.clone(), using("w"));
        assert_eq!(dir.take_code(), None);
    }

    #[test]
    fn status_is_written_at_once_when_the_phase_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = RuntimeDir::at(tmp.path().to_path_buf()).unwrap();
        let mut rec = Recorder::new(dir.clone(), using("w"));
        let mut snap = Snapshot::default();
        snap.phase = Phase::NeedCode;
        rec.write_status(&snap, true, false);
        assert_eq!(dir.read_status().unwrap().snapshot.phase, Phase::NeedCode);
        snap.phase = Phase::Connecting;
        rec.write_status(&snap, true, false);
        assert_eq!(dir.read_status().unwrap().snapshot.phase, Phase::Connecting);
        // Within the same second and phase, nothing is rewritten.
        snap.bytes_in = 7;
        rec.write_status(&snap, true, false);
        assert_eq!(dir.read_status().unwrap().snapshot.bytes_in, 0);
    }
}
