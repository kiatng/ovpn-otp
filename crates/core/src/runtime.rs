//! Files a running session keeps so other commands can see and stop it.
//!
//! There is no background service. Whoever runs the session (the GUI or
//! `ovpn-otp connect`) writes the files below into a private folder, and
//! `ovpn-otp status`, `logs` and `disconnect` read or drop files there:
//!
//! * `status.json` — the current [`Snapshot`], rewritten every second;
//! * `session.log` — the log (OpenVPN, app messages, and the management
//!   transcript with secrets removed);
//! * `stop` — created by `ovpn-otp disconnect`; the session sees it and stops;
//! * `<name>.ovpn` — the prepared profile, removed when the session ends.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::session::{Direction, EndReason, Event};
use crate::snapshot::Snapshot;

/// Environment variable that overrides the runtime folder.
pub const RUNTIME_ENV: &str = "OVPN_OTP_RUNTIME_DIR";

/// After this long without an update, a status file is considered left over.
pub const STALE_AFTER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct RuntimeDir {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusFile {
    pub pid: u32,
    pub name: String,
    pub settings: String,
    pub updated: DateTime<Local>,
    pub running: bool,
    pub snapshot: Snapshot,
}

impl StatusFile {
    /// True when a session is still updating this file.
    pub fn is_live(&self) -> bool {
        self.running
            && (Local::now() - self.updated)
                .to_std()
                .map(|d| d < STALE_AFTER)
                .unwrap_or(true)
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
        self.path.join("session.log")
    }
    pub fn stop_path(&self) -> PathBuf {
        self.path.join("stop")
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
    name: String,
    settings: String,
    log: Option<File>,
    last_write: Option<Instant>,
}

impl Recorder {
    /// Start recording. Clears any old stop request and starts a fresh log.
    pub fn new(dir: RuntimeDir, name: &str, settings_path: &Path) -> Recorder {
        let _ = std::fs::remove_file(dir.stop_path());
        let log = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.log_path())
            .ok();
        Recorder {
            dir,
            name: name.to_string(),
            settings: settings_path.display().to_string(),
            log,
            last_write: None,
        }
    }

    pub fn dir(&self) -> &RuntimeDir {
        &self.dir
    }

    /// Append an event to the log file, if it is worth a line.
    pub fn record(&mut self, ev: &Event) {
        let Some(line) = log_line(ev) else { return };
        if let Some(f) = self.log.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Rewrite `status.json`, at most once a second unless `force`.
    pub fn write_status(&mut self, snap: &Snapshot, running: bool, force: bool) {
        if !force {
            if let Some(t) = self.last_write {
                if t.elapsed() < Duration::from_secs(1) {
                    return;
                }
            }
        }
        self.last_write = Some(Instant::now());
        let status = StatusFile {
            pid: std::process::id(),
            name: self.name.clone(),
            settings: self.settings.clone(),
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

/// One log-file line for an event. Every text here is already free of secrets.
pub fn log_line(ev: &Event) -> Option<String> {
    let stamp = |t: &DateTime<Local>| t.format("%Y-%m-%d %H:%M:%S").to_string();
    Some(match ev {
        Event::Launching { at, attempt } => {
            format!(
                "{} app     info    starting OpenVPN (try {})",
                stamp(at),
                attempt + 1
            )
        }
        Event::Wire { at, dir, text } => {
            let arrow = match dir {
                Direction::In => "<-",
                Direction::Out => "->",
            };
            format!("{} wire    {arrow}      {text}", stamp(at))
        }
        Event::State { at, info } => format!(
            "{} state   {:<7} {} {} {}",
            stamp(at),
            "info",
            info.name,
            info.detail,
            info.local_ip
        )
        .trim_end()
        .to_string(),
        Event::Bytes { .. } | Event::Version(_) | Event::Pushed(_) => return None,
        Event::Log(e) => {
            let at = chrono::TimeZone::timestamp_opt(&Local, e.time, 0)
                .single()
                .unwrap_or_else(Local::now);
            format!(
                "{} openvpn {:<7} {}",
                stamp(&at),
                e.level.label(),
                e.message
            )
        }
        Event::Note { at, level, text } => {
            format!("{} app     {:<7} {text}", stamp(at), level.label())
        }
        Event::NeedCode { reason } => format!(
            "{} app     warning waiting for authenticator code ({reason:?})",
            stamp(&Local::now())
        ),
        Event::LoginSent { at } => format!("{} app     info    login sent", stamp(at)),
        Event::AuthFailed { reason } => format!(
            "{} app     error   login rejected: {reason}",
            stamp(&Local::now())
        ),
        Event::Reconnecting {
            at,
            attempt,
            delay,
            reason,
        } => format!(
            "{} app     warning connection lost ({reason}); try {attempt} in {}s",
            stamp(at),
            delay.as_secs()
        ),
        Event::Reach(r) => match (r.ok, r.latency_ms) {
            (true, Some(ms)) => format!(
                "{} check   info    {} reachable in {ms:.1} ms",
                stamp(&r.at),
                r.target
            ),
            _ => format!(
                "{} check   warning {} not reachable: {}",
                stamp(&r.at),
                r.target,
                r.error.clone().unwrap_or_default()
            ),
        },
        Event::Ended { reason } => {
            let text = match reason {
                EndReason::Disconnected => "disconnected".to_string(),
                EndReason::Dropped(r) => format!("dropped: {r}"),
                EndReason::Failed(r) => format!("failed: {r}"),
            };
            format!(
                "{} app     info    session ended, {text}",
                stamp(&Local::now())
            )
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::Phase;

    #[test]
    fn status_round_trip_and_stop_request() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = RuntimeDir::at(tmp.path().join("run")).unwrap();
        let mut rec = Recorder::new(dir.clone(), "work", Path::new("/s.toml"));
        let mut snap = Snapshot::default();
        snap.phase = Phase::Connected;
        snap.local_ip = "10.8.0.6".into();
        rec.write_status(&snap, true, true);
        let st = dir.read_status().unwrap();
        assert_eq!(st.name, "work");
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
        let mut rec = Recorder::new(dir.clone(), "w", Path::new("s"));
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
        drop(rec);
        let text = std::fs::read_to_string(dir.log_path()).unwrap();
        assert!(text.contains("hello"));
        assert_eq!(text.lines().count(), 1);
    }
}
