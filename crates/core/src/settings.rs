//! The shared settings file.
//!
//! One TOML file holds everything except secrets, so it can live in a synced
//! folder or a private git repository and be used from several machines. The
//! user name and password live in the OS credential store (see
//! [`crate::credentials`]); the authenticator code is never stored.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Environment variable that points at the settings file.
pub const CONFIG_ENV: &str = "OVPN_OTP_CONFIG";

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("cannot read settings file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("settings file {path} is not valid: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("cannot write settings file {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("settings file {0} has no profile: set [profile] path or inline")]
    NoProfile(PathBuf),
    #[error("cannot read profile {path}: {source}")]
    Profile {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// A short name for this connection. The saved login is stored in the
    /// credential store under this name.
    pub name: String,
    pub profile: ProfileSettings,
    pub keepalive: KeepAlive,
    pub check: ReachCheck,
    pub code: CodeSettings,
    pub openvpn: OpenVpnSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            name: "default".into(),
            profile: ProfileSettings::default(),
            keepalive: KeepAlive::default(),
            check: ReachCheck::default(),
            code: CodeSettings::default(),
            openvpn: OpenVpnSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProfileSettings {
    /// Path to the `.ovpn` profile. A relative path is relative to the
    /// settings file, so the two can sit side by side in a shared folder.
    pub path: String,
    /// The profile text itself, as an alternative to `path`.
    pub inline: String,
    /// Optional `host:port` that replaces the profile's `remote` line.
    pub remote: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct KeepAlive {
    /// Seconds between keep-alive pings sent by OpenVPN. 0 leaves the profile's value.
    pub ping: u32,
    /// Seconds without anything from the server before OpenVPN restarts the
    /// connection. 0 leaves the profile's value.
    pub ping_restart: u32,
    /// Reconnect automatically when the connection drops.
    pub auto_reconnect: bool,
    /// First wait before reconnecting, in seconds. Doubles on each failed try.
    pub backoff_initial: u32,
    /// Longest wait between reconnect tries, in seconds.
    pub backoff_max: u32,
}

impl Default for KeepAlive {
    fn default() -> Self {
        KeepAlive {
            ping: 10,
            ping_restart: 60,
            auto_reconnect: true,
            backoff_initial: 2,
            backoff_max: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ReachCheck {
    /// A host on the far side of the VPN to check while connected. `10.0.0.1`
    /// uses the system `ping`; `10.0.0.1:443` opens a TCP connection instead.
    /// Empty turns the check off.
    pub host: String,
    /// Seconds between checks.
    pub interval: u32,
}

impl Default for ReachCheck {
    fn default() -> Self {
        ReachCheck {
            host: String::new(),
            interval: 15,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct CodeSettings {
    /// How many digits the authenticator code has.
    pub digits: u8,
}

impl Default for CodeSettings {
    fn default() -> Self {
        CodeSettings { digits: 6 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OpenVpnSettings {
    /// Settings used on Windows.
    pub windows: OpenVpnPlatform,
    /// Settings used on Linux.
    pub linux: OpenVpnPlatform,
    /// Extra lines appended to the profile, one option per line.
    pub extra_options: Vec<String>,
    /// OpenVPN log detail, 1 (quiet) to 6 (very detailed). Default 3.
    pub verb: Option<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OpenVpnPlatform {
    /// Path to the `openvpn` program. Empty means find it automatically.
    pub path: String,
    /// Windows only: `auto`, `service` (the OpenVPN interactive service, no
    /// admin rights needed) or `direct` (run openvpn.exe yourself; needs admin).
    pub launch: String,
    /// Linux only: a command put in front of `openvpn` to give it network
    /// rights, for example `["sudo", "-n"]` or `["pkexec"]`. When not set, it
    /// is `["sudo", "-n"]` unless you run as root. Set `[]` when the openvpn
    /// program already has the rights it needs.
    pub command_prefix: Option<Vec<String>>,
}

/// A loaded settings file and where it came from.
#[derive(Debug, Clone)]
pub struct LoadedSettings {
    pub path: PathBuf,
    pub settings: Settings,
}

impl Settings {
    pub fn from_toml(text: &str) -> Result<Settings, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("settings always serialize")
    }

    /// The platform section that applies to this machine.
    pub fn platform(&self) -> &OpenVpnPlatform {
        if cfg!(windows) {
            &self.openvpn.windows
        } else {
            &self.openvpn.linux
        }
    }

    pub fn platform_mut(&mut self) -> &mut OpenVpnPlatform {
        if cfg!(windows) {
            &mut self.openvpn.windows
        } else {
            &mut self.openvpn.linux
        }
    }
}

/// Where the settings file is: `--config` flag, else `OVPN_OTP_CONFIG`, else
/// the per-user config folder (`~/.config/ovpn-otp/settings.toml` on Linux,
/// `%APPDATA%\ovpn-otp\settings.toml` on Windows).
pub fn settings_path(flag: Option<&Path>) -> PathBuf {
    if let Some(p) = flag {
        return expand_home(p);
    }
    if let Some(p) = std::env::var_os(CONFIG_ENV).filter(|v| !v.is_empty()) {
        return expand_home(Path::new(&p));
    }
    default_settings_path()
}

pub fn default_settings_path() -> PathBuf {
    match directories::ProjectDirs::from("", "", "ovpn-otp") {
        Some(d) => d.config_dir().join("settings.toml"),
        None => PathBuf::from("ovpn-otp-settings.toml"),
    }
}

fn expand_home(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("~") {
        if let Some(home) = directories::BaseDirs::new() {
            return home.home_dir().join(rest);
        }
    }
    p.to_path_buf()
}

/// Load settings. A missing file gives the defaults, so first start works.
pub fn load(path: &Path) -> Result<LoadedSettings, SettingsError> {
    let settings = match std::fs::read_to_string(path) {
        Ok(text) => Settings::from_toml(&text).map_err(|e| SettingsError::Parse {
            path: path.to_path_buf(),
            source: Box::new(e),
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
        Err(e) => {
            return Err(SettingsError::Read {
                path: path.to_path_buf(),
                source: e,
            })
        }
    };
    Ok(LoadedSettings {
        path: path.to_path_buf(),
        settings,
    })
}

/// Save settings, creating the folder if needed.
pub fn save(path: &Path, settings: &Settings) -> Result<(), SettingsError> {
    let err = |source| SettingsError::Write {
        path: path.to_path_buf(),
        source,
    };
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(err)?;
    }
    let text = format!("{HEADER}{}", settings.to_toml());
    std::fs::write(path, text).map_err(err)
}

const HEADER: &str = "# ovpn-otp settings. No secrets belong in this file: the login is kept in\n\
# the OS credential store and the authenticator code is typed at connect time.\n\
# See https://github.com/kiatng/ovpn-otp#settings for every option.\n\n";

impl LoadedSettings {
    /// Resolve the profile path relative to the settings file.
    pub fn profile_path(&self) -> Option<PathBuf> {
        let p = self.settings.profile.path.trim();
        if p.is_empty() {
            return None;
        }
        let p = expand_home(Path::new(p));
        if p.is_absolute() {
            Some(p)
        } else {
            let base = self.path.parent().unwrap_or(Path::new("."));
            Some(base.join(p))
        }
    }

    /// The profile text and the folder that relative paths inside it refer to.
    pub fn profile_text(&self) -> Result<(String, PathBuf), SettingsError> {
        if let Some(p) = self.profile_path() {
            let text = std::fs::read_to_string(&p).map_err(|e| SettingsError::Profile {
                path: p.clone(),
                source: e,
            })?;
            let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
            return Ok((text, dir));
        }
        let inline = self.settings.profile.inline.trim();
        if inline.is_empty() {
            return Err(SettingsError::NoProfile(self.path.clone()));
        }
        let dir = self.path.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok((inline.to_string(), dir))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_gives_defaults() {
        let s = Settings::from_toml("").unwrap();
        assert_eq!(s, Settings::default());
        assert_eq!(s.keepalive.ping, 10);
        assert_eq!(s.code.digits, 6);
    }

    #[test]
    fn round_trips() {
        let mut s = Settings::default();
        s.name = "work".into();
        s.profile.path = "work.ovpn".into();
        s.check.host = "10.0.0.1:443".into();
        s.openvpn.linux.command_prefix = Some(vec![]);
        let back = Settings::from_toml(&s.to_toml()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Settings::from_toml("pasword = \"x\"").is_err());
    }

    #[test]
    fn profile_path_is_relative_to_settings_file() {
        let dir = tempfile::tempdir().unwrap();
        let settings_file = dir.path().join("settings.toml");
        std::fs::write(&settings_file, "name = \"w\"\n[profile]\npath = \"w.ovpn\"\n").unwrap();
        std::fs::write(dir.path().join("w.ovpn"), "client\n").unwrap();
        let loaded = load(&settings_file).unwrap();
        assert_eq!(loaded.profile_path().unwrap(), dir.path().join("w.ovpn"));
        let (text, base) = loaded.profile_text().unwrap();
        assert_eq!(text, "client\n");
        assert_eq!(base, dir.path());
    }

    #[test]
    fn missing_file_is_defaults_and_missing_profile_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let loaded = load(&dir.path().join("none.toml")).unwrap();
        assert_eq!(loaded.settings, Settings::default());
        assert!(matches!(
            loaded.profile_text(),
            Err(SettingsError::NoProfile(_))
        ));
    }

    #[test]
    fn save_then_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/settings.toml");
        let mut s = Settings::default();
        s.profile.inline = "client\nremote example.org 1194\n".into();
        save(&path, &s).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# ovpn-otp settings"));
        assert_eq!(load(&path).unwrap().settings, s);
    }

    #[test]
    fn flag_beats_env() {
        assert_eq!(
            settings_path(Some(Path::new("/x/s.toml"))),
            PathBuf::from("/x/s.toml")
        );
    }
}
