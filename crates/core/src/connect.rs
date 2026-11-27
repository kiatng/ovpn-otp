//! Glue used by both the GUI and the CLI: settings + login + code -> a running session.

use std::path::PathBuf;

use crate::credentials::Login;
use crate::launch::{LaunchError, LaunchRequest, Launcher, OpenVpnLauncher};
use crate::profile::{self, PreparedProfile, ProfileError};
use crate::runtime::{RuntimeDir, Using};
use crate::session::{self, SessionHandle, SessionOptions};
use crate::settings::{LoadedSettings, Settings, SettingsError};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error(transparent)]
    Launch(#[from] LaunchError),
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error("cannot write the prepared profile {path}: {source}")]
    Prepare {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("no user name saved for '{0}'; log in first")]
    NoLogin(String),
}

/// A session that is ready to start.
pub struct Prepared {
    pub options: SessionOptions,
    pub launcher: Box<dyn Launcher>,
    /// The prepared profile file; delete it when the session ends.
    pub config_path: PathBuf,
    /// The `remote` the profile points at, for display.
    pub remotes: Vec<String>,
    pub static_challenge: bool,
    /// What the session uses, for the status.
    pub using: Using,
}

/// The log level OpenVPN gets as its one `--verb`: a `verb` in the extra
/// options wins, then the `openvpn.verb` setting, then 3.
pub fn effective_verb(settings: &Settings, prepared: &PreparedProfile) -> u8 {
    prepared.verb.or(settings.openvpn.verb).unwrap_or(3).min(11)
}

/// What a session with these settings uses: connection name, settings file,
/// profile, servers and user name. Works without a readable profile too; the
/// servers are then left empty.
pub fn describe(loaded: &LoadedSettings, username: &str) -> Using {
    let settings = &loaded.settings;
    let profile = match loaded.profile_path() {
        Some(p) => p.display().to_string(),
        None if settings.profile.inline.trim().is_empty() => String::new(),
        None => "inside the settings file".to_string(),
    };
    let servers = loaded
        .profile_text()
        .ok()
        .and_then(|(text, _)| profile::prepare(&text, settings).ok())
        .map(|p| p.server_labels())
        .unwrap_or_default();
    Using {
        name: settings.name.clone(),
        settings: loaded.path.display().to_string(),
        profile,
        servers,
        username: username.trim().to_string(),
    }
}

/// Check that a session could be prepared, without writing anything: the
/// profile can be read, the extra options are well formed, and OpenVPN is
/// there. Gives the profile as OpenVPN would get it.
pub fn check(loaded: &LoadedSettings) -> Result<PreparedProfile, ConnectError> {
    let settings = &loaded.settings;
    let (text, _) = loaded.profile_text()?;
    let prepared = profile::prepare(&text, settings)?;
    OpenVpnLauncher::from_settings(settings)?;
    Ok(prepared)
}

/// Prepare everything for a session without starting it.
///
/// The session asks again for a code when the first login is rejected
/// ([`SessionOptions::retry_login`]); a caller with nobody to ask turns that off.
pub fn prepare(
    loaded: &LoadedSettings,
    runtime: &RuntimeDir,
    login: Login,
    code: Option<String>,
) -> Result<Prepared, ConnectError> {
    if login.username.trim().is_empty() {
        return Err(ConnectError::NoLogin(loaded.settings.name.clone()));
    }
    let settings = &loaded.settings;
    let launcher = OpenVpnLauncher::from_settings(settings)?;
    let (text, work_dir) = loaded.profile_text()?;
    let prepared = profile::prepare(&text, settings)?;
    let using = Using {
        servers: prepared.server_labels(),
        ..describe(loaded, &login.username)
    };
    let verb = if cfg!(feature = "diagnostic-test") {
        6
    } else {
        effective_verb(settings, &prepared)
    };
    let config_path = session::prepared_config_path(&runtime.path, &settings.name);
    crate::launch::write_private(&config_path, prepared.text.as_bytes()).map_err(|e| {
        ConnectError::Prepare {
            path: config_path.clone(),
            source: e,
        }
    })?;
    let options = SessionOptions {
        login,
        code,
        code_digits: settings.code.digits,
        keepalive: settings.keepalive.clone(),
        reach: settings.check.clone(),
        launch: LaunchRequest {
            config: config_path.clone(),
            work_dir,
            private_dir: runtime.path.clone(),
            verb,
        },
        retry_login: true,
        remotes: prepared.remotes.clone(),
        remote_count: prepared.remote_count,
        notes: prepared.notes,
        connect_timeout: std::time::Duration::from_secs(settings.connect.timeout.into()),
    };
    Ok(Prepared {
        options,
        launcher: Box::new(launcher),
        config_path,
        remotes: prepared.remotes,
        static_challenge: prepared.static_challenge,
        using,
    })
}

impl Prepared {
    pub fn start(self) -> (SessionHandle, PathBuf) {
        let path = self.config_path.clone();
        (session::start(self.options, self.launcher), path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::Secret;
    use crate::settings::Settings;

    /// The user name is never made up: without one there is no session.
    #[test]
    fn a_login_without_a_user_name_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = LoadedSettings {
            path: tmp.path().join("settings.toml"),
            settings: Settings::default(),
        };
        let runtime = RuntimeDir::at(tmp.path().join("run")).unwrap();
        for username in ["", "   "] {
            let login = Login {
                username: username.into(),
                password: Secret::new("pw"),
            };
            let result = prepare(&loaded, &runtime, login, Some("123456".into()));
            assert!(
                matches!(result, Err(ConnectError::NoLogin(_))),
                "a session was prepared without a user name"
            );
        }
        // Nothing was written for OpenVPN either.
        assert_eq!(std::fs::read_dir(&runtime.path).unwrap().count(), 0);
    }

    fn loaded_with(dir: &std::path::Path, edit: impl FnOnce(&mut Settings)) -> LoadedSettings {
        let mut settings = Settings {
            name: "work".into(),
            ..Settings::default()
        };
        settings.openvpn.linux.path = "/bin/sh".into();
        settings.openvpn.windows.path = "C:\\Windows\\System32\\cmd.exe".into();
        settings.openvpn.windows.launch = "direct".into();
        settings.openvpn.linux.command_prefix = Some(Vec::new());
        edit(&mut settings);
        LoadedSettings {
            path: dir.join("settings.toml"),
            settings,
        }
    }

    /// The fix for a `verb` in the extra options that lost against the
    /// `--verb 3` on the command line: OpenVPN gets one `--verb`, and the
    /// extra options win over the setting, which wins over 3.
    #[test]
    fn the_log_level_comes_from_the_extra_options_then_the_setting_then_3() {
        let tmp = tempfile::tempdir().unwrap();
        let runtime = RuntimeDir::at(tmp.path().join("run")).unwrap();
        let login = || Login {
            username: "alice".into(),
            password: Secret::new("pw"),
        };
        let verb_for = |extra: &[&str], setting: Option<u8>| {
            let loaded = loaded_with(tmp.path(), |s| {
                s.profile.inline = "client\nremote vpn.example.org 8443 tcp\nverb 1\n".into();
                s.openvpn.extra_options = extra.iter().map(|e| e.to_string()).collect();
                s.openvpn.verb = setting;
            });
            let prepared = prepare(&loaded, &runtime, login(), None).unwrap();
            let config = std::fs::read_to_string(&prepared.config_path).unwrap();
            let added = config
                .split("added by ovpn-otp")
                .nth(1)
                .unwrap()
                .to_string();
            assert!(
                !added.contains("verb"),
                "a second verb in the config: {added}"
            );
            prepared.options.launch.verb
        };
        assert_eq!(verb_for(&[], None), 3);
        assert_eq!(verb_for(&[], Some(5)), 5);
        assert_eq!(verb_for(&["verb 6"], None), 6);
        assert_eq!(verb_for(&["--verb", "6"], Some(5)), 6);
        assert_eq!(verb_for(&["mute 10"], Some(0)), 0);
    }

    #[test]
    fn describes_what_a_session_uses() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("work.ovpn"),
            "client\nproto tcp\nremote vpn.example.org 8443\nremote 10.255.0.1 8443\n",
        )
        .unwrap();
        let loaded = loaded_with(tmp.path(), |s| s.profile.path = "work.ovpn".into());
        let using = describe(&loaded, " alice ");
        assert_eq!(using.name, "work");
        assert_eq!(using.settings, loaded.path.display().to_string());
        assert_eq!(
            using.profile,
            tmp.path().join("work.ovpn").display().to_string()
        );
        // The private address is not tried, so it is not shown either.
        assert_eq!(using.servers, vec!["vpn.example.org:8443 (tcp)"]);
        assert_eq!(using.username, "alice");

        // The same reaches the session and from there the status file.
        let runtime = RuntimeDir::at(tmp.path().join("run")).unwrap();
        let login = Login {
            username: "alice".into(),
            password: Secret::new("pw"),
        };
        let prepared = prepare(&loaded, &runtime, login, None).unwrap();
        assert_eq!(prepared.using, using);
        assert_eq!(
            prepared.options.connect_timeout,
            std::time::Duration::from_secs(60)
        );

        // A profile that is missing or inside the settings file.
        let missing = loaded_with(tmp.path(), |s| s.profile.path = "gone.ovpn".into());
        let using = describe(&missing, "");
        assert!(using.profile.ends_with("gone.ovpn"));
        assert!(using.servers.is_empty());
        let inline = loaded_with(tmp.path(), |s| {
            s.profile.inline = "client\nremote a.example.org 1194\n".into()
        });
        let using = describe(&inline, "");
        assert_eq!(using.profile, "inside the settings file");
        assert_eq!(using.servers, vec!["a.example.org:1194 (udp)"]);
        assert_eq!(describe(&loaded_with(tmp.path(), |_| {}), "").profile, "");
    }

    #[test]
    fn a_default_settings_file_has_no_user_name_in_it() {
        let text = Settings::default().to_toml().to_lowercase();
        assert!(!text.contains("user"), "{text}");
        let example = include_str!("../../../examples/settings.toml");
        assert!(Settings::from_toml(example).is_ok());
        assert!(!example.to_lowercase().contains("username"));
    }
}
