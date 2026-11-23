//! Glue used by both the GUI and the CLI: settings + login + code -> a running session.

use std::path::PathBuf;

use crate::credentials::Login;
use crate::launch::{LaunchError, LaunchRequest, Launcher, OpenVpnLauncher};
use crate::profile::{self, PreparedProfile, ProfileError};
use crate::runtime::RuntimeDir;
use crate::session::{self, SessionHandle, SessionOptions};
use crate::settings::{LoadedSettings, SettingsError};

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
            verb: settings.openvpn.verb.unwrap_or(3).clamp(1, 11),
        },
        retry_login: true,
        remotes: prepared.remotes.clone(),
        remote_count: prepared.remote_count,
        notes: prepared.notes,
    };
    Ok(Prepared {
        options,
        launcher: Box::new(launcher),
        config_path,
        remotes: prepared.remotes,
        static_challenge: prepared.static_challenge,
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

    #[test]
    fn a_default_settings_file_has_no_user_name_in_it() {
        let text = Settings::default().to_toml().to_lowercase();
        assert!(!text.contains("user"), "{text}");
        let example = include_str!("../../../examples/settings.toml");
        assert!(Settings::from_toml(example).is_ok());
        assert!(!example.to_lowercase().contains("username"));
    }
}
