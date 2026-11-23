//! Glue used by both the GUI and the CLI: settings + login + code -> a running session.

use std::path::PathBuf;

use crate::credentials::Login;
use crate::launch::{LaunchError, LaunchRequest, Launcher, OpenVpnLauncher};
use crate::profile;
use crate::runtime::RuntimeDir;
use crate::session::{self, SessionHandle, SessionOptions};
use crate::settings::{LoadedSettings, SettingsError};

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Settings(#[from] SettingsError),
    #[error(transparent)]
    Launch(#[from] LaunchError),
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

/// Prepare everything for a session without starting it.
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
    let (text, work_dir) = loaded.profile_text()?;
    let prepared = profile::prepare(&text, settings);
    let config_path = session::prepared_config_path(&runtime.path, &settings.name);
    crate::launch::write_private(&config_path, prepared.text.as_bytes()).map_err(|e| {
        ConnectError::Prepare {
            path: config_path.clone(),
            source: e,
        }
    })?;
    let launcher = OpenVpnLauncher::from_settings(settings)?;
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
