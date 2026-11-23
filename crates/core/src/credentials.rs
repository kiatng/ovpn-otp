//! Saved login (user name and password) in the OS credential store.
//!
//! Windows uses Credential Manager; Linux uses the Secret Service (GNOME
//! Keyring, KWallet, KeePassXC, ...). Nothing secret is ever written to a file.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

const SERVICE: &str = "ovpn-otp";

/// A string that is kept out of `Debug` output and wiped when dropped.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Secret(s.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Overwrite the bytes before the memory is freed.
        // SAFETY: writing zero bytes keeps the string valid UTF-8.
        unsafe {
            for b in self.0.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// A saved login.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Login {
    pub username: String,
    pub password: Secret,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential store: {0}")]
    Store(String),
    #[error("saved login is damaged; save it again")]
    Corrupt,
}

/// Somewhere to keep logins.
pub trait CredentialStore: Send + Sync {
    fn load(&self, name: &str) -> Result<Option<Login>, CredentialError>;
    fn save(&self, name: &str, login: &Login) -> Result<(), CredentialError>;
    fn delete(&self, name: &str) -> Result<(), CredentialError>;
}

fn encode(login: &Login) -> Secret {
    Secret::new(
        serde_json::json!({
            "username": login.username,
            "password": login.password.expose(),
        })
        .to_string(),
    )
}

fn decode(text: &str) -> Result<Login, CredentialError> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|_| CredentialError::Corrupt)?;
    let username = v["username"].as_str().ok_or(CredentialError::Corrupt)?;
    let password = v["password"].as_str().ok_or(CredentialError::Corrupt)?;
    Ok(Login {
        username: username.to_string(),
        password: Secret::new(password),
    })
}

/// The OS credential store.
#[derive(Debug, Default, Clone, Copy)]
pub struct KeyringStore;

impl KeyringStore {
    fn entry(name: &str) -> Result<keyring::Entry, CredentialError> {
        keyring::Entry::new(SERVICE, name).map_err(|e| CredentialError::Store(e.to_string()))
    }
}

impl CredentialStore for KeyringStore {
    fn load(&self, name: &str) -> Result<Option<Login>, CredentialError> {
        match Self::entry(name)?.get_password() {
            Ok(text) => {
                let text = Secret::new(text);
                decode(text.expose()).map(Some)
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CredentialError::Store(e.to_string())),
        }
    }

    fn save(&self, name: &str, login: &Login) -> Result<(), CredentialError> {
        Self::entry(name)?
            .set_password(encode(login).expose())
            .map_err(|e| CredentialError::Store(e.to_string()))
    }

    fn delete(&self, name: &str) -> Result<(), CredentialError> {
        match Self::entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CredentialError::Store(e.to_string())),
        }
    }
}

/// An in-memory store, for tests and for "do not remember" sessions.
#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<HashMap<String, Secret>>);

impl CredentialStore for MemoryStore {
    fn load(&self, name: &str) -> Result<Option<Login>, CredentialError> {
        let map = self.0.lock().unwrap();
        map.get(name).map(|s| decode(s.expose())).transpose()
    }
    fn save(&self, name: &str, login: &Login) -> Result<(), CredentialError> {
        self.0
            .lock()
            .unwrap()
            .insert(name.to_string(), encode(login));
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<(), CredentialError> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_hidden_in_debug() {
        let l = Login {
            username: "alice".into(),
            password: Secret::new("hunter2"),
        };
        let dbg = format!("{l:?}");
        assert!(dbg.contains("alice"));
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn memory_store_round_trip() {
        let store = MemoryStore::default();
        assert_eq!(store.load("w").unwrap(), None);
        let login = Login {
            username: "alice".into(),
            password: Secret::new("p\"w\\x"),
        };
        store.save("w", &login).unwrap();
        assert_eq!(store.load("w").unwrap(), Some(login));
        store.delete("w").unwrap();
        assert_eq!(store.load("w").unwrap(), None);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(matches!(decode("nope"), Err(CredentialError::Corrupt)));
        assert!(matches!(
            decode("{\"username\":\"a\"}"),
            Err(CredentialError::Corrupt)
        ));
    }
}
