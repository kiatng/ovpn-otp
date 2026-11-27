//! Core of ovpn-otp: drive the standard `openvpn` program through its
//! management interface, with a saved login and a separate authenticator code.
//!
//! * [`settings`] — the shared TOML settings file (no secrets in it);
//! * [`keys`] — read and change one setting by its name;
//! * [`credentials`] — the saved login in the OS credential store;
//! * [`profile`] — turn a `.ovpn` profile into the config OpenVPN runs;
//! * [`launch`] — start OpenVPN (directly, or via the Windows interactive service);
//! * [`mgmt`] — the management protocol parser;
//! * [`session`] — one session: log in, watch, keep alive, reconnect;
//! * [`snapshot`] — fold session events into the current picture;
//! * [`runtime`] — files that let other commands see and stop a session;
//! * [`report`] — the status report and exit codes that scripts read;
//! * [`diagnostics`] — the "copy diagnostics" report;
//! * [`connect`] — glue: settings + login + code -> a running session.

pub mod connect;
pub mod credentials;
pub mod diagnostics;
pub mod keys;
pub mod launch;
pub mod mgmt;
pub mod profile;
pub mod reach;
pub mod report;
pub mod runtime;
pub mod session;
pub mod settings;
pub mod snapshot;

pub mod update;
