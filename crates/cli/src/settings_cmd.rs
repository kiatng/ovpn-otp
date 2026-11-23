//! Commands that read and change what a connect uses: `config`, `profile`
//! and `login`.
//!
//! Everything the window lets you set is here too: every setting by name
//! (`config get`, `set`, `unset`), the profile, and the saved login.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::json;

use ovpn_otp_core::credentials::{CredentialStore, Login, Secret};
use ovpn_otp_core::keys::{self, Kind, KEYS};
use ovpn_otp_core::profile;
use ovpn_otp_core::report::exit_code;
use ovpn_otp_core::runtime::RuntimeDir;
use ovpn_otp_core::settings::{self, LoadedSettings, Settings};

use crate::{prompt_line, stdin_line, usage_error, ConfigCmd, LoginCmd, ProfileCmd};

fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON values always print")
    );
}

/// Say so when a session is running: it keeps the settings it started with.
fn note_running_session() {
    if let Ok(rt) = RuntimeDir::open() {
        if rt.live_session().is_some() {
            eprintln!(
                "A session is running. It keeps the old settings; run `ovpn-otp reconnect` to use the new ones."
            );
        }
    }
}

/// The profile path to store in the settings: relative when the profile sits
/// in the folder of the settings file (or below it), so that the two can
/// move together to another machine.
pub fn profile_setting(profile: &Path, settings_path: &Path) -> Result<String> {
    let profile = std::fs::canonicalize(profile)
        .with_context(|| format!("cannot find the profile {}", profile.display()))?;
    if !profile.is_file() {
        bail!("{} is not a file", profile.display());
    }
    let dir = settings_path.parent().unwrap_or(Path::new("."));
    Ok(
        match std::fs::canonicalize(dir)
            .ok()
            .and_then(|d| profile.strip_prefix(&d).ok().map(Path::to_path_buf))
        {
            Some(rel) => rel.display().to_string(),
            None => profile.display().to_string(),
        },
    )
}

// ---------------------------------------------------------------- config

pub fn cmd_config(path: &Path, action: ConfigCmd) -> Result<u8> {
    match action {
        ConfigCmd::Path => {
            println!("{}", path.display());
            if !path.exists() {
                eprintln!("(the file does not exist yet; create it with `ovpn-otp config init --profile FILE`)");
            }
        }
        ConfigCmd::Show { json } => {
            let loaded = settings::load(path)?;
            if json {
                print_json(&serde_json::to_value(&loaded.settings)?);
            } else {
                println!("# {}", path.display());
                print!("{}", loaded.settings.to_toml());
            }
        }
        ConfigCmd::Get { key, json } => {
            let loaded = settings::load(path)?;
            let value =
                keys::get(&loaded.settings, &key).map_err(|e| usage_error(e.to_string()))?;
            if json {
                print_json(&serde_json::to_value(&value)?);
            } else {
                match value {
                    Some(v) => println!("{}", keys::to_text(&v)),
                    None => eprintln!("({key} is not set)"),
                }
            }
        }
        ConfigCmd::Set { key, values } => {
            let loaded = settings::load(path)?;
            let changed = keys::set(&loaded.settings, &key, &values)
                .map_err(|e| usage_error(e.to_string()))?;
            save_changed(path, &loaded.settings, &changed, &key)?;
        }
        ConfigCmd::Unset { key } => {
            let loaded = settings::load(path)?;
            let changed =
                keys::unset(&loaded.settings, &key).map_err(|e| usage_error(e.to_string()))?;
            save_changed(path, &loaded.settings, &changed, &key)?;
        }
        ConfigCmd::Keys { json } => {
            let loaded = settings::load(path)?;
            print_keys(&loaded.settings, json)?;
        }
        ConfigCmd::Edit => return edit(path),
        ConfigCmd::Init {
            profile,
            name,
            force,
        } => {
            if path.exists() && !force {
                bail!(
                    "{} already exists (use --force to replace it)",
                    path.display()
                );
            }
            let mut s = Settings {
                name,
                ..Default::default()
            };
            s.profile.path = profile_setting(&profile, path)?;
            settings::save(path, &s)?;
            println!("Wrote {}", path.display());
            println!("Next: `ovpn-otp login` to save your user name and password.");
        }
    }
    Ok(exit_code::OK)
}

fn save_changed(path: &Path, before: &Settings, after: &Settings, key: &str) -> Result<()> {
    if before == after && path.exists() {
        eprintln!("{key} already has that value.");
        return Ok(());
    }
    settings::save(path, after)?;
    let key = key.trim();
    match keys::get(after, key)? {
        Some(v) => eprintln!("{key} = {}", keys::to_text(&v).replace('\n', ", ")),
        None => eprintln!("{key} is not set any more."),
    }
    note_running_session();
    Ok(())
}

fn print_keys(settings: &Settings, json: bool) -> Result<()> {
    if json {
        let mut list = Vec::new();
        for k in KEYS {
            list.push(json!({
                "key": k.name,
                "kind": k.kind.label(),
                "value": serde_json::to_value(keys::get(settings, k.name)?)?,
                "help": k.help,
            }));
        }
        print_json(&serde_json::Value::Array(list));
        return Ok(());
    }
    for k in KEYS {
        let value = match keys::get(settings, k.name)? {
            None => "(not set)".to_string(),
            Some(v) if matches!(k.kind, Kind::List | Kind::OptionalList) => {
                format!("[{}]", keys::to_text(&v).replace('\n', ", "))
            }
            // A whole profile does not fit on a line.
            Some(v) if k.name == "profile.inline" && !keys::to_text(&v).is_empty() => {
                format!("({} bytes of profile text)", keys::to_text(&v).len())
            }
            Some(v) => keys::to_text(&v),
        };
        println!("{} = {value}", k.name);
        println!("    {} ({})", k.help, k.kind.label());
    }
    Ok(())
}

/// The editor to open the settings file with, as a program and its options.
fn editor() -> Vec<String> {
    for var in ["VISUAL", "EDITOR"] {
        if let Ok(v) = std::env::var(var) {
            let words: Vec<String> = v.split_whitespace().map(str::to_string).collect();
            if !words.is_empty() {
                return words;
            }
        }
    }
    if cfg!(windows) {
        vec!["notepad".into()]
    } else {
        vec!["vi".into()]
    }
}

fn edit(path: &Path) -> Result<u8> {
    if !path.exists() {
        settings::save(path, &Settings::default())?;
        eprintln!("Created {} with the default settings.", path.display());
    }
    let words = editor();
    let status = std::process::Command::new(&words[0])
        .args(&words[1..])
        .arg(path)
        .status()
        .with_context(|| {
            format!(
                "cannot start the editor `{}`; set EDITOR to the one you use",
                words[0]
            )
        })?;
    if !status.success() {
        bail!("the editor `{}` ended with an error", words[0]);
    }
    // Read it back, so that a mistake shows now and not at the next connect.
    let loaded = settings::load(path)?;
    profile::extra_option_lines(&loaded.settings.openvpn.extra_options)?;
    eprintln!("{} is fine.", path.display());
    note_running_session();
    Ok(exit_code::OK)
}

// ---------------------------------------------------------------- profile

/// What `profile show` says about the profile in use.
#[derive(Debug, PartialEq, Eq)]
pub struct ProfileReport {
    /// The file, or `None` when the profile text is in the settings file.
    pub path: Option<PathBuf>,
    pub servers: Vec<String>,
    pub static_challenge: bool,
    pub notes: Vec<String>,
    /// Why the profile cannot be used, when it cannot.
    pub error: Option<String>,
}

pub fn profile_report(loaded: &LoadedSettings) -> ProfileReport {
    let mut report = ProfileReport {
        path: loaded.profile_path(),
        servers: Vec::new(),
        static_challenge: false,
        notes: Vec::new(),
        error: None,
    };
    let prepared = loaded
        .profile_text()
        .map_err(|e| e.to_string())
        .and_then(|(text, _)| profile::prepare(&text, &loaded.settings).map_err(|e| e.to_string()));
    match prepared {
        Ok(p) => {
            report.servers = p.server_labels();
            report.static_challenge = p.static_challenge;
            report.notes = p.notes;
        }
        Err(e) => report.error = Some(e),
    }
    report
}

impl ProfileReport {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "path": self.path.as_ref().map(|p| p.display().to_string()),
            "inline": self.path.is_none() && self.error.is_none(),
            "servers": self.servers,
            "static_challenge": self.static_challenge,
            "notes": self.notes,
            "error": self.error,
        })
    }

    fn to_text(&self) -> String {
        let mut out = String::new();
        let mut line = |label: &str, value: &str| {
            out.push_str(&format!("{label:<11} {value}\n"));
        };
        match &self.path {
            Some(p) => line("Profile:", &p.display().to_string()),
            None if self.error.is_none() => line("Profile:", "inside the settings file"),
            None => line("Profile:", "none"),
        }
        if let Some(e) = &self.error {
            line("Problem:", e);
            return out;
        }
        for (i, server) in self.servers.iter().enumerate() {
            line(if i == 0 { "Server:" } else { "" }, server);
        }
        line(
            "Code:",
            if self.static_challenge {
                "asked for by the server on its own (static-challenge)"
            } else {
                "added to the end of the password"
            },
        );
        for note in &self.notes {
            line("Note:", note);
        }
        out
    }
}

/// Folders where a profile is usually kept: next to the settings file, next
/// to the profile in use, and where OpenVPN itself looks.
fn profile_folders(loaded: &LoadedSettings) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut add = |d: PathBuf| {
        if !d.as_os_str().is_empty() && !dirs.contains(&d) {
            dirs.push(d);
        }
    };
    if let Some(d) = loaded.path.parent() {
        add(d.to_path_buf());
    }
    if let Some(d) = loaded
        .profile_path()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        add(d);
    }
    if cfg!(windows) {
        if let Some(home) = std::env::var_os("USERPROFILE") {
            add(Path::new(&home).join("OpenVPN").join("config"));
        }
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            add(Path::new(&pf).join("OpenVPN").join("config"));
        }
    } else {
        add(PathBuf::from("/etc/openvpn/client"));
    }
    dirs
}

/// The `.ovpn` files in `dir` and one level below it, sorted.
pub fn find_profiles(dir: &Path) -> Vec<PathBuf> {
    fn scan(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.is_dir() {
                if depth > 0 {
                    scan(&path, depth - 1, out);
                }
            } else if path
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("ovpn"))
            {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    scan(dir, 1, &mut out);
    out.sort();
    out
}

/// The servers a profile file points at, for the list.
fn servers_in(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| profile::prepare(&text, &Settings::default()).ok())
        .map(|p| p.server_labels())
        .unwrap_or_default()
}

pub fn cmd_profile(path: &Path, action: ProfileCmd) -> Result<u8> {
    let loaded = settings::load(path)?;
    match action {
        ProfileCmd::Show { json } => {
            let report = profile_report(&loaded);
            if json {
                print_json(&report.to_json());
            } else {
                print!("{}", report.to_text());
            }
            Ok(if report.error.is_some() {
                exit_code::FAILED
            } else {
                exit_code::OK
            })
        }
        ProfileCmd::Set { file } => {
            let mut changed = loaded.settings.clone();
            changed.profile.path = profile_setting(&file, path)?;
            settings::save(path, &changed)?;
            let now = LoadedSettings {
                path: path.to_path_buf(),
                settings: changed,
            };
            let report = profile_report(&now);
            eprint!("{}", report.to_text());
            if !now.settings.profile.inline.trim().is_empty() {
                eprintln!(
                    "The profile text inside the settings file (profile.inline) is not used while profile.path is set."
                );
            }
            note_running_session();
            Ok(if report.error.is_some() {
                exit_code::FAILED
            } else {
                exit_code::OK
            })
        }
        ProfileCmd::List { folders, json } => {
            let dirs = if folders.is_empty() {
                profile_folders(&loaded)
            } else {
                folders
            };
            let in_use = loaded
                .profile_path()
                .and_then(|p| std::fs::canonicalize(p).ok());
            let mut found: Vec<PathBuf> = Vec::new();
            for dir in &dirs {
                for file in find_profiles(dir) {
                    let file = std::fs::canonicalize(&file).unwrap_or(file);
                    if !found.contains(&file) {
                        found.push(file);
                    }
                }
            }
            if json {
                let list: Vec<_> = found
                    .iter()
                    .map(|f| {
                        json!({
                            "path": f.display().to_string(),
                            "in_use": Some(f) == in_use.as_ref(),
                            "servers": servers_in(f),
                        })
                    })
                    .collect();
                print_json(&serde_json::Value::Array(list));
                return Ok(exit_code::OK);
            }
            if found.is_empty() {
                let looked: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
                eprintln!("No .ovpn files in: {}", looked.join(", "));
                return Ok(exit_code::OK);
            }
            for f in &found {
                let mark = if Some(f) == in_use.as_ref() { "*" } else { " " };
                println!("{mark} {}  {}", f.display(), servers_in(f).join(", "));
            }
            eprintln!("(* is the profile in use; choose another with `ovpn-otp profile set FILE`)");
            Ok(exit_code::OK)
        }
    }
}

// ---------------------------------------------------------------- login

/// Save the login under the name of the connection.
pub fn login_set(
    store: &dyn CredentialStore,
    name: &str,
    username: &str,
    password: Secret,
) -> Result<()> {
    let username = username.trim();
    if username.is_empty() {
        bail!("the user name is empty");
    }
    if password.is_empty() {
        bail!("the password is empty");
    }
    store.save(
        name,
        &Login {
            username: username.to_string(),
            password,
        },
    )?;
    Ok(())
}

/// What `login show` prints: who is saved, and never the password.
pub fn login_show(store: &dyn CredentialStore, name: &str) -> Result<serde_json::Value> {
    let saved = store.load(name)?;
    Ok(json!({
        "name": name,
        "saved": saved.is_some(),
        "username": saved.map(|l| l.username),
    }))
}

pub fn cmd_login(store: &dyn CredentialStore, path: &Path, action: LoginCmd) -> Result<u8> {
    let loaded = settings::load(path)?;
    let name = &loaded.settings.name;
    match action {
        LoginCmd::Set {
            username,
            password_stdin,
        } => {
            let username = match username {
                Some(u) => u,
                None if password_stdin || !std::io::stdin().is_terminal() => {
                    // Keep the user name that is saved, so a script can change
                    // only the password.
                    match store.load(name) {
                        Ok(Some(l)) => l.username,
                        _ => {
                            return Err(usage_error(
                                "give the user name with --username (none is saved yet)",
                            ))
                        }
                    }
                }
                None => prompt_line("User name: ")?,
            };
            let password = if password_stdin {
                Secret::new(stdin_line()?.unwrap_or_default())
            } else {
                Secret::new(rpassword::prompt_password("Password (hidden): ")?)
            };
            login_set(store, name, &username, password)?;
            println!("Saved the login for '{name}' in the OS credential store.");
        }
        LoginCmd::Show { json } => {
            let shown = login_show(store, name)?;
            if json {
                print_json(&shown);
            } else {
                match shown["username"].as_str() {
                    Some(u) => {
                        println!("Connection: {name}");
                        println!("User name:  {u}");
                        println!("Password:   saved (never shown)");
                    }
                    None => {
                        println!("Connection: {name}");
                        println!("No login is saved. Save one with `ovpn-otp login set`.");
                    }
                }
            }
        }
        LoginCmd::Clear => {
            store.delete(name)?;
            println!("Removed the saved login for '{name}'.");
        }
    }
    Ok(exit_code::OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ovpn_otp_core::credentials::MemoryStore;

    #[test]
    fn login_is_saved_shown_without_the_password_and_cleared() {
        let store = MemoryStore::default();
        let shown = login_show(&store, "work").unwrap();
        assert_eq!(
            shown,
            json!({"name": "work", "saved": false, "username": null})
        );

        login_set(&store, "work", " alice ", Secret::new("s3cret-Pw")).unwrap();
        let shown = login_show(&store, "work").unwrap();
        assert_eq!(
            shown,
            json!({"name": "work", "saved": true, "username": "alice"})
        );
        assert!(!shown.to_string().contains("s3cret-Pw"));
        // The password itself did arrive in the store.
        assert_eq!(
            store.load("work").unwrap().unwrap().password.expose(),
            "s3cret-Pw"
        );
        // Another connection has its own login.
        assert_eq!(login_show(&store, "home").unwrap()["saved"], false);

        store.delete("work").unwrap();
        assert_eq!(login_show(&store, "work").unwrap()["saved"], false);
    }

    #[test]
    fn an_empty_user_name_or_password_is_not_saved() {
        let store = MemoryStore::default();
        assert!(login_set(&store, "work", "  ", Secret::new("pw")).is_err());
        assert!(login_set(&store, "work", "alice", Secret::new("")).is_err());
        assert_eq!(login_show(&store, "work").unwrap()["saved"], false);
    }

    fn loaded_in(dir: &Path, edit: impl FnOnce(&mut Settings)) -> LoadedSettings {
        let mut settings = Settings::default();
        edit(&mut settings);
        LoadedSettings {
            path: dir.join("settings.toml"),
            settings,
        }
    }

    #[test]
    fn the_profile_report_names_the_file_and_the_servers() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("work.ovpn"),
            "client\nproto tcp\nremote vpn.example.org 8443\nremote 10.255.0.1 8443\ncipher AES-128-CBC\n",
        )
        .unwrap();
        let loaded = loaded_in(tmp.path(), |s| s.profile.path = "work.ovpn".into());
        let report = profile_report(&loaded);
        assert_eq!(report.path, Some(tmp.path().join("work.ovpn")));
        assert_eq!(report.servers, vec!["vpn.example.org:8443 (tcp)"]);
        assert_eq!(report.error, None);
        assert_eq!(report.notes.len(), 2, "{:?}", report.notes);
        let text = report.to_text();
        assert!(
            text.contains("Server:     vpn.example.org:8443 (tcp)"),
            "{text}"
        );
        assert!(text.contains("added to the end of the password"), "{text}");
        let v = report.to_json();
        assert_eq!(v["inline"], false);
        assert_eq!(v["servers"][0], "vpn.example.org:8443 (tcp)");
        assert!(v["error"].is_null());

        let missing = loaded_in(tmp.path(), |s| s.profile.path = "gone.ovpn".into());
        let report = profile_report(&missing);
        assert!(report.error.as_deref().unwrap().contains("gone.ovpn"));
        assert!(report.to_text().contains("Problem:"));

        let none = profile_report(&loaded_in(tmp.path(), |_| {}));
        assert!(none.error.is_some());
        assert!(none.to_text().starts_with("Profile:    none"));

        let inline = loaded_in(tmp.path(), |s| {
            s.profile.inline =
                "client\nremote a.example.org 1194\nstatic-challenge \"Code\" 1\n".into()
        });
        let report = profile_report(&inline);
        assert_eq!(report.to_json()["inline"], true);
        assert!(report.static_challenge);
        assert!(report.to_text().contains("inside the settings file"));
    }

    #[test]
    fn finds_profiles_in_a_folder_and_one_level_below() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::create_dir_all(d.join("sub/deeper")).unwrap();
        for f in [
            "b.ovpn",
            "a.OVPN",
            "notes.txt",
            "sub/c.ovpn",
            "sub/deeper/d.ovpn",
        ] {
            std::fs::write(d.join(f), "client\nremote x.example.org 1194\n").unwrap();
        }
        let found: Vec<PathBuf> = find_profiles(d)
            .iter()
            .map(|p| p.strip_prefix(d).unwrap().to_path_buf())
            .collect();
        assert_eq!(
            found,
            vec![
                PathBuf::from("a.OVPN"),
                PathBuf::from("b.ovpn"),
                Path::new("sub").join("c.ovpn")
            ]
        );
        assert!(find_profiles(&d.join("nowhere")).is_empty());
        assert_eq!(
            servers_in(&d.join("b.ovpn")),
            vec!["x.example.org:1194 (udp)"]
        );
    }

    #[test]
    fn a_profile_next_to_the_settings_file_is_stored_as_a_relative_path() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        std::fs::create_dir_all(d.join("conf/vpn")).unwrap();
        std::fs::write(d.join("conf/vpn/work.ovpn"), "client\n").unwrap();
        std::fs::write(d.join("other.ovpn"), "client\n").unwrap();
        let settings_file = d.join("conf/settings.toml");
        let rel = profile_setting(&d.join("conf/vpn/work.ovpn"), &settings_file).unwrap();
        assert_eq!(PathBuf::from(rel), Path::new("vpn").join("work.ovpn"));
        let abs = profile_setting(&d.join("other.ovpn"), &settings_file).unwrap();
        assert!(Path::new(&abs).is_absolute(), "{abs}");
        assert!(profile_setting(&d.join("gone.ovpn"), &settings_file).is_err());
        assert!(profile_setting(&d.join("conf"), &settings_file).is_err());
    }
}
