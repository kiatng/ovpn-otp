//! Settings by name, for `ovpn-otp config get`, `set` and `unset`.
//!
//! A name is the path of a setting in the settings file, with dots:
//! `keepalive.ping` is `ping` under `[keepalive]`. [`KEYS`] lists every
//! setting, so the command line can reach everything the settings file holds.

use crate::profile;
use crate::settings::Settings;

/// What kind of value a setting takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    /// `true` or `false`.
    Bool,
    /// A whole number, zero or more.
    Number,
    /// A whole number, or not set at all.
    OptionalNumber,
    /// Any number of text items.
    List,
    /// A list, or not set at all.
    OptionalList,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Bool => "true or false",
            Kind::Number | Kind::OptionalNumber => "number",
            Kind::List | Kind::OptionalList => "list",
        }
    }
}

/// One setting that can be read and changed by name.
#[derive(Debug, Clone, Copy)]
pub struct Key {
    pub name: &'static str,
    pub kind: Kind,
    /// One sentence on what the setting does.
    pub help: &'static str,
}

const fn key(name: &'static str, kind: Kind, help: &'static str) -> Key {
    Key { name, kind, help }
}

/// Every setting, in the order of the settings file.
pub const KEYS: &[Key] = &[
    key(
        "name",
        Kind::Text,
        "A short name for the connection. The saved login is stored under this name.",
    ),
    key(
        "profile.path",
        Kind::Text,
        "The .ovpn profile to use. A relative path is relative to the settings file.",
    ),
    key(
        "profile.inline",
        Kind::Text,
        "The profile text itself, instead of profile.path.",
    ),
    key(
        "profile.remote",
        Kind::Text,
        "A server as host:port to use instead of the remote lines in the profile.",
    ),
    key(
        "profile.allow_private_remotes",
        Kind::Bool,
        "Also try server addresses inside a private network when the profile has a public one.",
    ),
    key(
        "keepalive.ping",
        Kind::Number,
        "Seconds between keep-alive pings. 0 uses the value in the profile.",
    ),
    key(
        "keepalive.ping_restart",
        Kind::Number,
        "Seconds without anything from the server before OpenVPN restarts the connection. 0 uses the value in the profile.",
    ),
    key(
        "keepalive.auto_reconnect",
        Kind::Bool,
        "Reconnect after a drop. You are asked for a new code.",
    ),
    key(
        "keepalive.backoff_initial",
        Kind::Number,
        "Seconds to wait before the first try to reconnect. The wait doubles on each try.",
    ),
    key(
        "keepalive.backoff_max",
        Kind::Number,
        "Longest wait between tries to reconnect, in seconds.",
    ),
    key(
        "check.host",
        Kind::Text,
        "A host behind the VPN to check while connected: 10.0.0.1 uses ping, 10.0.0.1:443 opens a TCP connection. Empty turns the check off.",
    ),
    key("check.interval", Kind::Number, "Seconds between checks."),
    key(
        "code.digits",
        Kind::Number,
        "Digits in your authenticator code. 0 accepts any length.",
    ),
    key(
        "connect.timeout",
        Kind::Number,
        "Give up a connect that makes no progress for this many seconds. 0 waits as long as OpenVPN does.",
    ),
    key(
        "openvpn.extra_options",
        Kind::List,
        "Extra OpenVPN options added after the profile, one option per item, such as \"mute 10\".",
    ),
    key(
        "openvpn.verb",
        Kind::OptionalNumber,
        "How much OpenVPN logs, from 0 (nothing) to 11. 3 when not set.",
    ),
    key(
        "openvpn.windows.path",
        Kind::Text,
        "Where openvpn.exe is, on Windows. Empty finds it.",
    ),
    key(
        "openvpn.windows.launch",
        Kind::Text,
        "How OpenVPN is started on Windows: auto, service (no admin rights) or direct (needs admin).",
    ),
    key(
        "openvpn.linux.path",
        Kind::Text,
        "Where openvpn is, on Linux. Empty finds it.",
    ),
    key(
        "openvpn.linux.command_prefix",
        Kind::OptionalList,
        "The command put in front of openvpn on Linux to give it network rights. sudo -n when not set.",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("there is no setting `{name}`.{hint} `ovpn-otp config keys` lists every setting.")]
    Unknown { name: String, hint: String },
    #[error("{name}: {problem}")]
    Value { name: String, problem: String },
}

fn value_error(name: &str, problem: impl Into<String>) -> KeyError {
    KeyError::Value {
        name: name.to_string(),
        problem: problem.into(),
    }
}

/// The setting with this name, or an error that names the closest ones.
pub fn find(name: &str) -> Result<&'static Key, KeyError> {
    let wanted = name.trim();
    if let Some(k) = KEYS.iter().find(|k| k.name == wanted) {
        return Ok(k);
    }
    // Help with a forgotten section (`ping`) or a section alone (`keepalive`).
    let close: Vec<&str> = KEYS
        .iter()
        .map(|k| k.name)
        .filter(|k| {
            !wanted.is_empty()
                && (k.ends_with(&format!(".{wanted}")) || k.starts_with(&format!("{wanted}.")))
        })
        .collect();
    let hint = if close.is_empty() {
        String::new()
    } else {
        format!(" Did you mean {}?", close.join(", "))
    };
    Err(KeyError::Unknown {
        name: wanted.to_string(),
        hint,
    })
}

fn table_of(settings: &Settings) -> toml::Table {
    match toml::Value::try_from(settings) {
        Ok(toml::Value::Table(t)) => t,
        _ => toml::Table::new(),
    }
}

fn lookup<'a>(table: &'a toml::Table, name: &str) -> Option<&'a toml::Value> {
    let mut parts = name.split('.');
    let mut value = table.get(parts.next()?)?;
    for part in parts {
        value = value.as_table()?.get(part)?;
    }
    Some(value)
}

/// Put `value` at `name`, or remove what is there when `value` is `None`.
fn place(table: &mut toml::Table, name: &str, value: Option<toml::Value>) {
    let (section, last) = match name.rsplit_once('.') {
        Some((section, last)) => (Some(section), last),
        None => (None, name),
    };
    let mut at = table;
    for part in section.into_iter().flat_map(|s| s.split('.')) {
        let entry = at
            .entry(part.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !entry.is_table() {
            *entry = toml::Value::Table(toml::Table::new());
        }
        at = entry.as_table_mut().expect("just made a table");
    }
    match value {
        Some(v) => {
            at.insert(last.to_string(), v);
        }
        None => {
            at.remove(last);
        }
    }
}

/// The value of a setting. `None` for a setting that is not set, which only
/// the optional ones can be.
pub fn get(settings: &Settings, name: &str) -> Result<Option<toml::Value>, KeyError> {
    let key = find(name)?;
    Ok(lookup(&table_of(settings), key.name).cloned())
}

/// A value as `config get` prints it: text as it is, a list one item per line.
pub fn to_text(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Array(items) => items.iter().map(to_text).collect::<Vec<_>>().join("\n"),
        other => other.to_string(),
    }
}

fn parse_bool(name: &str, text: &str) -> Result<bool, KeyError> {
    match text.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(value_error(
            name,
            format!("`{other}` is not true or false."),
        )),
    }
}

fn parse_number(name: &str, text: &str) -> Result<i64, KeyError> {
    text.trim().parse::<u32>().map(i64::from).map_err(|_| {
        value_error(
            name,
            format!("`{}` is not a whole number of 0 or more.", text.trim()),
        )
    })
}

/// A list from the command line: each word one item, or one word that is a
/// TOML list such as `["sudo", "-n"]`.
fn parse_list(name: &str, values: &[String]) -> Result<Vec<toml::Value>, KeyError> {
    if let [one] = values {
        if one.trim_start().starts_with('[') {
            let parsed: Result<toml::Table, _> = toml::from_str(&format!("v = {one}"));
            return match parsed.ok().and_then(|mut t| t.remove("v")) {
                Some(toml::Value::Array(items)) if items.iter().all(toml::Value::is_str) => {
                    Ok(items)
                }
                _ => Err(value_error(
                    name,
                    format!("`{one}` is not a list of texts, like [\"a\", \"b\"]."),
                )),
            };
        }
    }
    Ok(values
        .iter()
        .map(|v| toml::Value::String(v.clone()))
        .collect())
}

fn one<'a>(key: &Key, values: &'a [String]) -> Result<&'a str, KeyError> {
    match values {
        [v] => Ok(v),
        [] => Err(value_error(key.name, "give a value.")),
        _ => Err(value_error(
            key.name,
            format!(
                "takes one value, and {} were given. Put a value with spaces in quotes.",
                values.len()
            ),
        )),
    }
}

/// Rules that the types in [`Settings`] do not check by themselves.
fn check(name: &str, settings: &Settings) -> Result<(), KeyError> {
    profile::extra_option_lines(&settings.openvpn.extra_options)
        .map_err(|e| value_error(name, e.to_string()))?;
    if settings.openvpn.verb.is_some_and(|v| v > 11) {
        return Err(value_error(name, "the highest value is 11."));
    }
    let launch = settings.openvpn.windows.launch.trim();
    if !["", "auto", "service", "direct"].contains(&launch) {
        return Err(value_error(
            name,
            format!("`{launch}` is not one of auto, service, direct."),
        ));
    }
    if settings.name.trim().is_empty() {
        return Err(value_error(name, "the name cannot be empty."));
    }
    Ok(())
}

fn rebuild(key: &Key, table: toml::Table) -> Result<Settings, KeyError> {
    let settings: Settings = toml::Value::Table(table).try_into().map_err(|e| {
        let text = e.to_string();
        // The first line says what is wrong; the rest points into a file
        // that does not exist.
        value_error(key.name, text.lines().next().unwrap_or("not a valid value"))
    })?;
    check(key.name, &settings)?;
    Ok(settings)
}

/// The settings with `name` changed to the value given on the command line.
pub fn set(settings: &Settings, name: &str, values: &[String]) -> Result<Settings, KeyError> {
    let key = find(name)?;
    let value = match key.kind {
        Kind::Text => toml::Value::String(one(key, values)?.to_string()),
        Kind::Bool => toml::Value::Boolean(parse_bool(key.name, one(key, values)?)?),
        Kind::Number | Kind::OptionalNumber => {
            toml::Value::Integer(parse_number(key.name, one(key, values)?)?)
        }
        Kind::List | Kind::OptionalList => toml::Value::Array(parse_list(key.name, values)?),
    };
    let mut table = table_of(settings);
    place(&mut table, key.name, Some(value));
    rebuild(key, table)
}

/// The settings with `name` back at its default.
pub fn unset(settings: &Settings, name: &str) -> Result<Settings, KeyError> {
    let key = find(name)?;
    let default = lookup(&table_of(&Settings::default()), key.name).cloned();
    let mut table = table_of(settings);
    place(&mut table, key.name, default);
    rebuild(key, table)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn set_one(settings: &Settings, name: &str, value: &str) -> Result<Settings, KeyError> {
        set(settings, name, &strings(&[value]))
    }

    /// Every field of the settings file can be reached by name, so a new
    /// setting cannot be added without its entry in `KEYS`.
    #[test]
    fn every_setting_in_the_file_has_a_key() {
        let mut full = Settings::default();
        full.openvpn.verb = Some(4);
        full.openvpn.linux.command_prefix = Some(vec!["sudo".into()]);
        full.openvpn.windows.command_prefix = None;
        fn names(prefix: &str, table: &toml::Table, out: &mut Vec<String>) {
            for (k, v) in table {
                let name = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match v {
                    toml::Value::Table(t) => names(&name, t, out),
                    _ => out.push(name),
                }
            }
        }
        let mut in_file = Vec::new();
        names("", &table_of(&full), &mut in_file);
        for name in &in_file {
            // The two that only mean something on the other system.
            if name == "openvpn.linux.launch" {
                continue;
            }
            assert!(find(name).is_ok(), "no key for the setting `{name}`");
        }
        for key in KEYS {
            assert!(
                in_file.iter().any(|n| n == key.name),
                "the key `{}` is not a setting",
                key.name
            );
            assert!(!key.help.is_empty());
        }
    }

    #[test]
    fn reads_each_kind_of_value() {
        let mut s = Settings::default();
        s.profile.path = "work.ovpn".into();
        s.openvpn.extra_options = strings(&["mute 10", "verb 4"]);
        let text = |name: &str| get(&s, name).unwrap().map(|v| to_text(&v));
        assert_eq!(text("name").as_deref(), Some("default"));
        assert_eq!(text("profile.path").as_deref(), Some("work.ovpn"));
        assert_eq!(text("keepalive.ping").as_deref(), Some("10"));
        assert_eq!(text("keepalive.auto_reconnect").as_deref(), Some("true"));
        assert_eq!(text("connect.timeout").as_deref(), Some("60"));
        assert_eq!(
            text("openvpn.extra_options").as_deref(),
            Some("mute 10\nverb 4")
        );
        // Not set at all.
        assert_eq!(text("openvpn.verb"), None);
        assert_eq!(text("openvpn.linux.command_prefix"), None);
    }

    #[test]
    fn sets_each_kind_of_value() {
        let s = Settings::default();
        let s = set_one(&s, "name", "work").unwrap();
        let s = set_one(&s, "profile.path", "vpn/work.ovpn").unwrap();
        let s = set_one(&s, "keepalive.auto_reconnect", "no").unwrap();
        let s = set_one(&s, "keepalive.ping", "25").unwrap();
        let s = set_one(&s, "connect.timeout", "30").unwrap();
        let s = set_one(&s, "openvpn.verb", "5").unwrap();
        let s = set(
            &s,
            "openvpn.extra_options",
            &strings(&["mute 10", "disable-dco"]),
        )
        .unwrap();
        let s = set(
            &s,
            "openvpn.linux.command_prefix",
            &strings(&["sudo", "-n"]),
        )
        .unwrap();
        assert_eq!(s.name, "work");
        assert_eq!(s.profile.path, "vpn/work.ovpn");
        assert!(!s.keepalive.auto_reconnect);
        assert_eq!(s.keepalive.ping, 25);
        assert_eq!(s.connect.timeout, 30);
        assert_eq!(s.openvpn.verb, Some(5));
        assert_eq!(
            s.openvpn.extra_options,
            strings(&["mute 10", "disable-dco"])
        );
        assert_eq!(
            s.openvpn.linux.command_prefix,
            Some(strings(&["sudo", "-n"]))
        );
        // Nothing else moved.
        assert_eq!(s.keepalive.ping_restart, 60);
        assert_eq!(s.code.digits, 6);

        // A list as one word, and an empty list.
        let s = set_one(&s, "openvpn.linux.command_prefix", "[\"pkexec\"]").unwrap();
        assert_eq!(s.openvpn.linux.command_prefix, Some(strings(&["pkexec"])));
        let s = set(&s, "openvpn.linux.command_prefix", &[]).unwrap();
        assert_eq!(s.openvpn.linux.command_prefix, Some(Vec::new()));
        let s = set_one(&s, "openvpn.extra_options", "[]").unwrap();
        assert!(s.openvpn.extra_options.is_empty());
    }

    #[test]
    fn unset_puts_the_default_back() {
        let s = Settings::default();
        let changed = set_one(&s, "keepalive.ping", "25").unwrap();
        let changed = set_one(&changed, "openvpn.verb", "5").unwrap();
        let changed = set(&changed, "openvpn.linux.command_prefix", &[]).unwrap();
        let back = unset(&changed, "keepalive.ping").unwrap();
        let back = unset(&back, "openvpn.verb").unwrap();
        let back = unset(&back, "openvpn.linux.command_prefix").unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn refuses_values_that_cannot_be_right() {
        let s = Settings::default();
        let problem = |r: Result<Settings, KeyError>| r.unwrap_err().to_string();
        assert_eq!(
            problem(set_one(&s, "keepalive.ping", "soon")),
            "keepalive.ping: `soon` is not a whole number of 0 or more."
        );
        assert_eq!(
            problem(set_one(&s, "keepalive.auto_reconnect", "maybe")),
            "keepalive.auto_reconnect: `maybe` is not true or false."
        );
        assert!(problem(set_one(&s, "code.digits", "999")).starts_with("code.digits: "));
        assert_eq!(
            problem(set_one(&s, "openvpn.verb", "12")),
            "openvpn.verb: the highest value is 11."
        );
        assert_eq!(
            problem(set_one(&s, "openvpn.windows.launch", "magic")),
            "openvpn.windows.launch: `magic` is not one of auto, service, direct."
        );
        assert!(problem(set(&s, "name", &strings(&["two", "words"]))).contains("takes one value"));
        assert!(problem(set(&s, "name", &[])).contains("give a value"));
        assert!(problem(set_one(&s, "name", " ")).contains("cannot be empty"));
        // The extra options are checked the way connect checks them.
        assert!(
            problem(set(&s, "openvpn.extra_options", &strings(&["-v"]))).contains("option name")
        );
        assert!(problem(set_one(&s, "openvpn.extra_options", "[1, 2]")).contains("list of texts"));
    }

    #[test]
    fn an_unknown_name_gets_a_hint() {
        let s = Settings::default();
        let e = get(&s, "ping").unwrap_err().to_string();
        assert!(e.contains("there is no setting `ping`"), "{e}");
        assert!(e.contains("Did you mean keepalive.ping?"), "{e}");
        let e = get(&s, "keepalive").unwrap_err().to_string();
        assert!(e.contains("keepalive.ping, keepalive.ping_restart"), "{e}");
        let e = set_one(&s, "pasword", "x").unwrap_err().to_string();
        assert!(
            e.contains("config keys") && !e.contains("Did you mean"),
            "{e}"
        );
    }
}
