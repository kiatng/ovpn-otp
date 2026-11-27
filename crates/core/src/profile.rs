//! Turn the user's `.ovpn` profile into the config OpenVPN actually runs.
//!
//! The profile is copied with a few changes so the management interface can do
//! the login and keep-alive works the way the settings say:
//!
//! * `auth-user-pass <file>` becomes plain `auth-user-pass`, so OpenVPN asks
//!   this app for the login instead of reading a file;
//! * `auth-nocache` is added, so after a real drop OpenVPN asks again and the
//!   user can give a fresh code (an old code would be refused);
//! * `ping` / `ping-restart` from the settings are added at the end, where they
//!   override the profile's own values;
//! * a `remote` override from the settings replaces the profile's `remote` lines;
//! * `remote` lines with a private address are skipped when the profile also
//!   has a public one (see [`is_private_host`]), unless the settings allow them;
//! * a profile with an old `cipher X` line and no `data-ciphers` gets
//!   `data-ciphers ...:X` and `data-ciphers-fallback X` (see [`cipher_lines`]),
//!   because OpenVPN 2.6 and newer ignore `cipher` when they agree a cipher
//!   with the server;
//! * `connect-timeout` from the settings is added, unless the profile or the
//!   extra options set `connect-timeout` or `server-poll-timeout` themselves;
//! * a `verb` in the extra options is taken out and given back as
//!   [`PreparedProfile::verb`], because the level goes on the command line;
//! * any `management...` lines are removed; this app sets its own (only
//!   `management-log-cache` is added here, because the Windows interactive
//!   service does not allow it on the command line).

use std::net::IpAddr;

use crate::settings::Settings;

/// The result of preparing a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedProfile {
    /// Config text to give to OpenVPN.
    pub text: String,
    /// The profile asks for the code in a separate prompt (`static-challenge`)
    /// rather than appended to the password.
    pub static_challenge: bool,
    /// The servers OpenVPN will try, as `host:port`, in order.
    pub remotes: Vec<String>,
    /// `tcp` or `udp` for each server in `remotes`.
    pub protocols: Vec<String>,
    /// The log level from a `verb` in the extra options, when there is one.
    /// It wins over the `openvpn.verb` setting and is given to OpenVPN on the
    /// command line, where it is the only `--verb`.
    pub verb: Option<u8>,
    /// How many servers OpenVPN will try before it starts over: the `remote`
    /// lines in use plus any `<connection>` blocks. At least 1.
    pub remote_count: usize,
    /// What was changed for the user to know about, one sentence each.
    pub notes: Vec<String>,
}

impl PreparedProfile {
    /// The servers with the protocol for each, such as `vpn.example.org:8443 (tcp)`.
    pub fn server_labels(&self) -> Vec<String> {
        self.remotes
            .iter()
            .enumerate()
            .map(|(i, remote)| match self.protocols.get(i) {
                Some(p) => format!("{remote} ({p})"),
                None => remote.clone(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    /// The `extra_options` setting is not in a format OpenVPN can read.
    #[error("{0}")]
    ExtraOptions(String),
}

const MARK: &str = "# ---- added by ovpn-otp ----";

/// Options this app controls; matching profile lines are dropped.
const DROPPED: &[&str] = &[
    "management",
    "management-hold",
    "management-query-passwords",
    "management-client",
    "management-signal",
    "management-forget-disconnect",
    "management-log-cache",
    "auth-nocache",
    "auth-retry",
    "daemon",
];

/// The ciphers OpenVPN 2.6 and newer offer when a profile says nothing.
const DEFAULT_DATA_CIPHERS: &[&str] = &["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"];

/// One option line outside any `<block>`: its name and its parameters.
struct OptionLine<'a> {
    name: &'a str,
    args: Vec<&'a str>,
}

/// The option on a config line, or `None` for a blank line or a comment.
fn option_line(line: &str) -> Option<OptionLine<'_>> {
    let trimmed = line.trim();
    if trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    let mut words = trimmed.split_whitespace();
    let name = words.next()?.trim_start_matches("--");
    if name.is_empty() {
        return None;
    }
    Some(OptionLine {
        name,
        args: words.collect(),
    })
}

/// The tag when `line` opens an inline block such as `<ca>`.
fn block_open(line: &str) -> Option<&str> {
    line.trim()
        .strip_prefix('<')
        .and_then(|t| t.strip_suffix('>'))
        .filter(|t| !t.starts_with('/') && !t.is_empty())
}

/// What a first read of the profile found.
#[derive(Default)]
struct Scan {
    cipher: Option<String>,
    has_data_ciphers: bool,
    has_fallback: bool,
    public_remotes: usize,
    private_remotes: usize,
    connection_blocks: usize,
    /// The `proto` line, for servers that do not name a protocol themselves.
    proto: Option<String>,
    /// The profile or the extra options say how long to wait for a server.
    has_connect_timeout: bool,
}

/// `tcp` for `tcp`, `tcp-client`, `tcp4` and so on; `udp` for everything else,
/// which is what OpenVPN uses when nothing is said.
fn protocol_name(proto: Option<&str>) -> String {
    match proto {
        Some(p) if p.to_ascii_lowercase().starts_with("tcp") => "tcp".into(),
        _ => "udp".into(),
    }
}

fn scan(profile: &str, extra: &[String]) -> Scan {
    let mut s = Scan::default();
    let mut in_block: Option<String> = None;
    for line in profile.lines().chain(extra.iter().map(String::as_str)) {
        if let Some(tag) = &in_block {
            if line.trim().eq_ignore_ascii_case(&format!("</{tag}>")) {
                in_block = None;
            }
            continue;
        }
        if let Some(tag) = block_open(line) {
            if tag.eq_ignore_ascii_case("connection") {
                s.connection_blocks += 1;
            }
            in_block = Some(tag.to_string());
            continue;
        }
        let Some(opt) = option_line(line) else {
            continue;
        };
        match opt.name {
            "cipher" => s.cipher = opt.args.first().map(|c| c.to_string()),
            "data-ciphers" | "ncp-ciphers" => s.has_data_ciphers = true,
            "data-ciphers-fallback" => s.has_fallback = true,
            "proto" => s.proto = opt.args.first().map(|p| p.to_string()),
            "connect-timeout" | "server-poll-timeout" => s.has_connect_timeout = true,
            "remote" => match opt.args.first() {
                Some(host) if is_private_host(host) => s.private_remotes += 1,
                Some(_) => s.public_remotes += 1,
                None => {}
            },
            _ => {}
        }
    }
    s
}

/// Whether `host` is an address that only answers inside a private network:
/// RFC 1918 (`10.x`, `172.16-31.x`, `192.168.x`), carrier-grade NAT
/// (`100.64.0.0/10`), link-local (`169.254.x`, `fe80::/10`) or an IPv6 unique
/// local address (`fc00::/7`). A host name is never private here, because
/// only the DNS answer could tell.
pub fn is_private_host(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            let o = ip.octets();
            ip.is_private() || ip.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        Ok(IpAddr::V6(ip)) => {
            let first = ip.segments()[0];
            (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// The lines to add for a profile with an old `cipher X` line.
///
/// OpenVPN 2.6 and newer agree the cipher with the server from the
/// `data-ciphers` list and ignore `cipher`. A server that only knows `X`
/// (older firewalls, for example with AES-128-CBC) then refuses the client.
/// So `X` is added to the list, and also set as the fallback for servers that
/// cannot agree a cipher at all.
///
/// Nothing is added when the profile or `extra_options` sets `data-ciphers`
/// itself, or when `X` is not an AES, Camellia, ARIA or ChaCha20 cipher: other
/// old ciphers (such as BF-CBC) are not in every OpenVPN build, and naming
/// one that is missing stops OpenVPN at start.
///
/// OpenVPN turns off its kernel data channel (DCO) by itself when a cipher
/// that DCO cannot carry, such as a CBC one, is in these lines, so
/// `disable-dco` is not needed.
pub fn cipher_lines(cipher: &str, has_data_ciphers: bool, has_fallback: bool) -> Vec<String> {
    let cipher = cipher.to_ascii_uppercase();
    let known = ["AES-", "CAMELLIA-", "ARIA-"]
        .iter()
        .any(|p| cipher.starts_with(p))
        || cipher == "CHACHA20-POLY1305";
    if has_data_ciphers || !known {
        return Vec::new();
    }
    let mut lines = Vec::new();
    if !DEFAULT_DATA_CIPHERS.contains(&cipher.as_str()) {
        lines.push(format!(
            "data-ciphers {}:{cipher}",
            DEFAULT_DATA_CIPHERS.join(":")
        ));
    }
    if !has_fallback {
        lines.push(format!("data-ciphers-fallback {cipher}"));
    }
    lines
}

/// Turn the `extra_options` setting into OpenVPN config lines.
///
/// Two ways to write the options are accepted:
///
/// * one option per item, as in a config file: `"data-ciphers-fallback AES-128-CBC"`;
/// * command-line tokens: `"--data-ciphers-fallback", "AES-128-CBC"`. An item
///   that starts with `--` starts an option, and the items after it are its
///   parameters, up to the next item that starts with `--`.
///
/// Either way the result is one config line per option, without the `--`.
/// The two ways cannot be mixed in a way that leaves an item before the
/// first `--` item, because it would be unclear what that item belongs to.
pub fn extra_option_lines(items: &[String]) -> Result<Vec<String>, ProfileError> {
    let err = |msg: String| Err(ProfileError::ExtraOptions(msg));
    let tokens = items.iter().any(|i| i.trim().starts_with("--"));
    let mut lines: Vec<String> = Vec::new();
    for (i, raw) in items.iter().enumerate() {
        let n = i + 1;
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        if item.contains('\n') || item.contains('\r') {
            return err(format!(
                "extra_options item {n} has a line break in it. Write each option as its own item."
            ));
        }
        if let Some(option) = item.strip_prefix("--") {
            check_option_name(option, n, raw)?;
            lines.push(option.trim().to_string());
        } else if tokens {
            let Some(line) = lines.last_mut() else {
                return err(format!(
                    "extra_options item {n} (\"{item}\") comes before the first item that starts with \"--\". \
                     Write every option the same way: either one option per item, like \"verb 4\", \
                     or command-line tokens, like \"--verb\", \"4\"."
                ));
            };
            line.push(' ');
            line.push_str(&quote_parameter(item));
        } else {
            check_option_name(item, n, raw)?;
            lines.push(item.to_string());
        }
    }
    Ok(lines)
}

/// An option name is letters, digits, `-` and `_`, starting with a letter.
fn check_option_name(text: &str, n: usize, raw: &str) -> Result<(), ProfileError> {
    let name = text.split_whitespace().next().unwrap_or("");
    let ok = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        return Ok(());
    }
    Err(ProfileError::ExtraOptions(format!(
        "extra_options item {n} (\"{}\") does not start with an OpenVPN option name. \
         Write an option as \"verb 4\", or as \"--verb\", \"4\".",
        raw.trim()
    )))
}

/// Quote a parameter for a config line when it has spaces or quotes in it.
fn quote_parameter(p: &str) -> String {
    if !p.contains(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '\\' | '#' | ';')) {
        return p.to_string();
    }
    let mut out = String::with_capacity(p.len() + 2);
    out.push('"');
    for c in p.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// `host`, `port` -> `host:port`, with brackets around an IPv6 address.
fn remote_label(args: &[&str]) -> String {
    let host = args.first().copied().unwrap_or_default();
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match args.get(1) {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

/// The level in a `verb N` line, if the line is one.
fn verb_of(line: &str) -> Option<u8> {
    let opt = option_line(line)?;
    if opt.name != "verb" {
        return None;
    }
    // OpenVPN itself reads a missing or odd level as an error; 11 is its highest.
    Some(opt.args.first()?.parse::<u8>().ok()?.min(11))
}

pub fn prepare(profile: &str, settings: &Settings) -> Result<PreparedProfile, ProfileError> {
    let mut extra = extra_option_lines(&settings.openvpn.extra_options)?;
    // The log level goes on the command line, once. Left in the config as
    // well it would lose against that `--verb`.
    let verb = extra.iter().filter_map(|l| verb_of(l)).next_back();
    extra.retain(|l| verb_of(l).is_none());
    // A diagnostic run must not leave an unfiltered OpenVPN log elsewhere.
    if cfg!(feature = "diagnostic-test") {
        extra.retain(|line| {
            !option_line(line)
                .is_some_and(|opt| ["log", "log-append", "syslog"].contains(&opt.name))
        });
    }
    let remote_override = settings.profile.remote.trim();
    let found = scan(profile, &extra);
    let skip_private = remote_override.is_empty()
        && !settings.profile.allow_private_remotes
        && found.public_remotes > 0
        && found.private_remotes > 0;

    let mut out = String::with_capacity(profile.len() + 512);
    let mut in_block: Option<String> = None;
    let mut has_auth = false;
    let mut static_challenge = false;
    let mut remotes = Vec::new();
    let mut protocols = Vec::new();
    let mut skipped = Vec::new();

    for line in profile.lines() {
        let trimmed = line.trim();
        let keep = |out: &mut String| {
            out.push_str(line);
            out.push('\n');
        };
        if let Some(tag) = &in_block {
            if trimmed.eq_ignore_ascii_case(&format!("</{tag}>")) {
                in_block = None;
            }
            keep(&mut out);
            continue;
        }
        if let Some(tag) = block_open(line) {
            in_block = Some(tag.to_string());
            keep(&mut out);
            continue;
        }
        let Some(opt) = option_line(line) else {
            keep(&mut out);
            continue;
        };
        match opt.name {
            "auth-user-pass" => {
                has_auth = true;
                out.push_str("auth-user-pass\n");
            }
            "static-challenge" => {
                static_challenge = true;
                keep(&mut out);
            }
            "remote" => {
                let host = opt.args.first().copied().unwrap_or_default();
                if !remote_override.is_empty() {
                    out.push_str("# replaced by ovpn-otp: ");
                    out.push_str(trimmed);
                    out.push('\n');
                } else if skip_private && is_private_host(host) {
                    skipped.push(remote_label(&opt.args));
                    out.push_str("# skipped by ovpn-otp (private address): ");
                    out.push_str(trimmed);
                    out.push('\n');
                } else {
                    remotes.push(remote_label(&opt.args));
                    protocols.push(protocol_name(
                        opt.args.get(2).copied().or(found.proto.as_deref()),
                    ));
                    keep(&mut out);
                }
            }
            o if DROPPED.contains(&o)
                || (cfg!(feature = "diagnostic-test")
                    && ["log", "log-append", "syslog"].contains(&o)) =>
            {
                out.push_str("# removed by ovpn-otp: ");
                out.push_str(trimmed);
                out.push('\n');
            }
            _ => keep(&mut out),
        }
    }

    let mut notes = Vec::new();
    out.push('\n');
    out.push_str(MARK);
    out.push('\n');
    if !remote_override.is_empty() {
        let (host, port) = split_host_port(remote_override);
        match port {
            Some(p) => out.push_str(&format!("remote {host} {p}\n")),
            None => out.push_str(&format!("remote {host}\n")),
        }
        remotes.push(remote_override.to_string());
        protocols.push(protocol_name(found.proto.as_deref()));
    }
    if !skipped.is_empty() {
        notes.push(format!(
            "Not trying the private server address {} from the profile, because it does not answer \
             from outside that network. To try it too, set allow_private_remotes = true under [profile].",
            skipped.join(", ")
        ));
    }
    if !has_auth {
        out.push_str("auth-user-pass\n");
    }
    // Keep recent log lines so the app can show what happened before it attached.
    out.push_str("management-log-cache 500\n");
    out.push_str("auth-nocache\n");
    let ka = &settings.keepalive;
    if ka.ping > 0 {
        out.push_str(&format!("ping {}\n", ka.ping));
    }
    if ka.ping_restart > 0 {
        out.push_str(&format!("ping-restart {}\n", ka.ping_restart));
    }
    // So that OpenVPN gives up a server that does not answer after the same
    // time this app allows a try without progress.
    if settings.connect.timeout > 0 && !found.has_connect_timeout {
        out.push_str(&format!("connect-timeout {}\n", settings.connect.timeout));
    }
    if let Some(cipher) = &found.cipher {
        let added = cipher_lines(cipher, found.has_data_ciphers, found.has_fallback);
        if !added.is_empty() {
            notes.push(format!(
                "The profile names the cipher {cipher} in the old way, which OpenVPN 2.6 and newer \
                 ignore. Added for this session: {}.",
                added.join("; ")
            ));
        }
        for line in added {
            out.push_str(&line);
            out.push('\n');
        }
    }
    // Last, so that the user's own options win over everything above.
    for line in &extra {
        out.push_str(line);
        out.push('\n');
    }

    let remote_count = (remotes.len() + found.connection_blocks).max(1);
    Ok(PreparedProfile {
        text: out,
        static_challenge,
        remotes,
        protocols,
        verb,
        remote_count,
        notes,
    })
}

/// Split `host:port`, also handling `[v6]:port`. A bare host gives no port.
pub fn split_host_port(s: &str) -> (String, Option<String>) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').map(str::to_string);
            return (host.to_string(), port.filter(|p| !p.is_empty()));
        }
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), Some(port.to_string()))
        }
        _ => (s.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "client
dev tun
proto tcp
remote 203.0.113.10 8443 tcp-client
auth-user-pass creds.txt
management 127.0.0.1 7505
cipher AES-128-CBC
reneg-sec 0
<ca>
-----BEGIN CERTIFICATE-----
remote inside-a-block-is-not-an-option
-----END CERTIFICATE-----
</ca>
";

    #[cfg(feature = "diagnostic-test")]
    #[test]
    fn diagnostic_profile_drops_unfiltered_log_destinations() {
        let mut settings = Settings::default();
        settings.openvpn.extra_options =
            vec!["log-append extra.log".into(), "syslog openvpn".into()];
        let output = prepare("client\nlog private.log\n", &settings)
            .unwrap()
            .text;
        assert!(!output.lines().any(|line| line.starts_with("log ")
            || line.starts_with("log-append ")
            || line.starts_with("syslog ")));
    }

    /// Shaped like a firewall export: a public server, then the same server
    /// by its address inside the office network.
    const TWO_REMOTES: &str = "client
dev tun
proto tcp
remote 203.0.113.10 8443 tcp-client
remote 10.255.0.1 8443 tcp-client
cipher AES-128-CBC
auth SHA256
auth-user-pass
;otp no
";

    fn prep(profile: &str, settings: &Settings) -> PreparedProfile {
        prepare(profile, settings).unwrap()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rewrites_login_and_adds_keepalive() {
        let p = prep(PROFILE, &Settings::default());
        assert!(p.text.contains("\nauth-user-pass\n"));
        assert!(!p.text.contains("auth-user-pass creds.txt\n"));
        assert!(p
            .text
            .contains("# removed by ovpn-otp: management 127.0.0.1 7505"));
        assert!(p
            .text
            .contains("auth-nocache\nping 10\nping-restart 60\nconnect-timeout 60\n"));
        assert_eq!(p.server_labels(), vec!["203.0.113.10:8443 (tcp)"]);
        assert!(p.text.contains("remote inside-a-block-is-not-an-option"));
        assert_eq!(p.remotes, vec!["203.0.113.10:8443"]);
        assert_eq!(p.remote_count, 1);
        assert!(!p.static_challenge);
        // Added options come after the profile so they override it.
        assert!(p.text.find("ping 10").unwrap() > p.text.find("</ca>").unwrap());
    }

    #[test]
    fn remote_override_replaces_remote_lines() {
        let mut s = Settings::default();
        s.profile.remote = "vpn.example.org:1194".into();
        s.keepalive.ping = 0;
        s.keepalive.ping_restart = 0;
        let p = prep(PROFILE, &s);
        assert!(p
            .text
            .contains("# replaced by ovpn-otp: remote 203.0.113.10 8443 tcp-client"));
        assert!(p.text.contains("remote vpn.example.org 1194\n"));
        assert!(!p.text.contains("\nping "));
        assert_eq!(p.remotes, vec!["vpn.example.org:1194"]);
    }

    #[test]
    fn adds_auth_user_pass_when_missing_and_detects_static_challenge() {
        let p = prep(
            "client\nstatic-challenge \"Code\" 1\n",
            &Settings::default(),
        );
        assert!(p.text.contains("auth-user-pass\n"));
        assert!(p.static_challenge);
    }

    #[test]
    fn extra_options_are_appended() {
        let mut s = Settings::default();
        s.openvpn.extra_options = vec!["mute 10".into(), " ".into()];
        let p = prep("client\n", &s);
        assert!(p.text.trim_end().ends_with("mute 10"));
        assert_eq!(p.verb, None);
    }

    /// A `verb` in the extra options used to lose against the `--verb 3` on
    /// the command line. Now it is taken out of the config and handed back,
    /// so that the one `--verb` on the command line carries it.
    #[test]
    fn verb_in_extra_options_is_handed_back_for_the_command_line() {
        let mut s = Settings::default();
        for items in [
            strings(&["verb 5", "mute 10"]),
            strings(&["--verb", "5", "--mute", "10"]),
            strings(&["--verb 2", "--mute", "10", "--verb", "5"]),
        ] {
            s.openvpn.extra_options = items.clone();
            let p = prep("client\nverb 1\n", &s);
            assert_eq!(p.verb, Some(5), "{items:?}");
            let added = p.text.split(MARK).nth(1).unwrap();
            assert!(!added.contains("verb"), "{items:?}: {added}");
            assert!(added.contains("mute 10\n"), "{items:?}: {added}");
        }
        s.openvpn.extra_options = strings(&["verb 99"]);
        assert_eq!(prep("client\n", &s).verb, Some(11));
    }

    #[test]
    fn says_which_protocol_each_server_uses() {
        let p = prep(
            "client\nremote a.example.org 1194\nremote b.example.org 443 tcp\n",
            &Settings::default(),
        );
        assert_eq!(p.protocols, vec!["udp", "tcp"]);
        assert_eq!(
            p.server_labels(),
            vec!["a.example.org:1194 (udp)", "b.example.org:443 (tcp)"]
        );
        // A `proto` line after the servers still counts for them.
        let p = prep(
            "client\nremote a.example.org 1194\nproto tcp-client\n",
            &Settings::default(),
        );
        assert_eq!(p.server_labels(), vec!["a.example.org:1194 (tcp)"]);
        let mut s = Settings::default();
        s.profile.remote = "c.example.org:8443".into();
        let p = prep("client\nproto tcp\nremote a.example.org 1194 udp\n", &s);
        assert_eq!(p.server_labels(), vec!["c.example.org:8443 (tcp)"]);
    }

    #[test]
    fn connect_timeout_follows_the_setting_unless_the_profile_has_its_own() {
        let mut s = Settings::default();
        s.connect.timeout = 25;
        assert!(prep("client\n", &s).text.contains("\nconnect-timeout 25\n"));
        for own in ["connect-timeout 10", "server-poll-timeout 10"] {
            let p = prep(&format!("client\n{own}\n"), &s);
            assert!(!p.text.contains("connect-timeout 25"), "{own}");
        }
        s.openvpn.extra_options = strings(&["connect-timeout 7"]);
        let p = prep("client\n", &s);
        assert!(!p.text.contains("connect-timeout 25"));
        assert!(p.text.contains("connect-timeout 7\n"));
        s.openvpn.extra_options.clear();
        s.connect.timeout = 0;
        assert!(!prep("client\n", &s).text.contains("connect-timeout"));
    }

    #[test]
    fn old_cipher_line_gets_data_ciphers_and_fallback() {
        let p = prep(PROFILE, &Settings::default());
        assert!(p.text.contains(
            "\ndata-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC\n\
             data-ciphers-fallback AES-128-CBC\n"
        ));
        // The profile's own line stays, so OpenVPN still tells the server about it.
        assert!(p.text.contains("\ncipher AES-128-CBC\n"));
        assert!(
            p.notes.iter().any(|n| n.contains("AES-128-CBC")),
            "{:?}",
            p.notes
        );
        // No DCO switch: OpenVPN turns DCO off by itself for a CBC cipher.
        assert!(!p.text.contains("disable-dco"));
    }

    #[test]
    fn cipher_lines_follow_what_the_profile_already_says() {
        // Lower case in the profile is fine.
        assert_eq!(
            cipher_lines("aes-256-cbc", false, false),
            vec![
                "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC",
                "data-ciphers-fallback AES-256-CBC"
            ]
        );
        // Already one of the ciphers OpenVPN offers: only the fallback is new.
        assert_eq!(
            cipher_lines("AES-256-GCM", false, false),
            vec!["data-ciphers-fallback AES-256-GCM"]
        );
        // The profile has its own fallback.
        assert_eq!(
            cipher_lines("AES-128-CBC", false, true),
            vec!["data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC"]
        );
        // The profile sets data-ciphers itself: leave it alone.
        assert!(cipher_lines("AES-128-CBC", true, false).is_empty());
        // Ciphers that are missing from many OpenVPN builds are never added.
        assert!(cipher_lines("BF-CBC", false, false).is_empty());
        assert!(cipher_lines("none", false, false).is_empty());
    }

    #[test]
    fn profile_or_extra_options_with_data_ciphers_is_left_alone() {
        let with = format!("{PROFILE}data-ciphers AES-256-GCM\n");
        let p = prep(&with, &Settings::default());
        assert!(!p.text.contains("data-ciphers-fallback"));
        assert!(p.notes.is_empty());

        // The way out for a server that needs something else.
        let mut s = Settings::default();
        s.openvpn.extra_options = strings(&["--data-ciphers", "AES-256-GCM:AES-128-CBC"]);
        let p = prep(PROFILE, &s);
        assert!(p
            .text
            .trim_end()
            .ends_with("data-ciphers AES-256-GCM:AES-128-CBC"));
        assert_eq!(p.text.matches("\ndata-ciphers ").count(), 1);
        assert!(!p.text.contains("data-ciphers-fallback"));

        // A profile without a cipher line gets nothing either.
        let p = prep(
            "client\nremote vpn.example.org 1194\n",
            &Settings::default(),
        );
        assert!(!p.text.contains("data-ciphers"));
    }

    #[test]
    fn private_remote_is_skipped_when_a_public_one_exists() {
        let p = prep(TWO_REMOTES, &Settings::default());
        assert_eq!(p.remotes, vec!["203.0.113.10:8443"]);
        assert_eq!(p.remote_count, 1);
        assert!(p.text.contains(
            "# skipped by ovpn-otp (private address): remote 10.255.0.1 8443 tcp-client"
        ));
        assert!(!p.text.contains("\nremote 10.255.0.1"));
        assert!(p
            .notes
            .iter()
            .any(|n| n.contains("10.255.0.1:8443") && n.contains("allow_private_remotes")));
    }

    #[test]
    fn private_remotes_are_kept_when_allowed_or_when_there_is_nothing_else() {
        let mut s = Settings::default();
        s.profile.allow_private_remotes = true;
        let p = prep(TWO_REMOTES, &s);
        assert_eq!(p.remotes, vec!["203.0.113.10:8443", "10.255.0.1:8443"]);
        assert_eq!(p.remote_count, 2);
        assert!(p.text.contains("\nremote 10.255.0.1 8443 tcp-client\n"));

        // A VPN server that is only reachable inside the network.
        let p = prep(
            "client\nremote 192.168.1.1 1194\nremote 10.0.0.1 1194\n",
            &Settings::default(),
        );
        assert_eq!(p.remotes, vec!["192.168.1.1:1194", "10.0.0.1:1194"]);
        assert!(p.notes.is_empty());

        // A host name counts as public: only the DNS answer could tell.
        let p = prep(
            "client\nremote vpn.example.org 1194\nremote 172.16.4.4 1194\n",
            &Settings::default(),
        );
        assert_eq!(p.remotes, vec!["vpn.example.org:1194"]);
    }

    #[test]
    fn recognises_private_addresses() {
        for host in [
            "10.255.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.254",
            "169.254.10.10",
            "fd00::1",
            "fe80::1",
            "[fd12:3456::1]",
        ] {
            assert!(is_private_host(host), "{host} should be private");
        }
        for host in [
            "203.0.113.10",
            "172.32.0.1",
            "100.128.0.1",
            "127.0.0.1",
            "2001:db8::1",
            "vpn.example.org",
        ] {
            assert!(!is_private_host(host), "{host} should not be private");
        }
    }

    #[test]
    fn connection_blocks_count_as_servers() {
        let p = prep(
            "client\n<connection>\nremote a.example.org 1194\n</connection>\n\
             <connection>\nremote b.example.org 443 tcp\n</connection>\n",
            &Settings::default(),
        );
        assert_eq!(p.remote_count, 2);
    }

    #[test]
    fn extra_options_accept_config_lines_and_command_line_tokens() {
        // One option per item.
        assert_eq!(
            extra_option_lines(&strings(&["verb 4", "", "  mute 10 "])).unwrap(),
            vec!["verb 4", "mute 10"]
        );
        // (`prepare` takes a `verb` out again; see the test for it above.)
        // Command-line tokens, as someone would type them after `openvpn`.
        assert_eq!(
            extra_option_lines(&strings(&[
                "--data-ciphers",
                "AES-256-GCM:AES-128-GCM:AES-128-CBC",
                "--data-ciphers-fallback",
                "AES-128-CBC",
                "--disable-dco"
            ]))
            .unwrap(),
            vec![
                "data-ciphers AES-256-GCM:AES-128-GCM:AES-128-CBC",
                "data-ciphers-fallback AES-128-CBC",
                "disable-dco"
            ]
        );
        // A whole option in one item with the dashes left on.
        assert_eq!(
            extra_option_lines(&strings(&["--verb 4", "--mute", "10"])).unwrap(),
            vec!["verb 4", "mute 10"]
        );
        // A parameter with a space is quoted so it stays one parameter.
        assert_eq!(
            extra_option_lines(&strings(&["--up", "/opt/my scripts/up.sh"])).unwrap(),
            vec!["up \"/opt/my scripts/up.sh\""]
        );
    }

    #[test]
    fn extra_options_in_a_bad_format_are_refused_with_the_item_number() {
        let e = extra_option_lines(&strings(&["verb 4", "--mute", "10"])).unwrap_err();
        assert_eq!(
            e.to_string(),
            "extra_options item 1 (\"verb 4\") comes before the first item that starts with \"--\". \
             Write every option the same way: either one option per item, like \"verb 4\", \
             or command-line tokens, like \"--verb\", \"4\"."
        );
        let e = extra_option_lines(&strings(&["verb 4", "-v"])).unwrap_err();
        assert_eq!(
            e.to_string(),
            "extra_options item 2 (\"-v\") does not start with an OpenVPN option name. \
             Write an option as \"verb 4\", or as \"--verb\", \"4\"."
        );
        assert!(extra_option_lines(&strings(&["--"])).is_err());
        assert!(extra_option_lines(&strings(&["verb 4\nmute 10"])).is_err());

        // A bad format stops the profile from being prepared at all.
        let mut s = Settings::default();
        s.openvpn.extra_options = strings(&["AES-128-CBC", "--disable-dco"]);
        assert!(prepare(PROFILE, &s).is_err());
    }

    #[test]
    fn splits_host_port() {
        assert_eq!(
            split_host_port("a.b:443"),
            ("a.b".into(), Some("443".into()))
        );
        assert_eq!(split_host_port("10.0.0.1"), ("10.0.0.1".into(), None));
        assert_eq!(
            split_host_port("[fd00::1]:22"),
            ("fd00::1".into(), Some("22".into()))
        );
        assert_eq!(split_host_port("fd00::1"), ("fd00::1".into(), None));
    }
}
