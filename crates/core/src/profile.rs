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
//! * any `management...` lines are removed; this app sets its own (only
//!   `management-log-cache` is added here, because the Windows interactive
//!   service does not allow it on the command line).

use crate::settings::Settings;

/// The result of preparing a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedProfile {
    /// Config text to give to OpenVPN.
    pub text: String,
    /// The profile asks for the code in a separate prompt (`static-challenge`)
    /// rather than appended to the password.
    pub static_challenge: bool,
    /// The `remote` the profile (or the override) points at, for display.
    pub remotes: Vec<String>,
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

pub fn prepare(profile: &str, settings: &Settings) -> PreparedProfile {
    let remote_override = settings.profile.remote.trim();
    let mut out = String::with_capacity(profile.len() + 256);
    let mut in_block: Option<String> = None;
    let mut has_auth = false;
    let mut static_challenge = false;
    let mut remotes = Vec::new();

    for line in profile.lines() {
        let trimmed = line.trim();
        if let Some(tag) = &in_block {
            if trimmed.eq_ignore_ascii_case(&format!("</{tag}>")) {
                in_block = None;
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if let Some(tag) = trimmed
            .strip_prefix('<')
            .and_then(|t| t.strip_suffix('>'))
            .filter(|t| !t.starts_with('/'))
        {
            in_block = Some(tag.to_string());
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let mut words = trimmed.split_whitespace();
        let option = words.next().unwrap_or("").trim_start_matches("--");
        if trimmed.starts_with('#') || trimmed.starts_with(';') || option.is_empty() {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        match option {
            "auth-user-pass" => {
                has_auth = true;
                out.push_str("auth-user-pass\n");
            }
            "static-challenge" => {
                static_challenge = true;
                out.push_str(line);
                out.push('\n');
            }
            "remote" => {
                if remote_override.is_empty() {
                    remotes.push(words.take(2).collect::<Vec<_>>().join(":"));
                    out.push_str(line);
                    out.push('\n');
                } else {
                    out.push_str("# replaced by ovpn-otp: ");
                    out.push_str(trimmed);
                    out.push('\n');
                }
            }
            o if DROPPED.contains(&o) => {
                out.push_str("# removed by ovpn-otp: ");
                out.push_str(trimmed);
                out.push('\n');
            }
            _ => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }

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
    for extra in &settings.openvpn.extra_options {
        let extra = extra.trim();
        if !extra.is_empty() {
            out.push_str(extra);
            out.push('\n');
        }
    }

    PreparedProfile {
        text: out,
        static_challenge,
        remotes,
    }
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

    #[test]
    fn rewrites_login_and_adds_keepalive() {
        let p = prepare(PROFILE, &Settings::default());
        assert!(p.text.contains("\nauth-user-pass\n"));
        assert!(!p.text.contains("auth-user-pass creds.txt\n"));
        assert!(p
            .text
            .contains("# removed by ovpn-otp: management 127.0.0.1 7505"));
        assert!(p.text.contains("auth-nocache\nping 10\nping-restart 60\n"));
        assert!(p.text.contains("remote inside-a-block-is-not-an-option"));
        assert_eq!(p.remotes, vec!["203.0.113.10:8443"]);
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
        let p = prepare(PROFILE, &s);
        assert!(p
            .text
            .contains("# replaced by ovpn-otp: remote 203.0.113.10 8443 tcp-client"));
        assert!(p.text.contains("remote vpn.example.org 1194\n"));
        assert!(!p.text.contains("\nping "));
        assert_eq!(p.remotes, vec!["vpn.example.org:1194"]);
    }

    #[test]
    fn adds_auth_user_pass_when_missing_and_detects_static_challenge() {
        let p = prepare(
            "client\nstatic-challenge \"Code\" 1\n",
            &Settings::default(),
        );
        assert!(p.text.contains("auth-user-pass\n"));
        assert!(p.static_challenge);
    }

    #[test]
    fn extra_options_are_appended() {
        let mut s = Settings::default();
        s.openvpn.extra_options = vec!["verb 4".into(), " ".into()];
        let p = prepare("client\n", &s);
        assert!(p.text.trim_end().ends_with("verb 4"));
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
