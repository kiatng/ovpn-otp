//! Parser and helpers for the OpenVPN management protocol.
//!
//! OpenVPN talks to a management client over a line-based text protocol. Three
//! kinds of lines arrive:
//!
//! * real-time notifications, which start with `>` (`>STATE:`, `>LOG:`, ...);
//! * one-line replies to a command, `SUCCESS: ...` or `ERROR: ...`;
//! * multi-line replies (history dumps), which are plain lines closed by `END`.
//!
//! The full protocol is described in OpenVPN's `doc/management-notes.txt`.

use std::fmt;

/// The prompt OpenVPN sends when the management interface is password
/// protected. It arrives without a trailing newline.
pub const PASSWORD_PROMPT: &str = "ENTER PASSWORD:";

/// One line received from the management interface, classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// `ENTER PASSWORD:` prompt for the management password.
    PasswordPrompt,
    /// A real-time notification (`>...`).
    Notification(Notification),
    /// `SUCCESS: <text>`
    Success(String),
    /// `ERROR: <text>`
    Error(String),
    /// `END`, closing a multi-line reply.
    End,
    /// A line that is part of a multi-line reply.
    Data(String),
}

/// A real-time notification from OpenVPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// `>INFO:...`, sent right after a client connects.
    Info(String),
    /// `>HOLD:Waiting for hold release:N`; `N` is OpenVPN's suggested wait in seconds.
    Hold { wait_hint: u64 },
    /// `>STATE:...`
    State(StateInfo),
    /// `>BYTECOUNT:in,out`
    ByteCount { bytes_in: u64, bytes_out: u64 },
    /// `>LOG:...`
    Log(LogEntry),
    /// `>PASSWORD:...`
    Password(PasswordNotice),
    /// `>FATAL:...`
    Fatal(String),
    /// Anything else (`>ECHO:`, `>INFOMSG:`, `>NEED-OK:`, ...), kept as raw text.
    Other { kind: String, body: String },
}

/// A connection state change (`>STATE:` notification or `state` history line).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateInfo {
    /// Unix time in seconds, as reported by OpenVPN.
    pub time: i64,
    /// State name, e.g. `CONNECTING`, `WAIT`, `AUTH`, `GET_CONFIG`, `ASSIGN_IP`,
    /// `ADD_ROUTES`, `CONNECTED`, `RECONNECTING`, `EXITING`.
    pub name: String,
    /// Extra detail, e.g. `SUCCESS` or the reason for `RECONNECTING`.
    pub detail: String,
    /// The tunnel address assigned to this machine, if any.
    pub local_ip: String,
    /// The server address in use, if known.
    pub remote_ip: String,
    /// The server port in use, if known.
    pub remote_port: String,
}

/// One OpenVPN log line.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    /// Unix time in seconds (0 when OpenVPN did not include one).
    pub time: i64,
    pub level: LogLevel,
    pub message: String,
}

/// Severity of an OpenVPN log line, from its flag letters.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Fatal,
}

impl LogLevel {
    /// Map OpenVPN's flag letters (`I`, `W`, `N`, `F`, `D`) to a level. When
    /// several letters are present the most severe wins.
    pub fn from_flags(flags: &str) -> Self {
        if flags.contains('F') {
            LogLevel::Fatal
        } else if flags.contains('N') {
            LogLevel::Error
        } else if flags.contains('W') {
            LogLevel::Warning
        } else if flags.contains('D') && !flags.contains('I') {
            LogLevel::Debug
        } else {
            LogLevel::Info
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
            LogLevel::Fatal => "fatal",
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// What a `>PASSWORD:` notification asks for or reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordNotice {
    /// OpenVPN needs a user name and password for the given realm (normally `Auth`).
    NeedAuth {
        realm: String,
        /// Set when the profile uses `static-challenge`; the server then wants the
        /// code sent separately in `SCRV1` format instead of appended.
        static_challenge: Option<StaticChallenge>,
    },
    /// OpenVPN needs a password only (for example a private key passphrase).
    NeedPassword { realm: String },
    /// The server rejected the credentials.
    VerificationFailed { realm: String, reason: String },
    /// The server pushed a session token. The token is a secret and is never kept.
    AuthToken,
    /// Anything else.
    Other(String),
}

/// Settings from a profile's `static-challenge` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    /// Whether the challenge text asks for the response to be echoed.
    pub echo: bool,
    pub text: String,
}

/// Parse one line (without its line ending).
pub fn parse_line(line: &str) -> Line {
    let line = line.trim_end_matches(['\r', '\n']);
    if line == PASSWORD_PROMPT {
        return Line::PasswordPrompt;
    }
    if let Some(rest) = line.strip_prefix('>') {
        return Line::Notification(parse_notification(rest));
    }
    if let Some(rest) = line.strip_prefix("SUCCESS:") {
        return Line::Success(rest.trim().to_string());
    }
    if let Some(rest) = line.strip_prefix("ERROR:") {
        return Line::Error(rest.trim().to_string());
    }
    if line == "END" {
        return Line::End;
    }
    Line::Data(line.to_string())
}

fn parse_notification(rest: &str) -> Notification {
    let (kind, body) = rest.split_once(':').unwrap_or((rest, ""));
    match kind {
        "INFO" => Notification::Info(body.to_string()),
        "HOLD" => Notification::Hold {
            wait_hint: body
                .rsplit(':')
                .next()
                .and_then(|n| n.trim().parse().ok())
                .unwrap_or(0),
        },
        "STATE" => match parse_state(body) {
            Some(s) => Notification::State(s),
            None => other(kind, body),
        },
        "BYTECOUNT" => {
            let mut it = body.split(',');
            match (
                it.next().and_then(|v| v.trim().parse().ok()),
                it.next().and_then(|v| v.trim().parse().ok()),
            ) {
                (Some(bytes_in), Some(bytes_out)) => Notification::ByteCount {
                    bytes_in,
                    bytes_out,
                },
                _ => other(kind, body),
            }
        }
        "LOG" => match parse_log(body) {
            Some(l) => Notification::Log(l),
            None => other(kind, body),
        },
        "PASSWORD" => Notification::Password(parse_password(body)),
        "FATAL" => Notification::Fatal(body.to_string()),
        _ => other(kind, body),
    }
}

fn other(kind: &str, body: &str) -> Notification {
    Notification::Other {
        kind: kind.to_string(),
        body: body.to_string(),
    }
}

/// The state names OpenVPN reports (`man_state_name` in its `manage.c`).
const STATE_NAMES: &[&str] = &[
    "INITIAL",
    "CONNECTING",
    "RESOLVE",
    "TCP_CONNECT",
    "WAIT",
    "AUTH",
    "AUTH_PENDING",
    "GET_CONFIG",
    "ASSIGN_IP",
    "ADD_ROUTES",
    "CONNECTED",
    "RECONNECTING",
    "EXITING",
];

/// Whether `name` is the name of a connection state.
///
/// A log line has the same shape as a state line, `time,flags,message`, with
/// one or more of the letters `I`, `W`, `N`, `F` and `D` where a state line
/// has the name. So `1700000000,D,MANAGEMENT: CMD 'log on all'` must not be
/// read as the state `D`. A name that OpenVPN may add later still counts
/// when it is a word of capital letters that is not made of those letters.
pub fn is_state_name(name: &str) -> bool {
    if STATE_NAMES.contains(&name) {
        return true;
    }
    name.len() >= 4
        && name.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && !name.chars().all(|c| "IWNFD".contains(c))
}

/// Parse a state line: `time,STATE,detail,local_ip,remote_ip,remote_port,...`.
/// Used for both `>STATE:` notifications and `state` history lines. A log
/// line gives `None` (see [`is_state_name`]).
pub fn parse_state(body: &str) -> Option<StateInfo> {
    let f: Vec<&str> = body.split(',').collect();
    if f.len() < 2 {
        return None;
    }
    let time = f[0].trim().parse().ok()?;
    let name = f[1].trim();
    if !is_state_name(name) {
        return None;
    }
    let get = |i: usize| f.get(i).map(|s| s.trim().to_string()).unwrap_or_default();
    Some(StateInfo {
        time,
        name: name.to_string(),
        detail: get(2),
        local_ip: get(3),
        remote_ip: get(4),
        remote_port: get(5),
    })
}

/// Parse a log line: `time,flags,message`. Used for both `>LOG:`
/// notifications and `log` history lines. The message may itself contain commas.
pub fn parse_log(body: &str) -> Option<LogEntry> {
    let mut it = body.splitn(3, ',');
    let time = it.next()?.trim();
    let flags = it.next()?;
    let message = it.next().unwrap_or("");
    let time = if time.is_empty() {
        0
    } else {
        time.parse().ok()?
    };
    Some(LogEntry {
        time,
        level: LogLevel::from_flags(flags),
        message: message.to_string(),
    })
}

fn parse_password(body: &str) -> PasswordNotice {
    if body.starts_with("Auth-Token:") {
        return PasswordNotice::AuthToken;
    }
    if let Some(rest) = body.strip_prefix("Need ") {
        let realm = quoted(rest).unwrap_or_default();
        if rest.contains("username/password") {
            return PasswordNotice::NeedAuth {
                realm,
                static_challenge: parse_static_challenge(rest),
            };
        }
        if rest.contains(" password") {
            return PasswordNotice::NeedPassword { realm };
        }
    }
    if let Some(rest) = body.strip_prefix("Verification Failed:") {
        let realm = quoted(rest).unwrap_or_default();
        // The reason, when the server gave one, follows as ['text'].
        let after = rest.splitn(3, '\'').nth(2).unwrap_or("").trim();
        let reason = after
            .trim_matches(|c| c == '[' || c == ']')
            .trim_matches('\'')
            .to_string();
        return PasswordNotice::VerificationFailed { realm, reason };
    }
    PasswordNotice::Other(body.to_string())
}

/// Text between the first pair of single quotes.
fn quoted(s: &str) -> Option<String> {
    let start = s.find('\'')? + 1;
    let len = s[start..].find('\'')?;
    Some(s[start..start + len].to_string())
}

/// `... SC:1,Enter code` -> echo flag and challenge text.
fn parse_static_challenge(rest: &str) -> Option<StaticChallenge> {
    let sc = &rest[rest.find("SC:")? + 3..];
    let (flag, text) = sc.split_once(',').unwrap_or((sc, ""));
    let flag: u32 = flag.trim().parse().ok()?;
    Some(StaticChallenge {
        echo: flag & 1 == 1,
        text: text.to_string(),
    })
}

/// Quote a value for a management command, escaping `\` and `"`.
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars().filter(|c| *c != '\n' && *c != '\r') {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// Build the password value sent for a static-challenge profile:
/// `SCRV1:<base64 password>:<base64 code>`.
pub fn static_challenge_response(password: &str, code: &str) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    format!("SCRV1:{}:{}", b64.encode(password), b64.encode(code))
}

/// Facts pulled out of OpenVPN's log text: the pushed options and version.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushReply {
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub ifconfig: Option<String>,
}

/// Parse the options in a `PUSH: Received control message: 'PUSH_REPLY,...'` log
/// message. Returns `None` for any other message.
pub fn parse_push_reply(message: &str) -> Option<PushReply> {
    let start = message.find("PUSH_REPLY,")? + "PUSH_REPLY,".len();
    let body = message[start..].trim_end_matches('\'');
    let mut reply = PushReply::default();
    for opt in body.split(',') {
        let mut words = opt.split_whitespace();
        match words.next() {
            Some("route") => {
                let net = words.next().unwrap_or_default();
                let mask = words.next().unwrap_or("255.255.255.255");
                reply.routes.push(format!("{net}/{}", mask_to_prefix(mask)));
            }
            Some("route-ipv6") => {
                if let Some(net) = words.next() {
                    reply.routes.push(net.to_string());
                }
            }
            Some("redirect-gateway") => reply.routes.push("0.0.0.0/0 (all traffic)".into()),
            Some("dhcp-option") => {
                let kind = words.next().unwrap_or_default();
                if kind == "DNS" || kind == "DNS6" {
                    if let Some(addr) = words.next() {
                        reply.dns.push(addr.to_string());
                    }
                }
            }
            Some("dns") => {
                // OpenVPN 2.6 form: `dns server 0 address 10.0.0.1`
                let parts: Vec<&str> = words.collect();
                if let Some(pos) = parts.iter().position(|w| *w == "address") {
                    reply
                        .dns
                        .extend(parts[pos + 1..].iter().map(|s| s.to_string()));
                }
            }
            Some("ifconfig") => {
                let rest: Vec<&str> = words.collect();
                reply.ifconfig = Some(rest.join(" "));
            }
            _ => {}
        }
    }
    Some(reply)
}

/// The server address in a log line that names the link, as `host:port`.
///
/// OpenVPN writes the address as `[AF_INET]203.0.113.10:8443` in lines such as
/// `TCP connection established with ...`, `... link remote: ...` and
/// `TCP: connect to ... failed: ...`. Other lines give `None`.
pub fn parse_link_remote(message: &str) -> Option<String> {
    let names_link = [
        "link remote:",
        "TCP connection established with",
        "Attempting to establish TCP connection with",
        "TCP: connect to",
    ]
    .iter()
    .any(|p| message.contains(p));
    if !names_link {
        return None;
    }
    let rest = &message[message.find("[AF_INET")?..];
    let addr = rest.split_once(']')?.1;
    let addr: String = addr
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    (!addr.is_empty()).then_some(addr)
}

/// `255.255.255.0` -> `24`. Returns the mask unchanged if it is not a dotted mask.
fn mask_to_prefix(mask: &str) -> String {
    let octets: Option<Vec<u8>> = mask.split('.').map(|o| o.parse().ok()).collect();
    match octets {
        Some(o) if o.len() == 4 => {
            let n = u32::from_be_bytes([o[0], o[1], o[2], o[3]]);
            n.count_ones().to_string()
        }
        _ => mask.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_basic_lines() {
        assert_eq!(parse_line("ENTER PASSWORD:"), Line::PasswordPrompt);
        assert_eq!(
            parse_line("SUCCESS: password is correct\r\n"),
            Line::Success("password is correct".into())
        );
        assert_eq!(
            parse_line("ERROR: unknown command"),
            Line::Error("unknown command".into())
        );
        assert_eq!(parse_line("END"), Line::End);
        assert_eq!(
            parse_line("1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,"),
            Line::Data("1700000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,".into())
        );
    }

    #[test]
    fn parses_state() {
        let l = parse_line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,8443,,");
        let Line::Notification(Notification::State(s)) = l else {
            panic!("not a state: {l:?}")
        };
        assert_eq!(s.time, 1_700_000_000);
        assert_eq!(s.name, "CONNECTED");
        assert_eq!(s.detail, "SUCCESS");
        assert_eq!(s.local_ip, "10.8.0.6");
        assert_eq!(s.remote_ip, "203.0.113.5");
        assert_eq!(s.remote_port, "8443");

        let short = parse_state("1700000001,WAIT,,").unwrap();
        assert_eq!(short.name, "WAIT");
        assert_eq!(short.local_ip, "");
        assert!(parse_state("1700000001,0,I,hello").is_none());
        assert!(parse_state("garbage").is_none());
    }

    /// The lines of a captured log that were once shown as the states `D` and `I`.
    #[test]
    fn a_log_line_is_never_a_state() {
        for line in [
            "1795427689,D,MANAGEMENT: CMD 'log on all'",
            "1795427689,D,MANAGEMENT: CMD 'hold release'",
            "1795427689,I,OpenVPN 2.6.12 Windows [SSL (OpenSSL)] [LZO] [LZ4] [PKCS11] [AEAD] [DCO]",
            "1795427689,I,library versions: OpenSSL 3.3.7 7 Apr 2026, LZO 2.10",
            "1795427689,,MANAGEMENT: TCP Socket listening on [AF_INET]127.0.0.1:54589",
            "1795427689,W,WARNING: something",
            "1795427689,NW,two flags",
            "1795427689,FD,two more",
        ] {
            assert_eq!(parse_state(line), None, "{line}");
            assert_eq!(
                parse_line(&format!(">STATE:{line}")),
                Line::Notification(Notification::Other {
                    kind: "STATE".into(),
                    body: line.into()
                })
            );
            // As a log line it reads fine.
            assert!(parse_log(line).is_some(), "{line}");
        }
        for name in STATE_NAMES {
            let s = parse_state(&format!("1700000001,{name},,,,")).expect(name);
            assert_eq!(s.name, *name);
        }
        // A state OpenVPN may add one day.
        assert!(is_state_name("NEW_STATE"));
        assert!(!is_state_name("lower"));
        assert!(!is_state_name("WIND"));
    }

    #[test]
    fn parses_bytecount_and_hold() {
        assert_eq!(
            parse_line(">BYTECOUNT:1024,2048"),
            Line::Notification(Notification::ByteCount {
                bytes_in: 1024,
                bytes_out: 2048
            })
        );
        assert_eq!(
            parse_line(">HOLD:Waiting for hold release:10"),
            Line::Notification(Notification::Hold { wait_hint: 10 })
        );
        assert_eq!(
            parse_line(">HOLD:Waiting for hold release"),
            Line::Notification(Notification::Hold { wait_hint: 0 })
        );
    }

    #[test]
    fn parses_log_lines_with_commas() {
        let l = parse_line(">LOG:1700000000,W,WARNING: a, b, c");
        let Line::Notification(Notification::Log(e)) = l else {
            panic!()
        };
        assert_eq!(e.level, LogLevel::Warning);
        assert_eq!(e.message, "WARNING: a, b, c");
        let h = parse_log("1700000000,I,Initialization Sequence Completed").unwrap();
        assert_eq!(h.level, LogLevel::Info);
        assert_eq!(LogLevel::from_flags("NW"), LogLevel::Error);
        assert_eq!(LogLevel::from_flags("F"), LogLevel::Fatal);
        assert_eq!(LogLevel::from_flags("D"), LogLevel::Debug);
    }

    #[test]
    fn parses_password_requests() {
        assert_eq!(
            parse_line(">PASSWORD:Need 'Auth' username/password"),
            Line::Notification(Notification::Password(PasswordNotice::NeedAuth {
                realm: "Auth".into(),
                static_challenge: None
            }))
        );
        assert_eq!(
            parse_line(">PASSWORD:Need 'Auth' username/password SC:1,Enter your code"),
            Line::Notification(Notification::Password(PasswordNotice::NeedAuth {
                realm: "Auth".into(),
                static_challenge: Some(StaticChallenge {
                    echo: true,
                    text: "Enter your code".into()
                })
            }))
        );
        assert_eq!(
            parse_line(">PASSWORD:Need 'Private Key' password"),
            Line::Notification(Notification::Password(PasswordNotice::NeedPassword {
                realm: "Private Key".into()
            }))
        );
        assert_eq!(
            parse_line(">PASSWORD:Verification Failed: 'Auth'"),
            Line::Notification(Notification::Password(PasswordNotice::VerificationFailed {
                realm: "Auth".into(),
                reason: String::new()
            }))
        );
        assert_eq!(
            parse_line(">PASSWORD:Auth-Token:c2VjcmV0"),
            Line::Notification(Notification::Password(PasswordNotice::AuthToken))
        );
    }

    #[test]
    fn parses_the_reason_of_a_rejected_login() {
        assert_eq!(
            parse_line(
                ">PASSWORD:Verification Failed: 'Auth' ['Data channel cipher negotiation failed (no shared cipher)']"
            ),
            Line::Notification(Notification::Password(PasswordNotice::VerificationFailed {
                realm: "Auth".into(),
                reason: "Data channel cipher negotiation failed (no shared cipher)".into()
            }))
        );
    }

    #[test]
    fn finds_the_server_address_in_link_lines() {
        assert_eq!(
            parse_link_remote("TCP connection established with [AF_INET]203.0.113.10:8443")
                .as_deref(),
            Some("203.0.113.10:8443")
        );
        assert_eq!(
            parse_link_remote("TCPv4_CLIENT link remote: [AF_INET]203.0.113.10:8443").as_deref(),
            Some("203.0.113.10:8443")
        );
        assert_eq!(
            parse_link_remote(
                "TCP: connect to [AF_INET]10.255.0.1:8443 failed: Connection timed out"
            )
            .as_deref(),
            Some("10.255.0.1:8443")
        );
        assert_eq!(
            parse_link_remote("UDPv6 link remote: [AF_INET6]2001:db8::1:1194").as_deref(),
            Some("2001:db8::1:1194")
        );
        assert_eq!(parse_link_remote("UDPv4 link local: (not bound)"), None);
        assert_eq!(parse_link_remote("VERIFY OK: depth=0, CN=x"), None);
    }

    #[test]
    fn parses_fatal_and_other() {
        assert_eq!(
            parse_line(">FATAL:Cannot open TUN"),
            Line::Notification(Notification::Fatal("Cannot open TUN".into()))
        );
        assert_eq!(
            parse_line(">INFO:OpenVPN Management Interface Version 5"),
            Line::Notification(Notification::Info(
                "OpenVPN Management Interface Version 5".into()
            ))
        );
        assert_eq!(
            parse_line(">ECHO:123,hello"),
            Line::Notification(Notification::Other {
                kind: "ECHO".into(),
                body: "123,hello".into()
            })
        );
    }

    #[test]
    fn quotes_values() {
        assert_eq!(quote("plain"), "\"plain\"");
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(quote("pass word123456"), "\"pass word123456\"");
    }

    #[test]
    fn quote_cannot_inject_a_second_command() {
        assert_eq!(quote("pw\nsignal SIGTERM\r"), "\"pwsignal SIGTERM\"");
    }

    #[test]
    fn builds_static_challenge_response() {
        assert_eq!(
            static_challenge_response("pw", "123456"),
            "SCRV1:cHc=:MTIzNDU2"
        );
    }

    #[test]
    fn parses_push_reply() {
        let msg = "PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,route 192.168.5.0 255.255.255.0,dhcp-option DNS 10.20.0.53,route-gateway 10.8.0.1,topology subnet,ping 10,ifconfig 10.8.0.6 255.255.255.0'";
        let r = parse_push_reply(msg).unwrap();
        assert_eq!(r.routes, vec!["10.20.0.0/16", "192.168.5.0/24"]);
        assert_eq!(r.dns, vec!["10.20.0.53"]);
        assert_eq!(r.ifconfig.as_deref(), Some("10.8.0.6 255.255.255.0"));
        assert!(parse_push_reply("something else").is_none());
    }
}
