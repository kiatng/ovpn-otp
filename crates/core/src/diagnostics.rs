//! "Copy diagnostics": a plain-text report to paste into an issue or a chat.
//!
//! The report never contains the password or code (they are never recorded in
//! the first place). The user name is replaced with `<user>`, and the inline
//! profile text is left out of the settings.

use chrono::Local;

use crate::settings::Settings;
use crate::snapshot::{format_bytes, format_duration, Snapshot};

/// Build the report. `username` is removed wherever it appears.
pub fn bundle(snap: &Snapshot, settings: &Settings, settings_path: &str, username: &str) -> String {
    let now = Local::now();
    let mut out = String::new();
    let mut line = |s: String| {
        out.push_str(&s);
        out.push('\n');
    };
    line("ovpn-otp diagnostics".into());
    line(format!("generated: {}", now.format("%Y-%m-%d %H:%M:%S %z")));
    line(format!(
        "app: ovpn-otp {} on {} {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    line(format!("openvpn: {}", empty_dash(&snap.openvpn_version)));
    line(String::new());

    line("== status ==".into());
    line(format!("phase: {}", snap.phase.label()));
    line(format!(
        "openvpn state: {} {}",
        empty_dash(&snap.state),
        snap.state_detail
    ));
    line(format!("server: {}", empty_dash(&snap.server)));
    line(format!("tunnel address: {}", empty_dash(&snap.local_ip)));
    if let Some(since) = snap.connected_since {
        line(format!(
            "connected for: {}",
            format_duration((now - since).num_seconds())
        ));
    }
    line(format!(
        "received: {} ({}/s)   sent: {} ({}/s)",
        format_bytes(snap.bytes_in),
        format_bytes(snap.rate_in as u64),
        format_bytes(snap.bytes_out),
        format_bytes(snap.rate_out as u64)
    ));
    if let Some(idle) = snap.idle_secs(now) {
        line(format!("last data received: {} ago", format_duration(idle)));
    }
    line(format!("routes: {}", join_or_dash(&snap.routes)));
    line(format!("dns: {}", join_or_dash(&snap.dns)));
    if let Some(r) = &snap.reach {
        line(format!(
            "reach {}: {}",
            r.target,
            match (r.ok, r.latency_ms) {
                (true, Some(ms)) => format!("ok, {ms:.1} ms"),
                _ => format!("failed: {}", r.error.clone().unwrap_or_default()),
            }
        ));
    }
    if let Some(e) = &snap.last_error {
        line(format!("last error: {e}"));
    }
    line(String::new());

    line(format!("== settings ({settings_path}) ==", ));
    let mut shown = settings.clone();
    if !shown.profile.inline.is_empty() {
        shown.profile.inline = format!("<{} bytes of inline profile, not shown>", shown.profile.inline.len());
    }
    line(shown.to_toml());

    line("== timeline ==".into());
    for t in &snap.timeline {
        line(format!("{} {:<13} {}", t.at.format("%H:%M:%S"), t.state, t.detail));
    }
    line(String::new());

    line("== log (last 300 lines) ==".into());
    let skip = snap.logs.len().saturating_sub(300);
    for l in snap.logs.iter().skip(skip) {
        line(format!(
            "{} {:<7} {:<7} {}",
            l.at.format("%H:%M:%S"),
            l.source,
            l.level.label(),
            l.message
        ));
    }
    line(String::new());

    line("== management transcript (last 200 lines, secrets hidden) ==".into());
    let skip = snap.wire.len().saturating_sub(200);
    for w in snap.wire.iter().skip(skip) {
        let arrow = match w.dir {
            crate::session::Direction::In => "<-",
            crate::session::Direction::Out => "->",
        };
        line(format!("{} {arrow} {}", w.at.format("%H:%M:%S"), w.text));
    }
    redact(&out, username)
}

/// Replace every occurrence of `username` with `<user>`.
pub fn redact(text: &str, username: &str) -> String {
    let username = username.trim();
    if username.len() < 2 {
        return text.to_string();
    }
    text.replace(username, "<user>")
}

fn empty_dash(s: &str) -> &str {
    if s.is_empty() {
        "-"
    } else {
        s
    }
}

fn join_or_dash(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{Direction, Event};

    #[test]
    fn report_hides_username_and_inline_profile() {
        let mut snap = Snapshot::default();
        snap.apply(&Event::Wire {
            at: Local::now(),
            dir: Direction::Out,
            text: "username \"Auth\" \"alice.tan\"".into(),
        });
        let mut s = Settings::default();
        s.profile.inline = "client\n<key>\nSECRETKEY\n</key>\n".into();
        let text = bundle(&snap, &s, "/x/settings.toml", "alice.tan");
        assert!(!text.contains("alice.tan"));
        assert!(text.contains("username \"Auth\" \"<user>\""));
        assert!(!text.contains("SECRETKEY"));
        assert!(text.contains("inline profile, not shown"));
    }
}
