//! Reachability check: can we reach a host on the far side of the tunnel?
//!
//! `host:port` opens a TCP connection (no special rights needed). A bare host
//! runs the system `ping` once.

use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use chrono::{DateTime, Local};

use crate::profile::split_host_port;

const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReachResult {
    pub at: DateTime<Local>,
    pub target: String,
    pub ok: bool,
    /// Round-trip or connect time in milliseconds, when it worked.
    pub latency_ms: Option<f64>,
    /// Why it failed.
    pub error: Option<String>,
}

pub fn check(target: &str) -> ReachResult {
    let target = target.trim();
    let at = Local::now();
    let result = match split_host_port(target) {
        (host, Some(port)) => tcp_check(&host, &port),
        (host, None) => ping_check(&host),
    };
    match result {
        Ok(ms) => ReachResult {
            at,
            target: target.to_string(),
            ok: true,
            latency_ms: Some(ms),
            error: None,
        },
        Err(e) => ReachResult {
            at,
            target: target.to_string(),
            ok: false,
            latency_ms: None,
            error: Some(e),
        },
    }
}

fn tcp_check(host: &str, port: &str) -> Result<f64, String> {
    let port: u16 = port.parse().map_err(|_| format!("bad port {port}"))?;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve {host}"))?;
    let start = Instant::now();
    TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| e.to_string())?;
    Ok(start.elapsed().as_secs_f64() * 1000.0)
}

fn ping_check(host: &str) -> Result<f64, String> {
    if host.is_empty() || host.starts_with('-') {
        return Err("no host to check".into());
    }
    let mut cmd = Command::new("ping");
    if cfg!(windows) {
        cmd.args(["-n", "1", "-w", "3000", host]);
    } else {
        cmd.args(["-c", "1", "-W", "3", host]);
    }
    cmd.stdin(Stdio::null()).stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let out = cmd.output().map_err(|e| format!("cannot run ping: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match (out.status.success(), parse_ping_ms(&text)) {
        (true, Some(ms)) => Ok(ms),
        _ => Err(format!("no reply from {host}")),
    }
}

/// Find the round-trip time in `ping` output: `time=12.3 ms`, `time=12ms`, `time<1ms`.
pub fn parse_ping_ms(text: &str) -> Option<f64> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(i) = lower.find("time").or_else(|| lower.find("zeit")) else {
            continue;
        };
        let rest = &lower[i..];
        let Some(j) = rest.find(['=', '<']) else {
            continue;
        };
        let less = rest[j..].starts_with('<');
        let num: String = rest[j + 1..]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        if let Ok(v) = num.parse::<f64>() {
            return Some(if less { v / 2.0 } else { v });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ping_output() {
        assert_eq!(
            parse_ping_ms("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=12.3 ms"),
            Some(12.3)
        );
        assert_eq!(
            parse_ping_ms("Reply from 10.0.0.1: bytes=32 time=15ms TTL=128"),
            Some(15.0)
        );
        assert_eq!(
            parse_ping_ms("Reply from 10.0.0.1: bytes=32 time<1ms TTL=128"),
            Some(0.5)
        );
        assert_eq!(parse_ping_ms("Request timed out."), None);
    }

    #[test]
    fn tcp_check_measures_a_local_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let r = check(&format!("127.0.0.1:{port}"));
        assert!(r.ok, "{r:?}");
        assert!(r.latency_ms.unwrap() >= 0.0);
    }

    #[test]
    fn tcp_check_reports_failure() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let r = check(&format!("127.0.0.1:{port}"));
        assert!(!r.ok);
        assert!(r.error.is_some());
    }
}
