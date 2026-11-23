//! A stand-in for the `openvpn` program, for the command-line tests.
//!
//! It takes the options ovpn-otp gives to OpenVPN, opens the management
//! interface they name, and plays the script in the `OVPN_OTP_FAKE`
//! environment variable (see `ovpn_otp_testkit::Fake::from_spec`), for
//! example `accept=pw123456;plan=reset`. It makes no network connection.

use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use ovpn_otp_testkit::Fake;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    // --management <host> <port> <password file>
    let Some(at) = args.iter().position(|a| a == "--management") else {
        eprintln!("fake openvpn: no --management option");
        return ExitCode::from(1);
    };
    let (Some(host), Some(port), Some(pw_file)) =
        (args.get(at + 1), args.get(at + 2), args.get(at + 3))
    else {
        eprintln!("fake openvpn: --management needs a host, a port and a password file");
        return ExitCode::from(1);
    };
    let spec = std::env::var("OVPN_OTP_FAKE").unwrap_or_default();
    let mut fake = match Fake::from_spec(&spec) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("fake openvpn: OVPN_OTP_FAKE: {e}");
            return ExitCode::from(1);
        }
    };
    match std::fs::read_to_string(pw_file) {
        Ok(pw) => fake.mgmt_password = pw.trim().to_string(),
        Err(e) => {
            eprintln!("fake openvpn: cannot read {pw_file}: {e}");
            return ExitCode::from(1);
        }
    }
    let listener = match TcpListener::bind(format!("{host}:{port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fake openvpn: cannot listen on {host}:{port}: {e}");
            return ExitCode::from(1);
        }
    };
    if let Ok((stream, _)) = listener.accept() {
        fake.serve(stream, Arc::new(AtomicBool::new(false)));
    }
    ExitCode::SUCCESS
}
