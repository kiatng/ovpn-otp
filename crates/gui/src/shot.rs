//! A picture of the window, for the README and for checking a change.
//!
//! Only built with the `screenshots` feature, so none of it is in a release:
//!
//! ```sh
//! cargo build -p ovpn-otp-gui --features screenshots
//! ```
//!
//! Set `OVPN_OTP_GUI_SCREENSHOT` to a `.png` path and the window saves a
//! picture of itself there and closes. These go with it:
//!
//! * `OVPN_OTP_GUI_SCREENSHOT_AFTER`: seconds to wait first (2 when not set);
//! * `OVPN_OTP_GUI_SCREENSHOT_SECTION`: open Details, Log, Wire or Settings;
//! * `OVPN_OTP_GUI_SCREENSHOT_LOGIN`: `user:password:code` to put in the
//!   boxes, for a session against the fake OpenVPN of the tests. Never a
//!   real login: other programs can read the environment of a process;
//! * `OVPN_OTP_GUI_SCREENSHOT_CONNECT=1`: press Connect at the start.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::Section;

pub struct Shot {
    path: PathBuf,
    at: Instant,
    section: Option<Section>,
    login: Option<(String, String, String)>,
    connects: bool,
    asked: bool,
    saved: Arc<AtomicBool>,
}

impl Shot {
    pub fn from_env() -> Option<Shot> {
        let path = std::env::var_os("OVPN_OTP_GUI_SCREENSHOT").filter(|p| !p.is_empty())?;
        let after = std::env::var("OVPN_OTP_GUI_SCREENSHOT_AFTER")
            .ok()
            .and_then(|s| s.trim().parse::<f32>().ok())
            .unwrap_or(2.0);
        let section = std::env::var("OVPN_OTP_GUI_SCREENSHOT_SECTION")
            .ok()
            .and_then(|s| Section::from_name(&s));
        let login = std::env::var("OVPN_OTP_GUI_SCREENSHOT_LOGIN")
            .ok()
            .and_then(|s| {
                let mut parts = s.splitn(3, ':').map(str::to_string);
                Some((parts.next()?, parts.next()?, parts.next()?))
            });
        let connects = std::env::var("OVPN_OTP_GUI_SCREENSHOT_CONNECT").is_ok_and(|v| v == "1");
        Some(Shot {
            login,
            connects,
            path: PathBuf::from(path),
            at: Instant::now() + Duration::from_secs_f32(after.max(0.0)),
            section,
            asked: false,
            saved: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The section to open for the picture.
    pub fn section(&self) -> Option<Section> {
        self.section
    }

    /// What to put in the user name, password and code boxes.
    pub fn login(&self) -> Option<(String, String, String)> {
        self.login.clone()
    }

    /// Whether to press Connect at the start.
    pub fn connects(&self) -> bool {
        self.connects
    }

    /// Ask for the picture when it is time, and close the window once it is saved.
    pub fn tick(&mut self, ctx: &egui::Context) {
        ctx.request_repaint_after(Duration::from_millis(100));
        if self.saved.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        if self.asked || Instant::now() < self.at {
            return;
        }
        self.asked = true;
        let path = self.path.clone();
        let saved = self.saved.clone();
        ctx.request_screenshot(move |image| {
            if let Err(e) = save_png(&path, &image) {
                eprintln!("cannot save the screenshot {}: {e}", path.display());
            }
            saved.store(true, Ordering::SeqCst);
        });
    }
}

fn save_png(path: &Path, image: &egui::ColorImage) -> Result<(), Box<dyn std::error::Error>> {
    let file = std::io::BufWriter::new(std::fs::File::create(path)?);
    let mut encoder = png::Encoder::new(file, image.width() as u32, image.height() as u32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header()?;
    writer.write_image_data(image.as_raw())?;
    Ok(())
}
