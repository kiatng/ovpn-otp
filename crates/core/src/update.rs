//! Download and install the official release for this platform.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

const API: &str = "https://api.github.com/repos/kiatng/ovpn-otp/releases/latest";
const MAX_ARCHIVE: u64 = 100 * 1024 * 1024;
const MAX_BINARY: u64 = 100 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Release {
    pub version: semver::Version,
}

#[derive(Deserialize)]
struct ReleaseMetadata {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .user_agent("ovpn-otp-updater")
        .https_only(true)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| e.to_string())
}

pub fn check() -> Result<Option<Release>, String> {
    let r: ReleaseMetadata = client()?
        .get(API)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .map_err(|e| e.to_string())?;
    if r.draft || r.prerelease {
        return Ok(None);
    }
    let version =
        semver::Version::parse(r.tag_name.strip_prefix('v').ok_or("Invalid release tag")?)
            .map_err(|e| e.to_string())?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION")).map_err(|e| e.to_string())?;
    Ok(
        (version > current && version.pre.is_empty() && version.build.is_empty())
            .then_some(Release { version }),
    )
}

fn platform() -> Result<(&'static str, &'static str, [&'static str; 2]), String> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Ok((
            "x86_64-pc-windows-msvc",
            "zip",
            ["ovpn-otp.exe", "ovpn-otp-gui.exe"],
        ))
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok((
            "x86_64-unknown-linux-gnu",
            "tar.gz",
            ["ovpn-otp", "ovpn-otp-gui"],
        ))
    } else {
        Err("No release is available for this platform".into())
    }
}

fn download(url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let response = client()?
        .get(url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("Download is too large".into());
    }
    Ok(bytes)
}

fn verify(bytes: &[u8], checksum: &str, filename: &str) -> Result<(), String> {
    let mut fields = checksum.split_whitespace();
    let hash = fields.next().ok_or("Empty checksum")?;
    let name = fields.next().ok_or("Missing checksum filename")?;
    if name.trim_start_matches('*') != filename
        || fields.next().is_some()
        || hash.len() != 64
        || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("Invalid checksum file".into());
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(hash) {
        return Err("Downloaded archive failed its SHA-256 check".into());
    }
    Ok(())
}

fn save_binary(mut input: impl Read, path: &Path) -> Result<(), String> {
    let mut file = fs::File::create(path).map_err(|e| e.to_string())?;
    let n =
        io::copy(&mut input.by_ref().take(MAX_BINARY + 1), &mut file).map_err(|e| e.to_string())?;
    if n == 0 || n > MAX_BINARY {
        return Err("Invalid executable size".into());
    }
    file.flush().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn unpack(
    bytes: &[u8],
    root: &str,
    names: [&str; 2],
    stage: &Path,
    ext: &str,
) -> Result<(), String> {
    let mut found = [false; 2];
    if ext == "zip" {
        let mut zip = zip::ZipArchive::new(io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
            for (n, name) in names.iter().enumerate() {
                if entry.name() == format!("{root}/{name}") {
                    if found[n] || entry.is_dir() {
                        return Err("Invalid archive entries".into());
                    }
                    save_binary(&mut entry, &stage.join(name))?;
                    found[n] = true;
                }
            }
        }
    } else {
        let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
        for entry in archive.entries().map_err(|e| e.to_string())? {
            let mut entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path().map_err(|e| e.to_string())?.into_owned();
            for (n, name) in names.iter().enumerate() {
                if path == Path::new(root).join(name) {
                    if found[n] || !entry.header().entry_type().is_file() {
                        return Err("Invalid archive entries".into());
                    }
                    save_binary(&mut entry, &stage.join(name))?;
                    found[n] = true;
                }
            }
        }
    }
    if !found.into_iter().all(|x| x) {
        return Err("The release is missing an executable".into());
    }
    Ok(())
}

/// Verify and install both executables alongside the running executable.
pub fn install(release: &Release) -> Result<PathBuf, String> {
    let (target, ext, names) = platform()?;
    let root = format!("ovpn-otp-v{}-{target}", release.version);
    let filename = format!("{root}.{ext}");
    let base = format!(
        "https://github.com/kiatng/ovpn-otp/releases/download/v{}",
        release.version
    );
    let checksum = download(&format!("{base}/{filename}.sha256"), 4096)?;
    let archive = download(&format!("{base}/{filename}"), MAX_ARCHIVE)?;
    verify(
        &archive,
        std::str::from_utf8(&checksum).map_err(|e| e.to_string())?,
        &filename,
    )?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if !names
        .iter()
        .any(|name| exe.file_name().is_some_and(|n| n == *name))
    {
        return Err("The program was renamed; install the release manually.".into());
    }
    let dir = exe.parent().ok_or("Cannot find installation folder")?;
    let stage = tempfile::Builder::new()
        .prefix(".ovpn-otp-update-")
        .tempdir_in(dir)
        .map_err(|e| format!("Cannot write to installation folder: {e}"))?;
    unpack(&archive, &root, names, stage.path(), ext)?;
    if let Err((error, recovery_failed)) = replace_pair(dir, stage.path(), names) {
        if recovery_failed {
            let kept = stage.keep();
            return Err(format!(
                "{error} Some files could not be restored; backups remain in {}.",
                kept.display()
            ));
        }
        return Err(error);
    }
    Ok(exe)
}

fn replace_pair(dir: &Path, stage: &Path, names: [&str; 2]) -> Result<(), (String, bool)> {
    let mut installed: Vec<(&str, bool)> = Vec::new();
    for name in names {
        let dest = dir.join(name);
        let backup = stage.join(format!("{name}.old"));
        let existed = dest.exists();
        let mut recovery_failed = false;
        let result = (|| -> io::Result<()> {
            if existed {
                fs::rename(&dest, &backup)?;
            }
            if let Err(e) = fs::rename(stage.join(name), &dest) {
                if existed && fs::rename(&backup, &dest).is_err() {
                    recovery_failed = true;
                }
                return Err(e);
            }
            Ok(())
        })();
        if let Err(e) = result {
            for (prior, existed) in installed.into_iter().rev() {
                let dest = dir.join(prior);
                if fs::remove_file(&dest).is_err() {
                    recovery_failed = true;
                    continue;
                }
                if existed && fs::rename(stage.join(format!("{prior}.old")), dest).is_err() {
                    recovery_failed = true;
                }
            }
            return Err((format!("Could not replace {name}: {e}."), recovery_failed));
        }
        installed.push((name, existed));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_checks_file_and_contents() {
        let bytes = b"release";
        let hash = format!("{:x}", Sha256::digest(bytes));
        assert!(verify(bytes, &format!("{hash}  release.zip\n"), "release.zip").is_ok());
        assert!(verify(b"changed", &format!("{hash}  release.zip"), "release.zip").is_err());
        assert!(verify(bytes, &format!("{hash}  other.zip"), "release.zip").is_err());
    }
    #[test]
    fn zip_extracts_only_expected_executables_and_requires_both() {
        let mut zip = zip::ZipWriter::new(io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("release/ovpn-otp.exe", options).unwrap();
        zip.write_all(b"cli").unwrap();
        zip.start_file("release/ovpn-otp-gui.exe", options).unwrap();
        zip.write_all(b"gui").unwrap();
        zip.start_file("release/../../unwanted", options).unwrap();
        zip.write_all(b"bad").unwrap();
        let bytes = zip.finish().unwrap().into_inner();
        let dir = tempfile::tempdir().unwrap();
        unpack(
            &bytes,
            "release",
            ["ovpn-otp.exe", "ovpn-otp-gui.exe"],
            dir.path(),
            "zip",
        )
        .unwrap();
        assert_eq!(fs::read(dir.path().join("ovpn-otp.exe")).unwrap(), b"cli");
        assert_eq!(
            fs::read(dir.path().join("ovpn-otp-gui.exe")).unwrap(),
            b"gui"
        );
        assert!(!dir.path().join("unwanted").exists());
        assert!(unpack(
            &bytes,
            "other",
            ["ovpn-otp.exe", "ovpn-otp-gui.exe"],
            dir.path(),
            "zip"
        )
        .is_err());
    }
    #[test]
    fn replacement_failure_restores_the_first_executable() {
        let dir = tempfile::tempdir().unwrap();
        let stage = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cli"), b"old cli").unwrap();
        fs::write(dir.path().join("gui"), b"old gui").unwrap();
        fs::write(stage.path().join("cli"), b"new cli").unwrap();
        assert!(replace_pair(dir.path(), stage.path(), ["cli", "gui"]).is_err());
        assert_eq!(fs::read(dir.path().join("cli")).unwrap(), b"old cli");
        assert_eq!(fs::read(dir.path().join("gui")).unwrap(), b"old gui");
    }
}
