//! The pinned runtime cache. Cache files are private and never trusted merely
//! because they exist: every executable is SHA-512 checked on every launch.
//! The machine owner (the caller's uid) is trusted, as with the plybox binary.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest, Sha512};

struct Payload {
    path: &'static str,
    size: u64,
    sha512: &'static str,
    gzip: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/gvisor_payload.rs"));

pub struct Prepared {
    pub path: PathBuf,
    pub sha512: &'static str,
    pub verification_us: u64,
}

pub fn prepare() -> Result<Option<Prepared>, String> {
    if PAYLOAD.is_empty() {
        return Ok(None);
    }
    let base = crate::workspace::state_base();
    prepare_at(&base).map(Some).map_err(|e| format!("embedded gVisor: {e}; no external runtime fallback"))
}

fn prepare_at(base: &Path) -> Result<Prepared, String> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(base).map_err(|e| e.to_string())?;
    // The configured state base may be a symlink, just like HOME. Its owner
    // is trusted, but another user must not be able to replace cache entries.
    let base = fs::canonicalize(base).map_err(|e| e.to_string())?;
    let md = fs::metadata(&base).map_err(|e| e.to_string())?;
    if md.uid() != unsafe { libc::geteuid() } || md.mode() & 0o022 != 0 {
        return Err(format!("unsafe state directory {}: must be owned by you and not writable by others", base.display()));
    }
    let runtimes = base.join("runtimes");
    let _base = private_dir(&runtimes)?;
    let dir = runtimes.join(PAYLOAD_HASH);
    let directory = private_dir(&dir)?;
    // Anchor all child lookups to the directory we checked, not a symlink
    // supplied in place of the payload directory.
    let anchored = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let lock = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(anchored.join(".lock")).map_err(|e| format!("cache lock: {e}"))?;
    check_file(&lock, 0o600).map_err(|e| format!("cache lock: {e}"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(format!("cache lock: {}", io::Error::last_os_error()));
    }
    let sidecars = private_dir(&anchored.join("gvisor-bin"))?;
    let sidecar_path = PathBuf::from(format!("/proc/self/fd/{}", sidecars.as_raw_fd()));
    let mut verification_us = 0;
    for payload in PAYLOAD {
        let (parent, name) = match payload.path.strip_prefix("gvisor-bin/") {
            Some(name) => (&sidecar_path, name),
            None => (&anchored, payload.path),
        };
        let path = parent.join(name);
        let start = Instant::now();
        let valid = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path) {
            Ok(mut file) => {
                check_file(&file, 0o500).map_err(|e| format!("{}: {e}", payload.path))?;
                file.metadata().map_err(|e| e.to_string())?.len() == payload.size
                    && sha512(&mut file).map_err(|e| e.to_string())? == payload.sha512
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(format!("{}: {e}", payload.path)),
        };
        verification_us += start.elapsed().as_micros() as u64;
        if !valid {
            extract(payload, parent, name)?;
        }
    }
    Ok(Prepared { path: dir.join("runsc"), sha512: PAYLOAD[0].sha512, verification_us })
}

fn private_dir(path: &Path) -> Result<File, String> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let dir = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let md = dir.metadata().map_err(|e| e.to_string())?;
    if md.uid() != unsafe { libc::geteuid() } || md.mode() & 0o7777 != 0o700 {
        return Err(format!("{} must be an owner-only directory (0700)", path.display()));
    }
    Ok(dir)
}

fn check_file(file: &File, mode: u32) -> Result<(), String> {
    let md = file.metadata().map_err(|e| e.to_string())?;
    if !md.is_file() || md.uid() != unsafe { libc::geteuid() } || md.mode() & 0o7777 != mode || md.nlink() != 1 {
        return Err(format!("expected a regular file owned by you, mode {mode:04o}, without hard links"));
    }
    Ok(())
}

pub fn sha512(reader: &mut impl Read) -> io::Result<String> {
    let mut hash = Sha512::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

fn extract(payload: &Payload, parent: &Path, name: &str) -> Result<(), String> {
    let (temporary, mut file) = (0..1000).find_map(|n| {
        let path = parent.join(format!(".{name}.{}.{n}.tmp", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => Some(Ok((Temporary(path), file))),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => None,
            Err(e) => Some(Err(e.to_string())),
        }
    }).ok_or("cannot allocate a temporary runtime file")??;
    let mut decoder = flate2::read::GzDecoder::new(payload.gzip).take(payload.size + 1);
    let mut hash = Sha512::new();
    let mut size = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder.read(&mut buf).map_err(|e| format!("decompress {}: {e}", payload.path))?;
        if n == 0 { break; }
        hash.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        size += n as u64;
    }
    if size != payload.size || format!("{:x}", hash.finalize()) != payload.sha512 {
        return Err(format!("embedded payload checksum mismatch: {}", payload.path));
    }
    file.set_permissions(fs::Permissions::from_mode(0o500)).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&temporary.0, parent.join(name)).map_err(|e| e.to_string())?;
    File::open(parent).and_then(|f| f.sync_all()).map_err(|e| e.to_string())?;
    Ok(())
}
