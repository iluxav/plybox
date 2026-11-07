//! Hard storage limits. Persistent overlays need a capacity-limited backing
//! filesystem: polling directory sizes cannot enforce a hard quota. This
//! backend verifies a volume provisioned by the operator; it never resizes
//! the host filesystem or silently falls back to monitoring.
use crate::{limits::parse_size, policy::Policy};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

#[derive(Default, Debug)]
pub struct Caps {
    pub disk: Option<u64>,
    pub tmpfs: Option<u64>,
    pub file_size: Option<u64>,
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
}

impl Caps {
    pub fn parse(pol: &Policy) -> Result<Self, String> {
        let size = |s: &Option<String>| s.as_deref().map(parse_size).transpose();
        let disk = size(&pol.limits.disk)?;
        let tmpfs = size(&pol.limits.tmpfs)?.or(disk.map(|n| n.min(64 << 20)));
        let caps = Self {
            disk,
            tmpfs,
            file_size: size(&pol.limits.file_size)?,
            bytes_out: size(&pol.limits.bytes_out)?,
            bytes_in: size(&pol.limits.bytes_in)?,
        };
        if disk == Some(0) {
            return Err("disk must be greater than zero".into());
        }
        if let Some(n) = tmpfs {
            if !(3 * 4096..=i64::MAX as u64).contains(&n) {
                return Err("tmpfs must be at least 12K and at most i64::MAX bytes".into());
            }
        }
        if caps.file_size.is_some_and(|n| n > i64::MAX as u64) {
            return Err("file_size exceeds the maximum Linux file size".into());
        }
        if (disk.is_some() || tmpfs.is_some()) && pol.isolation != "ns" {
            return Err("disk/tmpfs caps currently require namespace isolation; gVisor is not verified for these caps".into());
        }
        if disk.is_some() && pol.fs.workspace_mode != "overlay" {
            return Err("disk caps require an overlay workspace; bind writes are outside the session volume".into());
        }
        Ok(caps)
    }

    /// Three separate scratch mounts share the configured total allocation
    /// by dividing it into equal page-aligned capacities (round DOWN).
    pub fn scratch_mount_bytes(&self) -> Option<u64> {
        self.tmpfs.map(|n| n / 3 / 4096 * 4096)
    }
}

pub fn verify_volume(session: &Path, cap: u64) -> Result<u64, String> {
    let f = std::fs::File::open(session).map_err(|e| format!("disk volume: {e}"))?;
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(f.as_raw_fd(), &mut fs) } != 0 {
        return Err(format!("disk volume: {}", std::io::Error::last_os_error()));
    }
    // Deliberately exclude virtual/remote filesystems and btrfs (subvolume
    // accounting is not a hard per-session quota). No free-space estimates.
    if ![0xef53, 0x58465342, 0x01021994].contains(&fs.f_type) {
        return Err("disk cap needs a capacity-limited ext4, XFS or tmpfs session volume; this filesystem is unsupported".into());
    }
    // f_blocks counts f_frsize units (statfs(2)); f_bsize is only the
    // preferred I/O size. They coincide on ext4/XFS/tmpfs, but use the right
    // one so a filesystem where they differ cannot pass with a wrong total.
    // The field is u64 on musl and i64 on glibc, hence the conversion.
    #[allow(clippy::useless_conversion)]
    let frsize = u64::try_from(fs.f_frsize).map_err(|_| "invalid volume fragment size")?;
    let bytes = fs.f_blocks.checked_mul(frsize).ok_or("disk volume capacity overflow")?;
    if bytes == 0 || bytes > cap {
        return Err(format!("disk cap {cap} cannot be enforced: session volume capacity is {bytes} bytes; use --session on a dedicated volume with capacity at most {cap} (a directory on a larger disk is not a quota)"));
    }
    // OverlayFS owns a mode-000 work/work directory. Enumerate mountinfo,
    // not user-created directory contents: even the unprivileged owner
    // cannot traverse all saved overlay directories.
    let mounts =
        std::fs::read("/proc/self/mountinfo").map_err(|e| format!("disk mount validation: {e}"))?;
    reject_nested_mounts(session, &mounts)?;
    Ok(bytes)
}

fn reject_nested_mounts(session: &Path, mounts: &[u8]) -> Result<(), String> {
    for line in mounts.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let field = line
            .split(|b| *b == b' ')
            .nth(4)
            .ok_or("malformed mountinfo")?;
        let mut decoded = Vec::with_capacity(field.len());
        let mut i = 0;
        while i < field.len() {
            if field[i] == b'\\' {
                let oct = field
                    .get(i + 1..i + 4)
                    .ok_or("malformed mountinfo escape")?;
                if !oct.iter().all(|b| (b'0'..=b'7').contains(b)) {
                    return Err("malformed mountinfo escape".into());
                }
                let byte = (oct[0] - b'0') as u16 * 64
                    + (oct[1] - b'0') as u16 * 8
                    + (oct[2] - b'0') as u16;
                decoded.push(u8::try_from(byte).map_err(|_| "malformed mountinfo escape")?);
                i += 4;
            } else {
                decoded.push(field[i]);
                i += 1;
            }
        }
        let mount = std::path::PathBuf::from(std::ffi::OsString::from_vec(decoded));
        if mount != session && mount.starts_with(session) {
            return Err(format!(
                "disk cap: nested mount in session volume at {}",
                mount.display()
            ));
        }
    }
    Ok(())
}

/// Both soft and hard limits are inherited by exec and descendants. A
/// workload with no capabilities cannot raise the hard limit again.
pub fn limit_file_size(bytes: u64) -> Result<(), String> {
    let r = libc::rlimit {
        rlim_cur: bytes,
        rlim_max: bytes,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &r) } != 0 {
        return Err(format!("file_size: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nested_mount_validation_decodes_paths_and_respects_components() {
        let session = Path::new("/pool/my session");
        let outside = b"1 0 0:1 / /pool/my\\040session-two rw - tmpfs tmpfs rw\n";
        assert!(reject_nested_mounts(session, outside).is_ok());
        let own = b"1 0 0:1 / /pool/my\\040session rw - tmpfs tmpfs rw\n";
        assert!(reject_nested_mounts(session, own).is_ok());
        let nested = b"1 0 0:1 / /pool/my\\040session/upper/mount rw - tmpfs tmpfs rw\n";
        assert!(reject_nested_mounts(session, nested)
            .unwrap_err()
            .contains("nested mount"));
    }
    #[test]
    fn unsupported_storage_modes_fail_closed() {
        let mut p = Policy::default();
        p.limits.disk = Some("16M".into());
        p.isolation = "gvisor".into();
        assert!(Caps::parse(&p).unwrap_err().contains("gVisor"));
        p.isolation = "ns".into();
        p.fs.workspace_mode = "bind".into();
        assert!(Caps::parse(&p).unwrap_err().contains("overlay"));
    }
    #[test]
    fn scratch_capacity_never_exceeds_requested_total() {
        let mut p = Policy::default();
        p.limits.tmpfs = Some("16385".into());
        let c = Caps::parse(&p).unwrap();
        assert_eq!(c.scratch_mount_bytes(), Some(4096));
        p.limits.tmpfs = Some("0".into());
        assert!(Caps::parse(&p).is_err());
    }
}
