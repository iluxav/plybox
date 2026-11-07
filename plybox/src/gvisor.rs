//! The gVisor tier: `--isolation gvisor`.
//!
//! gVisor (runsc) puts a user-space kernel between the workload and the
//! real one. The lab measured it closing six of the eight kernel doors by
//! not implementing them, with the remaining ones closed by our seccomp
//! allowlist, which applies inside it too. It costs ~10 ms per start and
//! some syscall throughput, needs no root (`--rootless`) and no KVM.
//!
//! The lab also showed that `runsc do`'s convenience mount policy exposes
//! the host filesystem and every unix socket. So plybox writes a real OCI
//! bundle with exactly the mounts the bubblewrap box has, binds only the
//! session directory (where the proxy socket lives) with `--host-uds=open`,
//! and runs the workload as the invoking uid with no capabilities.
//!
//! Workspace: gVisor's overlay is internal (memory or a backing file), not
//! an upper directory plybox can read — and overlaying every mount would
//! also copy the proxy socket up into memory and break it. So here
//! `workspace_mode = "overlay"` means the workspace is mounted READ-ONLY:
//! untrusted code can read the repository and write only to $HOME and /tmp,
//! which vanish at exit. `bind` writes straight to the directory, as usual.
//!
//! Limits: the same cgroup enforcer wraps runsc. Note the lab's finding —
//! inside gVisor a memory kill takes the whole sandbox (the sentry is one
//! process), and TasksMax does not bound guest processes 1:1.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::policy::Policy;

pub struct Bundle {
    pub dir: PathBuf,
}

/// Write the OCI bundle (config.json + rootfs skeleton) into the session.
pub fn write_bundle(
    pol: &Policy,
    work: &Path,
    session: &Path,
    me: &Path,
    inner_argv: &[String],
    env: &[(String, String)],
    workspace_writable: bool,
) -> Result<Bundle, String> {
    let dir = session.join("bundle");
    // Host tools: a skeleton root in the session, the host's /usr bound in.
    // An image: the image itself is the root (read-only; gVisor overlays it
    // in memory, which is also where the mount points get created).
    let host_root = pol.fs.rootfs == "host";
    let rootfs = if host_root {
        dir.join("rootfs")
    } else {
        std::fs::canonicalize(&pol.fs.rootfs).map_err(|e| format!("rootfs {}: {e}", pol.fs.rootfs))?
    };
    if host_root {
        for d in ["usr", "etc", "proc", "dev", "tmp", "home/box", "work", "run/plybox", "opt", "sys"] {
            std::fs::create_dir_all(rootfs.join(d)).map_err(|e| format!("bundle {d}: {e}"))?;
        }
    } else {
        std::fs::create_dir_all(&dir).map_err(|e| format!("bundle: {e}"))?;
    }
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    let mut mounts: Vec<Value> = vec![];
    let ro_bind = |mounts: &mut Vec<Value>, src: &str, dst: &str| {
        mounts.push(json!({ "destination": dst, "type": "bind", "source": src, "options": ["rbind", "ro"] }));
    };

    match pol.fs.rootfs.as_str() {
        "host" => {
            for (link, target) in [("lib", "usr/lib"), ("lib64", "usr/lib"), ("bin", "usr/bin"), ("sbin", "usr/bin")] {
                let p = rootfs.join(link);
                if p.symlink_metadata().is_err() {
                    std::os::unix::fs::symlink(target, &p).map_err(|e| format!("bundle {link}: {e}"))?;
                }
            }
            ro_bind(&mut mounts, "/usr", "/usr");
            for f in ["/etc/ssl", "/etc/ca-certificates", "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/ld.so.cache", "/etc/localtime"] {
                if Path::new(f).exists() {
                    if Path::new(f).is_file() {
                        let _ = std::fs::write(rootfs.join(&f[1..]), b"");
                    } else {
                        let _ = std::fs::create_dir_all(rootfs.join(&f[1..]));
                    }
                    ro_bind(&mut mounts, f, f);
                }
            }
        }
        _ => {
            // The image is the root (see above); only the account files are
            // swapped for the ones that know the box's uid.
            ro_bind(&mut mounts, &session.join("passwd").to_string_lossy(), "/etc/passwd");
            ro_bind(&mut mounts, &session.join("group").to_string_lossy(), "/etc/group");
        }
    }

    mounts.push(json!({ "destination": "/proc", "type": "proc", "source": "proc" }));
    mounts.push(json!({ "destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] }));
    mounts.push(json!({ "destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"] }));
    mounts.push(json!({ "destination": "/dev/shm", "type": "tmpfs", "source": "shm", "options": ["nosuid", "noexec", "nodev", "mode=1777"] }));
    mounts.push(json!({ "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777"] }));
    // $HOME: a tmpfs owned by the box's uid, so it is writable without caps.
    mounts.push(json!({ "destination": "/home/box", "type": "tmpfs", "source": "tmpfs",
                        "options": ["nosuid", "nodev", "mode=700", format!("uid={uid}"), format!("gid={gid}")] }));
    // The workspace: read-only unless the user chose bind mode.
    mounts.push(json!({ "destination": "/work", "type": "bind", "source": work,
                        "options": ["rbind", if workspace_writable { "rw" } else { "ro" }] }));
    ro_bind(&mut mounts, &session.to_string_lossy(), "/run/plybox");
    // The socket directory, writable: a unix-socket connect needs write
    // permission, and gVisor enforces that on read-only mounts.
    if host_root {
        let _ = std::fs::create_dir_all(rootfs.join("run/plybox/sock"));
    }
    mounts.push(json!({ "destination": "/run/plybox/sock", "type": "bind",
                        "source": session.join("sock"), "options": ["rbind", "rw"] }));
    if host_root {
        let _ = std::fs::write(rootfs.join("plybox"), b"");
    }
    ro_bind(&mut mounts, &me.to_string_lossy(), "/plybox");
    for pair in &pol.fs.ro_bind {
        let (h, b) = pair.split_once(':').ok_or_else(|| format!("ro_bind `{pair}`: expected HOST:BOX"))?;
        if host_root {
            let _ = std::fs::create_dir_all(rootfs.join(b.trim_start_matches('/')));
        }
        ro_bind(&mut mounts, h, b);
    }

    let env_list: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    // A host cgroup's pids.max does not bound guest processes (they are not
    // host tasks), so the process limit is also asked of the sandbox itself.
    let rlimits: Vec<Value> = match pol.limits.pids {
        Some(n) => vec![json!({ "type": "RLIMIT_NPROC", "hard": n, "soft": n })],
        None => vec![],
    };
    let spec = json!({
        "ociVersion": "1.1.0",
        "hostname": "plybox",
        "process": {
            "terminal": false,
            "user": { "uid": uid, "gid": gid },
            "args": inner_argv,
            "env": env_list,
            "cwd": "/work",
            "noNewPrivileges": true,
            "rlimits": rlimits,
            "capabilities": { "bounding": [], "effective": [], "inheritable": [], "permitted": [], "ambient": [] }
        },
        "root": { "path": rootfs, "readonly": !host_root },
        "mounts": mounts,
        "linux": {
            "namespaces": [
                { "type": "pid" }, { "type": "network" }, { "type": "ipc" }, { "type": "uts" }, { "type": "mount" }
            ]
        }
    });
    std::fs::write(dir.join("config.json"), serde_json::to_string_pretty(&spec).unwrap()).map_err(|e| format!("config.json: {e}"))?;
    Ok(Bundle { dir })
}

/// The runsc invocation. Only the rootfs is overlaid (in memory): an overlay
/// over every mount would copy the proxy socket up and break it.
pub fn command(runsc: &Path, session: &Path, bundle: &Bundle, id: &str) -> Command {
    // Which host unix-socket operations the sandbox may perform. Only the
    // proxy's socket directory is mounted, so this governs one socket.
    let host_uds = std::env::var("PLYBOX_GVISOR_HOST_UDS").unwrap_or_else(|_| "open".into());
    let mut c = Command::new(runsc);
    c.arg("--rootless")
        .arg("--network=none")
        .arg(format!("--host-uds={host_uds}"))
        .arg("--ignore-cgroups")
        .arg("--overlay2=root:memory")
        .arg("--root")
        .arg(session.join("runsc"))
        .arg("run")
        .arg("--bundle")
        .arg(&bundle.dir)
        .arg(format!("plybox-{id}"));
    c
}

pub fn find_runsc(configured: Option<&str>) -> Result<PathBuf, String> {
    if let Some(p) = configured {
        let p = PathBuf::from(p);
        return if p.is_file() { Ok(p) } else { Err(format!("runsc not found at {}", p.display())) };
    }
    if let Some(path) = std::env::var_os("PATH") {
        for d in path.to_string_lossy().split(':') {
            let p = Path::new(d).join("runsc");
            if p.is_file() {
                return Ok(p);
            }
        }
    }
    Err("gVisor's runsc not found — install it or pass --runsc PATH".into())
}
