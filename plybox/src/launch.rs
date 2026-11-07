//! The supervisor side of `plybox run`.
//!
//! Namespaces and mounts are delegated to bubblewrap, exactly as the lab's
//! box did (`lab/net/box.sh`): bwrap is mature, audited, setuid-free, and
//! the same engine srt and Greywall use. What plybox adds around it is the
//! part none of them have together — the hostname-deciding proxy outside the
//! box, the in-box forwarder, the seccomp allowlist, Landlock, and the
//! record. (Later slices: secrets at the proxy, the copy-on-write workspace,
//! cgroup limits, the gVisor tier.)
//!
//! The box runs `plybox __inner`, which bridges 127.0.0.1:3128 to the proxy
//! socket and execs the workload under the kernel-surface layer.

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;

use crate::limits::{self, Enforcer, Limits};
use crate::policy::Policy;
use crate::proxy::{Allow, Proxy};
use crate::record::Record;
use crate::secrets::{self, Secret, Tls};
use crate::workspace;

const PROXY_PORT: u16 = 3128;

pub fn run(pol: Policy, cmd: Vec<String>, session: Option<PathBuf>, quiet: bool) -> Result<i32, String> {
    let bwrap = which("bwrap").ok_or("bubblewrap (bwrap) not found — plybox uses it for namespaces")?;
    let work = pol.workspace_abs()?;
    let session = session.map(Ok).unwrap_or_else(default_session)?;
    std::fs::create_dir_all(&session).map_err(|e| format!("session {}: {e}", session.display()))?;
    let session = std::fs::canonicalize(&session).map_err(|e| format!("session {}: {e}", session.display()))?;
    let record = Arc::new(Record::open(&session.join("record.jsonl")).map_err(|e| format!("record: {e}"))?);
    let overlay = pol.fs.workspace_mode == "overlay";
    if overlay {
        std::fs::create_dir_all(session.join("upper")).map_err(|e| format!("upper: {e}"))?;
        std::fs::create_dir_all(session.join("work")).map_err(|e| format!("overlay work: {e}"))?;
    }
    std::fs::write(
        session.join("meta.json"),
        serde_json::to_string_pretty(&json!({
            "workspace": work, "workspace_mode": pol.fs.workspace_mode, "cmd": cmd,
            "started": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        }))
        .unwrap(),
    )
    .map_err(|e| format!("meta.json: {e}"))?;

    // Limits: a cgroup of our own if the kernel lets us, else systemd-run.
    let lim = Limits {
        mem_bytes: pol.limits.mem.as_deref().map(limits::parse_size).transpose()?,
        pids: pol.limits.pids,
        cpu: pol.limits.cpu,
    };
    let session_id = session.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "box".into());
    let enforcer = Enforcer::prepare(lim, &session_id);

    // The proxy: bound before anything else so the box can connect at once.
    let sock = session.join("proxy.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).map_err(|e| format!("proxy socket {}: {e}", sock.display()))?;
    let allow = Allow::parse(&pol.net.allow)?;

    // Secrets stay here. If there are any, a session CA is made so the
    // proxy can terminate TLS for their hosts, and the box is told to trust it.
    let secret_list: Vec<Secret> = secrets::parse(&pol.secret_specs())?;
    let tls = if secret_list.is_empty() { None } else { Some(Arc::new(Tls::new(&pol.net.trust_ca)?)) };
    if let Some(t) = &tls {
        t.write_trust_files(&session, &pol.net.trust_ca)?;
    }
    let maps = parse_maps(&pol.net.map)?;

    let proxy = Proxy::new(allow, Arc::clone(&record), secrets::by_host(&secret_list), tls.clone(), maps);
    let acceptor = Arc::clone(&proxy);
    std::thread::spawn(move || acceptor.serve(listener));

    record.event(
        "start",
        json!({
            "cmd": cmd, "rootfs": pol.fs.rootfs, "workspace": work, "workspace_mode": pol.fs.workspace_mode,
            "allow": pol.net.allow,
            "secrets": secret_list.iter().map(|s| format!("{}@{}", s.name, s.host)).collect::<Vec<_>>(),
            "limits": { "mem": pol.limits.mem, "pids": pol.limits.pids, "cpu": pol.limits.cpu, "via": enforcer.describe() },
            "session": session, "kernel": uname_release(),
        }),
    );
    if !quiet {
        eprintln!(
            "plybox: box up — network: {}; secrets: {}; workspace {} at /work ({}); limits: {}; record {}",
            if pol.net.allow.is_empty() { "none".to_string() } else { pol.net.allow.join(", ") },
            secret_list.len(),
            work.display(),
            pol.fs.workspace_mode,
            enforcer.describe(),
            session.join("record.jsonl").display()
        );
    }
    if !enforcer.limits.is_empty() && matches!(enforcer.mode, limits::Mode::None) {
        eprintln!("plybox: warning: limits requested but {}", enforcer.describe());
    }

    let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let argv = bwrap_argv(&pol, &work, &session, &me, &cmd, &secret_list, tls.is_some(), overlay)?;
    let status = enforcer.command(&bwrap, &argv).status().map_err(|e| format!("bwrap: {e}"))?;
    let code = status.code().unwrap_or(128 + status_signal(&status));
    enforcer.finish();
    // The box is gone, so its ends of any tunnels are closed; give the
    // tunnel threads a moment to write their record lines.
    proxy.drain(std::time::Duration::from_secs(2));
    let changed = if overlay {
        workspace::Session { dir: session.clone(), workspace: work.clone() }.changes().map(|c| c.len()).unwrap_or(0)
    } else {
        0
    };
    record.event("exit", json!({ "code": code, "workspace_changes": changed }));
    if !quiet && overlay {
        eprintln!(
            "plybox: box exited {code}; {changed} workspace change(s) held in the session — `plybox diff {0}` / `plybox apply {0}`",
            session.display()
        );
    }
    Ok(code)
}

fn parse_maps(entries: &[String]) -> Result<std::collections::HashMap<String, std::net::SocketAddr>, String> {
    let mut m = std::collections::HashMap::new();
    for e in entries {
        let (host, addr) = e.split_once('=').ok_or_else(|| format!("map `{e}`: expected host=ip:port"))?;
        let addr: std::net::SocketAddr = addr.parse().map_err(|_| format!("map `{e}`: bad ip:port"))?;
        m.insert(host.trim().to_ascii_lowercase(), addr);
    }
    Ok(m)
}

fn bwrap_argv(
    pol: &Policy,
    work: &Path,
    session: &Path,
    me: &Path,
    cmd: &[String],
    secret_list: &[Secret],
    trust_session_ca: bool,
    overlay: bool,
) -> Result<Vec<String>, String> {
    let mut a: Vec<String> = vec![];
    let mut push = |xs: &[&str]| a.extend(xs.iter().map(|s| s.to_string()));

    push(&["--unshare-all", "--unshare-user", "--die-with-parent", "--new-session"]);

    match pol.fs.rootfs.as_str() {
        "host" => push(&[
            "--ro-bind", "/usr", "/usr",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin",
            "--ro-bind-try", "/etc/ssl", "/etc/ssl",
            "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
            "--ro-bind-try", "/etc/passwd", "/etc/passwd",
            "--ro-bind-try", "/etc/group", "/etc/group",
            "--ro-bind-try", "/etc/hosts", "/etc/hosts",
            "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
            "--ro-bind-try", "/etc/localtime", "/etc/localtime",
        ]),
        dir => {
            let dir = std::fs::canonicalize(dir).map_err(|e| format!("rootfs {dir}: {e}"))?;
            push(&["--ro-bind", &dir.to_string_lossy(), "/"]);
        }
    }

    push(&["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home", "--dir", "/home/box"]);
    if overlay {
        // The real directory is the read-only lower layer; writes land in
        // the session's upper layer, for `plybox diff` / `apply`.
        let upper = session.join("upper");
        let workdir = session.join("work");
        push(&["--overlay-src", &work.to_string_lossy(), "--overlay", &upper.to_string_lossy(), &workdir.to_string_lossy(), "/work"]);
    } else {
        push(&["--bind", &work.to_string_lossy(), "/work"]);
    }
    push(&["--ro-bind", &session.to_string_lossy(), "/run/plybox"]);
    push(&["--ro-bind", &me.to_string_lossy(), "/plybox"]);
    for pair in &pol.fs.ro_bind {
        let (h, b) = pair.split_once(':').ok_or_else(|| format!("ro_bind `{pair}`: expected HOST:BOX"))?;
        push(&["--ro-bind", h, b]);
    }

    push(&["--chdir", "/work", "--cap-drop", "ALL", "--disable-userns", "--clearenv"]);

    // Environment: tight defaults, then the policy's values on top.
    let proxy_url = format!("http://127.0.0.1:{PROXY_PORT}");
    let mut env: Vec<(String, String)> = vec![
        ("HOME".into(), "/home/box".into()),
        ("USER".into(), "box".into()),
        ("TERM".into(), "dumb".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
        ("HTTPS_PROXY".into(), proxy_url.clone()),
        ("HTTP_PROXY".into(), proxy_url.clone()),
        ("https_proxy".into(), proxy_url.clone()),
        ("http_proxy".into(), proxy_url),
        ("NO_PROXY".into(), "localhost,127.0.0.1".into()),
        ("no_proxy".into(), "localhost,127.0.0.1".into()),
        ("NODE_USE_ENV_PROXY".into(), "1".into()),
    ];
    for (k, v) in &pol.env {
        env.retain(|(ek, _)| ek != k);
        env.push((k.clone(), v.clone()));
    }
    // The session CA, so TLS the proxy terminates is trusted by curl, git,
    // python and node inside.
    if trust_session_ca {
        for k in ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO"] {
            env.retain(|(ek, _)| ek != k);
            env.push((k.into(), "/run/plybox/bundle.pem".into()));
        }
        env.retain(|(ek, _)| ek != "NODE_EXTRA_CA_CERTS");
        env.push(("NODE_EXTRA_CA_CERTS".into(), "/run/plybox/ca.pem".into()));
    }
    // Placeholders last: a secret's name always holds the placeholder, never
    // a value that slipped in through --env.
    for s in secret_list {
        env.retain(|(ek, _)| ek != &s.name);
        env.push((s.name.clone(), s.placeholder.clone()));
    }
    for (k, v) in &env {
        push(&["--setenv", k, v]);
    }

    push(&["--", "/plybox", "__inner", "--proxy-sock", "/run/plybox/proxy.sock", "--"]);
    a.extend(cmd.iter().cloned());
    Ok(a)
}

/// Sessions persist (they hold the record and the workspace's upper layer),
/// so they live under the state directory, not the runtime one.
fn default_session() -> Result<PathBuf, String> {
    let id = format!(
        "{}-{}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        std::process::id()
    );
    Ok(workspace::sessions_base().join(id))
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?
        .to_string_lossy()
        .split(':')
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

fn uname_release() -> String {
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = u.release.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn status_signal(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().unwrap_or(0)
}
