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

use crate::gvisor;
use crate::image;
use crate::limits::{self, Enforcer, Limits};
use crate::policy::{Policy, RunOpts};
use crate::proxy::{Allow, Proxy};
use crate::record::Record;
use crate::secrets::{self, Secret, Tls};
use crate::workspace;

const PROXY_PORT: u16 = 3128;

pub fn run(pol: Policy, cmd: Vec<String>, opts: RunOpts) -> Result<i32, String> {
    let RunOpts { session, resume, quiet, learn } = opts;
    let mut pol = pol;
    pol.absolute_paths()?;
    if !["ns", "gvisor"].contains(&pol.isolation.as_str()) || !["overlay", "bind"].contains(&pol.fs.workspace_mode.as_str()) {
        return Err("expected isolation ns|gvisor and workspace_mode overlay|bind".into());
    }
    let work = pol.fs.workspace.clone();
    let (session, _guard, mut meta, resuming) = if let Some(resumed) = resume {
        if pol.isolation != "ns" || pol.fs.workspace_mode != "overlay" {
            return Err("resume must keep namespace isolation and the overlay workspace".into());
        }
        let original = std::fs::canonicalize(&resumed.meta.workspace).map_err(|e| format!("original workspace: {e}"))?;
        if work != original {
            return Err(format!("resume must use the original workspace: {}", original.display()));
        }
        if resumed.meta.git_head.is_some() && workspace::git_head(&work) != resumed.meta.git_head {
            eprintln!("plybox: warning: the workspace's git HEAD changed since this session began; saved changes will overlay the current host files");
        }
        if !quiet {
            eprintln!("plybox: resuming session {} (saved workspace files; fresh processes, home and tmp)", workspace::session_name(&resumed.dir));
        }
        (resumed.dir, resumed.guard, resumed.meta, true)
    } else {
        let session = session.map(Ok).unwrap_or_else(default_session)?;
        std::fs::create_dir_all(&session).map_err(|e| format!("session {}: {e}", session.display()))?;
        let session = std::fs::canonicalize(&session).map_err(|e| format!("session: {e}"))?;
        let guard = workspace::lock(&session)?;
        if ["meta.json", "record.jsonl", "upper", "work"].iter().any(|name| session.join(name).symlink_metadata().is_ok()) {
            return Err("session directory already contains a run; use --resume SESSION to continue it".into());
        }
        let meta = workspace::Meta {
            workspace: work.clone(), workspace_mode: pol.fs.workspace_mode.clone(), isolation: pol.isolation.clone(),
            started: workspace::now(), started_ns: now_ns(), git_head: workspace::git_head(&work),
            ..Default::default()
        };
        (session, guard, meta, false)
    };
    if session.starts_with(&work) {
        return Err("the session directory must be outside the workspace".into());
    }
    meta.isolation = pol.isolation.clone();
    meta.cmd = cmd.clone();
    meta.policy = Some(pol.for_resume());
    meta.runs = if resuming { meta.runs.max(1).saturating_add(1) } else { 1 };
    meta.last_started = workspace::now();
    meta.last_started_ns = now_ns();
    meta.ended = None;
    meta.exit_code = None;
    workspace::write_meta(&session, &meta)?;
    let record = Arc::new(Record::open(&session.join("record.jsonl")).map_err(|e| format!("record: {e}"))?);
    let result = run_box(pol, cmd, &session, quiet, learn, &mut meta, &record, resuming);
    // The box is gone: its certificates, socket and bundle are of no further
    // use (every run makes fresh ones). The workspace copy and record stay.
    workspace::remove_run_files(&session);
    meta.ended = Some(workspace::now());
    meta.exit_code = result.as_ref().ok().copied();
    if result.is_err() {
        record.event("error", json!({ "run": meta.runs, "phase": "run" }));
    }
    workspace::write_meta(&session, &meta)?;
    result
}

fn now_ns() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

fn run_box(
    mut pol: Policy, cmd: Vec<String>, session: &Path, quiet: bool, learn: Option<Option<PathBuf>>,
    meta: &mut workspace::Meta, record: &Arc<Record>, resuming: bool,
) -> Result<i32, String> {
    let learning = learn.is_some();
    let gvisor_tier = pol.isolation == "gvisor";
    let engine: PathBuf = if gvisor_tier {
        gvisor::find_runsc(pol.runsc.as_deref())?
    } else {
        which("bwrap").ok_or("bubblewrap (bwrap) not found — plybox uses it for namespaces")?
    };
    let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    // An image is the box's root filesystem; pulled once, then cached.
    let image = match pol.image.clone() {
        Some(r) => {
            let img = image::ensure(&r, false, quiet)?;
            pol.fs.rootfs = img.rootfs.to_string_lossy().into_owned();
            Some(img)
        }
        None => None,
    };
    let own_root = pol.fs.rootfs != "host";
    if own_root {
        require_static(&me)?;
    }
    let work = pol.workspace_abs()?;
    let overlay = pol.fs.workspace_mode == "overlay";
    if overlay && !gvisor_tier {
        std::fs::create_dir_all(session.join("upper")).map_err(|e| format!("upper: {e}"))?;
        std::fs::create_dir_all(session.join("work")).map_err(|e| format!("overlay work: {e}"))?;
    }
    if overlay && gvisor_tier && !quiet {
        eprintln!("plybox: gVisor tier: the workspace is read-only; writes go to $HOME and /tmp and vanish at exit (use --workspace-mode bind to write to the directory)");
    }
    meta.image = image.as_ref().map(|i| json!({ "ref": i.meta.reference, "digest": i.meta.digest }));
    workspace::write_meta(session, meta)?;

    // Limits: a cgroup of our own if the kernel lets us, else systemd-run.
    let lim = Limits {
        mem_bytes: pol.limits.mem.as_deref().map(limits::parse_size).transpose()?,
        pids: pol.limits.pids,
        cpu: pol.limits.cpu,
    };
    let session_id = session.file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "box".into());
    let enforcer = Enforcer::prepare(lim, &session_id);

    // The proxy: bound before anything else so the box can connect at once.
    // The socket lives in its own small directory, which is the only part of
    // the session the box may write to: connecting to a unix socket needs
    // write permission on it, and gVisor refuses that on a read-only mount.
    std::fs::create_dir_all(session.join("sock")).map_err(|e| format!("sock dir: {e}"))?;
    // Permissions, host side: the sessions base is 0700, so no other user on
    // the host reaches any session. Inside the gVisor tier our files show
    // up as root's while the workload runs as our uid, so the session dir is
    // 0711 (traverse, no listing) and the socket is world-connectable — the
    // 0700 base is what actually guards them.
    {
        use std::os::unix::fs::PermissionsExt;
        let base = workspace::sessions_base();
        if session.starts_with(&base) {
            let _ = std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o711));
        let _ = std::fs::set_permissions(session.join("sock"), std::fs::Permissions::from_mode(0o711));
    }
    let sock = session.join("sock/proxy.sock");
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).map_err(|e| format!("proxy socket {}: {e}", sock.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o777));
    }
    let allow = Allow::parse(&pol.net.allow)?;

    // Secrets stay here. If there are any, a session CA is made so the
    // proxy can terminate TLS for their hosts, and the box is told to trust it.
    let secret_list: Vec<Secret> = secrets::parse(&pol.secret_specs()?)?;
    let tls = if secret_list.is_empty() { None } else { Some(Arc::new(Tls::new(&pol.net.trust_ca)?)) };
    if let Some(t) = &tls {
        t.write_trust_files(&session, &pol.net.trust_ca)?;
    }
    let maps = parse_maps(&pol.net.map)?;

    let proxy = Proxy::new(allow, Arc::clone(&record), secrets::by_host(&secret_list), tls.clone(), maps, learning);
    let acceptor = Arc::clone(&proxy);
    std::thread::spawn(move || acceptor.serve(listener));
    if learning {
        eprintln!("plybox: LEARN MODE — every public destination is allowed and recorded; the box is NOT contained on the network for this run");
    }

    record.event(
        "start",
        json!({
            "cmd": cmd, "isolation": pol.isolation, "rootfs": pol.fs.rootfs, "workspace": work,
            "image": image.as_ref().map(|i| json!({ "ref": i.meta.reference, "digest": i.meta.digest })),
            "workspace_mode": if gvisor_tier && overlay { "read-only (gvisor tier)" } else { pol.fs.workspace_mode.as_str() },
            "allow": pol.net.allow,
            "secrets": secret_list.iter().map(|s| format!("{}@{}", s.name, s.host)).collect::<Vec<_>>(),
            "limits": { "mem": pol.limits.mem, "pids": pol.limits.pids, "cpu": pol.limits.cpu, "via": enforcer.describe() },
            "session": session, "kernel": uname_release(), "resumed": resuming, "run": meta.runs,
        }),
    );
    if !quiet {
        eprintln!(
            "plybox: box up ({}{}) — network: {}; secrets: {}; workspace {} at /work ({}); limits: {}; session {}",
            pol.isolation,
            image.as_ref().map(|i| format!(", image {}", i.meta.reference)).unwrap_or_default(),
            if pol.net.allow.is_empty() { "none".to_string() } else { pol.net.allow.join(", ") },
            secret_list.len(),
            work.display(),
            pol.fs.workspace_mode,
            enforcer.describe(),
            workspace::session_name(&session)
        );
    }
    if !enforcer.limits.is_empty() && matches!(enforcer.mode, limits::Mode::None) {
        eprintln!("plybox: warning: limits requested but {}", enforcer.describe());
    }

    let image_env: &[String] = image.as_ref().map(|i| i.meta.env.as_slice()).unwrap_or(&[]);
    let env = box_env(&pol, &secret_list, tls.is_some(), image_env);
    if own_root {
        write_accounts(&pol.fs.rootfs, &session)?;
    }
    let mut inner_argv: Vec<String> = ["/plybox", "__inner", "--proxy-sock", "/run/plybox/sock/proxy.sock"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if own_root {
        // The whole root is an image: Landlock may read all of it, but write
        // only /work, /tmp, $HOME and /dev, as in host mode.
        inner_argv.push("--ro-root".into());
    }
    inner_argv.push("--".into());
    inner_argv.extend(cmd.iter().cloned());
    let status = if gvisor_tier {
        let bundle = gvisor::write_bundle(&pol, &work, &session, &me, &inner_argv, &env, !overlay)?;
        let mut c = gvisor::command(&engine, &session, &bundle, &session_id);
        enforcer.wrap(&mut c).status().map_err(|e| format!("runsc: {e}"))?
    } else {
        let argv = bwrap_argv(&pol, &work, &session, &env, &inner_argv, overlay)?;
        enforcer.command(&engine, &argv).status().map_err(|e| format!("bwrap: {e}"))?
    };
    let code = status.code().unwrap_or(128 + status_signal(&status));
    enforcer.finish();
    // The box is gone, so its ends of any tunnels are closed; give the
    // tunnel threads a moment to write their record lines.
    proxy.drain(std::time::Duration::from_secs(2));
    let changed = if overlay && !gvisor_tier {
        workspace::Session { dir: session.to_path_buf(), workspace: work.clone() }.changes().map(|c| c.len()).unwrap_or(0)
    } else {
        0
    };
    record.event("exit", json!({ "code": code, "workspace_changes": changed, "run": meta.runs }));

    // Learn mode: write the policy the run would have needed.
    if let Some(out) = learn {
        let learned = proxy.learned();
        let mut learned_pol = pol.clone();
        let mut allow: Vec<String> = learned_pol.net.allow.iter().cloned().chain(learned.iter().cloned()).collect();
        allow.sort();
        allow.dedup();
        learned_pol.net.allow = allow;
        let path = out.unwrap_or_else(|| session.join("learned.toml"));
        let text = format!(
            "# plybox policy learned on {} from: {}\n# {} destination(s) were reached that the policy did not list; review before trusting.\n\n{}",
            uname_release(),
            cmd.join(" "),
            learned.len(),
            learned_pol.to_toml()
        );
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        record.event("learned", json!({ "destinations": learned, "policy": path }));
        eprintln!(
            "plybox: learned {} new destination(s){}{} — policy written to {}; review it, then run with --policy {}",
            learned.len(),
            if learned.is_empty() { "" } else { ": " },
            learned.join(", "),
            path.display(),
            path.display()
        );
    }
    if !quiet && overlay && !gvisor_tier {
        eprintln!(
            "plybox: box exited {code}; {changed} workspace change(s) held in session {0} — `plybox diff {0}` / `plybox apply {0}`",
            workspace::session_name(&session)
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

/// A rootfs of its own runs `/plybox __inner` from inside it, so the binary
/// must not need the image's libc. A dynamically linked plybox names its
/// loader (`ld-linux…`/`ld-musl…`) in its first page; a static one does not.
fn require_static(me: &Path) -> Result<(), String> {
    let mut head = vec![0u8; 8192];
    let n = std::fs::File::open(me).and_then(|mut f| std::io::Read::read(&mut f, &mut head)).unwrap_or(0);
    let head = &head[..n];
    let dynamic = head.windows(7).any(|w| w == b"ld-linu") || head.windows(7).any(|w| w == b"ld-musl");
    if dynamic {
        return Err(format!(
            "{} is dynamically linked, and a box with its own root filesystem (--image/--rootfs) runs plybox inside that image — \
             use the static build: cargo build --release --target x86_64-unknown-linux-musl",
            me.display()
        ));
    }
    Ok(())
}

/// The image's account files plus one entry for the box's uid, so tools that
/// look the user up (git, npm, `os.userInfo()`, `whoami`) find one.
fn write_accounts(rootfs: &str, session: &Path) -> Result<(), String> {
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let root = Path::new(rootfs);
    let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap_or_default();
    let mut passwd = read("etc/passwd");
    if !passwd.lines().any(|l| l.split(':').nth(2) == Some(&uid.to_string())) {
        if !passwd.is_empty() && !passwd.ends_with('\n') {
            passwd.push('\n');
        }
        passwd.push_str(&format!("box:x:{uid}:{gid}:plybox:/home/box:/bin/sh\n"));
    }
    let mut group = read("etc/group");
    if !group.lines().any(|l| l.split(':').nth(2) == Some(&gid.to_string())) {
        if !group.is_empty() && !group.ends_with('\n') {
            group.push('\n');
        }
        group.push_str(&format!("box:x:{gid}:\n"));
    }
    std::fs::write(session.join("passwd"), passwd).map_err(|e| format!("passwd: {e}"))?;
    std::fs::write(session.join("group"), group).map_err(|e| format!("group: {e}"))?;
    Ok(())
}

/// Image variables the box keeps from the image's config: everything except
/// the ones plybox owns (identity and the proxy).
const PLYBOX_OWNED_ENV: &[&str] = &[
    "HOME", "USER", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy",
    "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "NODE_USE_ENV_PROXY",
];

/// The environment inside the box: tight defaults, the image's own variables
/// (PATH and friends), the policy's values, the session CA (when TLS is
/// terminated) and, last, the secret placeholders.
fn box_env(pol: &Policy, secret_list: &[Secret], trust_session_ca: bool, image_env: &[String]) -> Vec<(String, String)> {
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
    let set = |env: &mut Vec<(String, String)>, k: &str, v: &str| {
        env.retain(|(ek, _)| ek != k);
        env.push((k.to_string(), v.to_string()));
    };
    for pair in image_env {
        if let Some((k, v)) = pair.split_once('=') {
            if !PLYBOX_OWNED_ENV.contains(&k) {
                set(&mut env, k, v);
            }
        }
    }
    for (k, v) in &pol.env {
        set(&mut env, k, v);
    }
    if trust_session_ca {
        for k in ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO"] {
            set(&mut env, k, "/run/plybox/bundle.pem");
        }
        set(&mut env, "NODE_EXTRA_CA_CERTS", "/run/plybox/ca.pem");
    }
    // Placeholders last: a secret's name always holds the placeholder, never
    // a value that slipped in through --env.
    for s in secret_list {
        set(&mut env, &s.name, &s.placeholder);
    }
    env
}

fn bwrap_argv(
    pol: &Policy,
    work: &Path,
    session: &Path,
    env: &[(String, String)],
    inner_argv: &[String],
    overlay: bool,
) -> Result<Vec<String>, String> {
    let me = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
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
            // The image is the read-only lower layer of an in-memory root:
            // mount points can be created on top, the image stays untouched,
            // and many boxes share one cached copy.
            let dir = std::fs::canonicalize(dir).map_err(|e| format!("rootfs {dir}: {e}"))?;
            push(&["--overlay-src", &dir.to_string_lossy(), "--tmp-overlay", "/"]);
            push(&["--ro-bind", &session.join("passwd").to_string_lossy(), "/etc/passwd"]);
            push(&["--ro-bind", &session.join("group").to_string_lossy(), "/etc/group"]);
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
    // Bubblewrap keeps its own POSIX lock until the sandbox is gone, even
    // if this supervisor is terminated while a systemd scope survives it.
    push(&["--lock-file", "/run/plybox/lock"]);
    push(&["--bind", &session.join("sock").to_string_lossy(), "/run/plybox/sock"]);
    push(&["--ro-bind", &me.to_string_lossy(), "/plybox"]);
    let _ = pol; // rootfs/ro_bind consumed above
    for pair in &pol.fs.ro_bind {
        let (h, b) = pair.split_once(':').ok_or_else(|| format!("ro_bind `{pair}`: expected HOST:BOX"))?;
        push(&["--ro-bind", h, b]);
    }

    push(&["--chdir", "/work", "--cap-drop", "ALL", "--disable-userns", "--clearenv"]);
    for (k, v) in env {
        push(&["--setenv", k, v]);
    }
    push(&["--"]);
    a.extend(inner_argv.iter().cloned());
    Ok(a)
}

/// Sessions persist (they hold the record and the workspace's upper layer),
/// so they live under the state directory, not the runtime one.
fn default_session() -> Result<PathBuf, String> {
    workspace::new_session_dir()
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
