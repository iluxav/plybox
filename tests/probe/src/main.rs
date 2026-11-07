//! plybox lab probe.
//!
//! Each probe attempts ONE step an attacker inside a sandbox would take and
//! reports whether it worked. Output is one TSV line per probe:
//!
//!     id <TAB> verdict <TAB> detail
//!
//! ALLOWED = the step worked (bad). BLOCKED = it failed (good).
//! NA      = this run cannot tell (precondition missing).
//!
//! Rules for every probe:
//!   * harmless: no exploit code, only "is this door open?";
//!   * never prints secret contents, only names and counts;
//!   * removes whatever it creates;
//!   * runs in its own forked child, so one probe cannot change the next.
//!
//! `probe --list` prints `id <TAB> why it matters`.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[derive(Clone, Copy)]
enum V {
    Allowed,
    Blocked,
    Na,
}
use V::*;
type R = (V, String);

struct Probe {
    id: &'static str,
    why: &'static str,
    run: fn() -> R,
}

const PROBES: &[Probe] = &[
    // --- kernel attack surface -------------------------------------------
    Probe { id: "k.userns", why: "Nested user namespace: unlocks kernel code that normally needs privileges", run: k_userns },
    Probe { id: "k.userns.net", why: "...then admin rights over a private network stack (nf_tables bug class, CVE-2024-1086)", run: k_userns_net },
    Probe { id: "k.userns.mount", why: "...then mounting filesystems (CVE-2022-0185 class)", run: k_userns_mount },
    Probe { id: "k.io_uring", why: "io_uring: Google disabled it after kernelCTF exploits", run: k_io_uring },
    Probe { id: "k.bpf", why: "bpf(): verifier bugs have given kernel code execution", run: k_bpf },
    Probe { id: "k.userfaultfd", why: "userfaultfd: makes kernel race bugs reliable to exploit", run: k_userfaultfd },
    Probe { id: "k.perf", why: "perf_event_open: long history of kernel bugs", run: k_perf },
    Probe { id: "k.sock.nfnetlink", why: "Channel to netfilter, where CVE-2024-1086 lived", run: k_sock_nfnetlink },
    Probe { id: "k.sock.packet", why: "Raw packets: spoof traffic and bypass egress rules", run: k_sock_packet },
    Probe { id: "k.sock.alg", why: "Kernel crypto sockets: rarely needed, repeatedly buggy", run: k_sock_alg },
    Probe { id: "k.sock.vsock", why: "VM sockets: a channel to the hypervisor or host", run: k_sock_vsock },
    Probe { id: "k.ptrace", why: "ptrace: take over other processes in the box", run: k_ptrace },
    Probe { id: "k.keyctl", why: "Kernel keyrings are not per-box; Docker blocks this", run: k_keyctl },
    Probe { id: "k.mount", why: "mount() directly, without a namespace trick", run: k_mount },
    Probe { id: "k.mknod", why: "Create a disk device node (ply finding #1)", run: k_mknod },
    Probe { id: "k.kallsyms", why: "Kernel addresses: defeats KASLR for exploits", run: k_kallsyms },
    Probe { id: "k.kmsg", why: "Kernel log: leaks addresses and host activity", run: k_kmsg },
    // --- the process itself ----------------------------------------------
    Probe { id: "p.nnp", why: "no_new_privs off: setuid binaries can still raise privileges", run: p_nnp },
    Probe { id: "p.seccomp", why: "No syscall filter at all", run: p_seccomp },
    Probe { id: "p.caps", why: "Runs as root or with capabilities", run: p_caps },
    Probe { id: "p.hostpid", why: "Sees host processes and their environment (tokens live there)", run: p_hostpid },
    Probe { id: "p.fds", why: "Inherited file descriptors (Leaky Vessels, CVE-2024-21626)", run: p_fds },
    // --- files, secrets, host IPC ----------------------------------------
    Probe { id: "f.secrets", why: "Reads credential files in the host home (what npm worms harvest)", run: f_secrets },
    Probe { id: "f.secrets.proc", why: "Same files through /proc/self/root (the path trick Ona reported)", run: f_secrets_proc },
    Probe { id: "f.write.home", why: "Writes into the host home: persistence via shell startup files", run: f_write_home },
    Probe { id: "f.write.outside", why: "Writes outside the workspace", run: f_write_outside },
    Probe { id: "f.inject.githook", why: "Plants a git hook that the host runs later", run: f_inject_githook },
    Probe { id: "f.inject.agentcfg", why: "Plants agent settings that run outside the box (CVE-2026-25725 class)", run: f_inject_agentcfg },
    Probe { id: "f.ipc.dbus", why: "Session bus: systemd --user will start processes outside the box", run: f_ipc_dbus },
    Probe { id: "f.ipc.docker", why: "Docker socket: root on the host", run: f_ipc_docker },
    Probe { id: "f.ipc.abstract", why: "Abstract unix sockets of host services", run: f_ipc_abstract },
    Probe { id: "f.ipc.agent", why: "ssh-agent: use the host's SSH keys", run: f_ipc_agent },
    // --- network ----------------------------------------------------------
    Probe { id: "n.tcp.public", why: "Direct connection to any internet address (exfiltration)", run: n_tcp_public },
    Probe { id: "n.tcp.v6", why: "Same over IPv6, which filters often forget", run: n_tcp_v6 },
    Probe { id: "n.dns.direct", why: "DNS to a resolver the attacker picks (DNS tunnelling)", run: n_dns_direct },
    Probe { id: "n.dns.system", why: "Arbitrary names through the system resolver (data inside DNS names)", run: n_dns_system },
    Probe { id: "n.host.lo", why: "Services on the host's loopback", run: n_host_lo },
    Probe { id: "n.host.lan", why: "Services on the host's LAN address", run: n_host_lan },
    Probe { id: "n.metadata", why: "Cloud metadata service (instance credentials)", run: n_metadata },
    // --- resources --------------------------------------------------------
    // Active tests: they create processes and allocate memory until a limit
    // bites, so they do not depend on seeing the cgroup tree from inside.
    // Both are capped (PROBE_FORK_CAP, PROBE_MEM_MB) so they stay harmless.
    Probe { id: "q.pids", why: "No process limit: a fork bomb takes the host down", run: q_pids },
    Probe { id: "q.mem", why: "No memory limit: one agent can starve the host", run: q_mem },
];

fn main() {
    let list = std::env::args().nth(1).as_deref() == Some("--list");
    for p in PROBES {
        if list {
            println!("{}\t{}", p.id, p.why);
        } else {
            run(p);
        }
    }
}

/// Run one probe in a forked child and print its line. A probe that is
/// killed (seccomp, timeout) still produces a line.
fn run(p: &Probe) {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        println!("{}\tNA\tpipe: {}", p.id, os_err());
        return;
    }
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("{}\tNA\tfork: {}", p.id, os_err());
        return;
    }
    if pid == 0 {
        unsafe {
            libc::close(fds[0]);
            libc::alarm(15);
        }
        let (v, detail) = (p.run)();
        let verdict = match v {
            Allowed => "ALLOWED",
            Blocked => "BLOCKED",
            Na => "NA",
        };
        let line = format!("{verdict}\t{}", detail.replace(['\t', '\n'], " "));
        unsafe {
            libc::write(fds[1], line.as_ptr() as *const libc::c_void, line.len());
            libc::_exit(0);
        }
    }
    unsafe { libc::close(fds[1]) };
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = unsafe { libc::read(fds[0], chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
        if n <= 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
    unsafe { libc::close(fds[0]) };
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let line = if !buf.is_empty() {
        String::from_utf8_lossy(&buf).into_owned()
    } else if libc::WIFSIGNALED(status) {
        match libc::WTERMSIG(status) {
            libc::SIGALRM => "NA\ttimed out".to_string(),
            libc::SIGSYS => "BLOCKED\tkilled by the syscall filter (SIGSYS)".to_string(),
            libc::SIGKILL => "BLOCKED\tkilled by SIGKILL (the OOM killer, or a hard limit)".to_string(),
            sig => format!("BLOCKED\tkilled by signal {sig}"),
        }
    } else {
        "NA\tno result".to_string()
    };
    println!("{}\t{line}", p.id);
}

// ---------------------------------------------------------------- helpers

fn os_err() -> String {
    std::io::Error::last_os_error().to_string()
}

fn env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}

/// A scratch path in the workspace (the one place every config can write).
fn scratch(name: &str) -> String {
    format!(".probe-{}-{name}", std::process::id())
}

fn status_field(key: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix(key))
        .map(|v| v.trim().to_string())
}

fn open_or_block(fd: libc::c_long, what: &str) -> R {
    if fd >= 0 {
        (Allowed, format!("{what}: ok"))
    } else {
        (Blocked, os_err())
    }
}

fn sock(domain: i32, ty: i32, proto: i32, what: &str) -> R {
    let fd = unsafe { libc::socket(domain, ty, proto) };
    open_or_block(fd as libc::c_long, what)
}

enum Reach {
    Replied(usize),
    Silent(String),
    NoConnect(std::io::Error),
}

/// Connect, send a harmless request, and wait for ANY bytes back. A bare
/// connect() is not evidence: inside a TUN-based sandbox the TUN device
/// completes the TCP handshake before any policy runs, so connect succeeds
/// and only the data path is refused. A reply proves the peer was reached.
fn reach(addr: &str) -> Reach {
    use std::io::Write;
    let a: SocketAddr = match addr.parse() {
        Ok(a) => a,
        Err(_) => return Reach::NoConnect(std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad address")),
    };
    let mut s = match TcpStream::connect_timeout(&a, Duration::from_secs(3)) {
        Ok(s) => s,
        Err(e) => return Reach::NoConnect(e),
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.write_all(b"GET / HTTP/1.0\r\nHost: plybox-probe\r\n\r\n");
    let mut buf = [0u8; 64];
    match s.read(&mut buf) {
        Ok(n) if n > 0 => Reach::Replied(n),
        Ok(_) => Reach::Silent("peer closed without a reply".into()),
        Err(e) => Reach::Silent(format!("no reply: {e}")),
    }
}

fn tcp_probe(addr: &str, what: &str) -> R {
    match reach(addr) {
        Reach::Replied(n) => (Allowed, format!("reached {what} ({addr}): {n} bytes back")),
        Reach::Silent(why) => (Blocked, format!("{addr}: connected but {why} (a proxy sink refusing the data path)")),
        Reach::NoConnect(e) => (Blocked, format!("{addr}: {e}")),
    }
}

/// Send one A query; returns (bytes, rcode) of whatever comes back.
fn dns_query(server: SocketAddr, name: &str) -> std::io::Result<(usize, u8)> {
    let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let s = UdpSocket::bind(bind)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut q = vec![0x70, 0x62, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    s.send_to(&q, server)?;
    let mut buf = [0u8; 512];
    let (n, _) = s.recv_from(&mut buf)?;
    Ok((n, buf[3] & 0x0f))
}

fn unix_connect(path: &str, what: &str) -> R {
    match UnixStream::connect(path) {
        Ok(_) => (Allowed, format!("connected to {what} ({path})")),
        Err(e) => (Blocked, format!("{path}: {e}")),
    }
}

/// Tightest limit in this process's cgroup chain.
/// None = cgroupfs not visible; Some(None) = no limit; Some(Some(n)) = limit.
fn cgroup_limit(file: &str) -> Option<Option<u64>> {
    let cg = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cg.lines().find_map(|l| l.strip_prefix("0::"))?.trim().to_string();
    let root = std::path::Path::new("/sys/fs/cgroup");
    let mut path = std::path::PathBuf::from(format!("/sys/fs/cgroup{rel}"));
    let (mut seen, mut min) = (false, None::<u64>);
    loop {
        if let Ok(v) = std::fs::read_to_string(path.join(file)) {
            seen = true;
            if let Ok(n) = v.trim().parse::<u64>() {
                min = Some(min.map_or(n, |m| m.min(n)));
            }
        }
        if path == root || !path.pop() {
            break;
        }
    }
    seen.then_some(min)
}

// ------------------------------------------------------------- kernel

fn k_userns() -> R {
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
        (Allowed, "unshare(CLONE_NEWUSER) ok: full capabilities inside a new user namespace".into())
    } else {
        (Blocked, os_err())
    }
}

fn k_userns_net() -> R {
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return (Blocked, format!("unshare: {}", os_err()));
    }
    let proto = (libc::ETH_P_ALL as u16).to_be() as i32;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
    if fd >= 0 {
        (Allowed, "new user+net namespace, raw packet socket opened: network admin rights over a fresh stack".into())
    } else {
        (Blocked, format!("namespace made, raw socket refused: {}", os_err()))
    }
}

fn k_userns_mount() -> R {
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        return (Blocked, format!("unshare: {}", os_err()));
    }
    let dir = scratch("mnt");
    let _ = std::fs::create_dir(&dir);
    let r = unsafe {
        libc::mount(cstr("none").as_ptr(), cstr(&dir).as_ptr(), cstr("tmpfs").as_ptr(), 0, std::ptr::null())
    };
    let err = os_err();
    if r == 0 {
        unsafe { libc::umount2(cstr(&dir).as_ptr(), libc::MNT_DETACH) };
    }
    let _ = std::fs::remove_dir(&dir);
    if r == 0 {
        (Allowed, "new user+mount namespace, tmpfs mounted: filesystem mount code reachable".into())
    } else {
        (Blocked, format!("namespace made, mount refused: {err}"))
    }
}

fn k_io_uring() -> R {
    let mut params = [0u8; 120];
    let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 4 as libc::c_uint, params.as_mut_ptr()) };
    open_or_block(fd, "io_uring_setup")
}

fn k_bpf() -> R {
    // BPF_MAP_CREATE (cmd 0): array map, 4-byte key, 4-byte value, 1 entry.
    let mut attr = [0u32; 30];
    attr[0] = 2;
    attr[1] = 4;
    attr[2] = 4;
    attr[3] = 1;
    let fd = unsafe {
        libc::syscall(libc::SYS_bpf, 0 as libc::c_int, attr.as_mut_ptr(), std::mem::size_of_val(&attr) as libc::c_uint)
    };
    open_or_block(fd, "bpf(BPF_MAP_CREATE)")
}

fn k_userfaultfd() -> R {
    const UFFD_USER_MODE_ONLY: libc::c_int = 1;
    let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | UFFD_USER_MODE_ONLY) };
    open_or_block(fd, "userfaultfd")
}

fn k_perf() -> R {
    // perf_event_attr, version 0 (64 bytes): software CPU clock, user space only.
    let mut attr = [0u8; 64];
    attr[0..4].copy_from_slice(&1u32.to_ne_bytes()); // PERF_TYPE_SOFTWARE
    attr[4..8].copy_from_slice(&64u32.to_ne_bytes()); // size
    let flags: u64 = (1 << 5) | (1 << 6); // exclude_kernel | exclude_hv
    attr[40..48].copy_from_slice(&flags.to_ne_bytes());
    let fd = unsafe {
        libc::syscall(libc::SYS_perf_event_open, attr.as_mut_ptr(), 0 as libc::pid_t, -1 as libc::c_int, -1 as libc::c_int, 0 as libc::c_ulong)
    };
    open_or_block(fd, "perf_event_open")
}

fn k_sock_nfnetlink() -> R {
    sock(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER, "netfilter netlink socket")
}

fn k_sock_packet() -> R {
    sock(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32, "raw packet socket")
}

fn k_sock_alg() -> R {
    sock(libc::AF_ALG, libc::SOCK_SEQPACKET, 0, "AF_ALG socket")
}

fn k_sock_vsock() -> R {
    sock(libc::AF_VSOCK, libc::SOCK_STREAM, 0, "AF_VSOCK socket")
}

fn k_ptrace() -> R {
    let child = unsafe { libc::fork() };
    if child < 0 {
        return (Na, format!("fork: {}", os_err()));
    }
    if child == 0 {
        unsafe {
            libc::pause();
            libc::_exit(0);
        }
    }
    let r = unsafe { libc::ptrace(libc::PTRACE_SEIZE, child, 0usize, 0usize) };
    let err = os_err();
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
    }
    if r == 0 {
        (Allowed, "PTRACE_SEIZE on a child: ok".into())
    } else {
        (Blocked, err)
    }
}

fn k_keyctl() -> R {
    const KEY_SPEC_PROCESS_KEYRING: libc::c_int = -2;
    let id = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            cstr("user").as_ptr(),
            cstr("plybox-probe").as_ptr(),
            b"x".as_ptr(),
            1usize,
            KEY_SPEC_PROCESS_KEYRING,
        )
    };
    open_or_block(id, "add_key")
}

fn k_mount() -> R {
    let dir = scratch("mnt");
    let _ = std::fs::create_dir(&dir);
    let r = unsafe {
        libc::mount(cstr("none").as_ptr(), cstr(&dir).as_ptr(), cstr("tmpfs").as_ptr(), 0, std::ptr::null())
    };
    let err = os_err();
    if r == 0 {
        unsafe { libc::umount2(cstr(&dir).as_ptr(), libc::MNT_DETACH) };
    }
    let _ = std::fs::remove_dir(&dir);
    if r == 0 {
        (Allowed, "mount(tmpfs): ok".into())
    } else {
        (Blocked, err)
    }
}

fn k_mknod() -> R {
    let path = scratch("blk");
    // block device 8:0 — the first SCSI/SATA disk. Created, never opened.
    let r = unsafe { libc::mknod(cstr(&path).as_ptr(), libc::S_IFBLK | 0o600, 0x800) };
    let err = os_err();
    let _ = std::fs::remove_file(&path);
    if r == 0 {
        (Allowed, "mknod(block 8:0): ok".into())
    } else {
        (Blocked, err)
    }
}

fn k_kallsyms() -> R {
    let mut buf = [0u8; 4096];
    let n = match std::fs::File::open("/proc/kallsyms").and_then(|mut f| f.read(&mut buf)) {
        Ok(n) => n,
        Err(e) => return (Blocked, format!("/proc/kallsyms: {e}")),
    };
    let real = String::from_utf8_lossy(&buf[..n])
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|addr| u64::from_str_radix(addr, 16).map(|a| a != 0).unwrap_or(false));
    if real {
        (Allowed, "/proc/kallsyms shows real kernel addresses".into())
    } else {
        (Blocked, "/proc/kallsyms readable, addresses zeroed".into())
    }
}

fn k_kmsg() -> R {
    let fd = unsafe { libc::open(cstr("/dev/kmsg").as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    open_or_block(fd as libc::c_long, "open /dev/kmsg")
}

// ------------------------------------------------------------ process

fn p_nnp() -> R {
    match status_field("NoNewPrivs:").as_deref() {
        Some("1") => (Blocked, "no_new_privs is set".into()),
        Some(v) => (Allowed, format!("NoNewPrivs={v}")),
        None => (Na, "cannot read /proc/self/status".into()),
    }
}

fn p_seccomp() -> R {
    match status_field("Seccomp:").as_deref() {
        Some("0") => (Allowed, "Seccomp=0: every syscall the kernel has is reachable".into()),
        Some(v) => (Blocked, format!("Seccomp={v}: a filter is active")),
        None => (Na, "cannot read /proc/self/status".into()),
    }
}

fn p_caps() -> R {
    let uid = unsafe { libc::geteuid() };
    let eff = status_field("CapEff:").unwrap_or_default();
    let has_caps = u64::from_str_radix(&eff, 16).map(|c| c != 0).unwrap_or(false);
    if uid == 0 || has_caps {
        (Allowed, format!("euid={uid} CapEff={eff}"))
    } else {
        (Blocked, format!("euid={uid}, no capabilities"))
    }
}

fn p_hostpid() -> R {
    let me = std::process::id().to_string();
    let comm = std::fs::read_to_string("/proc/1/comm").unwrap_or_default();
    let (mut procs, mut environs) = (0, 0);
    if let Ok(dir) = std::fs::read_dir("/proc") {
        for entry in dir.filter_map(|e| e.ok()) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            procs += 1;
            if name != me {
                let mut one = [0u8; 1];
                let readable = std::fs::File::open(format!("/proc/{name}/environ"))
                    .and_then(|mut f| f.read(&mut one))
                    .map(|n| n > 0)
                    .unwrap_or(false);
                if readable {
                    environs += 1;
                }
            }
        }
    }
    let detail = format!("{procs} processes visible, pid 1 is `{}`, environment readable for {environs}", comm.trim());
    if procs > 8 {
        (Allowed, detail)
    } else {
        (Blocked, detail)
    }
}

fn p_fds() -> R {
    let mut found = Vec::new();
    for fd in 3..1024 {
        if let Ok(target) = std::fs::read_link(format!("/proc/self/fd/{fd}")) {
            let target = target.to_string_lossy().into_owned();
            if !target.starts_with("pipe:") {
                found.push(format!("{fd}->{target}"));
            }
        }
    }
    if found.is_empty() {
        (Blocked, "nothing inherited beyond stdin/stdout/stderr".into())
    } else {
        (Allowed, format!("{} inherited: {}", found.len(), found.iter().take(3).cloned().collect::<Vec<_>>().join(", ")))
    }
}

// ----------------------------------------------- files, secrets, host IPC

const SECRETS: &[&str] = &[
    ".ssh",
    ".aws/credentials",
    ".config/gh/hosts.yml",
    ".npmrc",
    ".docker/config.json",
    ".claude/.credentials.json",
    ".gnupg",
    ".netrc",
    ".kube/config",
    ".config/gcloud",
    ".git-credentials",
    ".bash_history",
];

/// Names only — never contents.
fn readable_secrets(prefix: &str) -> R {
    let Some(home) = env("PROBE_HOST_HOME") else {
        return (Na, "PROBE_HOST_HOME not set".into());
    };
    let mut hits = Vec::new();
    for rel in SECRETS {
        let path = format!("{prefix}{home}/{rel}");
        let readable = match std::fs::metadata(&path) {
            Ok(m) if m.is_dir() => std::fs::read_dir(&path).map(|mut d| d.next().is_some()).unwrap_or(false),
            Ok(_) => {
                let mut one = [0u8; 1];
                std::fs::File::open(&path).and_then(|mut f| f.read(&mut one)).map(|n| n > 0).unwrap_or(false)
            }
            Err(_) => false,
        };
        if readable {
            hits.push(*rel);
        }
    }
    if hits.is_empty() {
        (Blocked, format!("none of {} known credential paths readable", SECRETS.len()))
    } else {
        (Allowed, format!("{} of {} readable: {}", hits.len(), SECRETS.len(), hits.join(", ")))
    }
}

fn f_secrets() -> R {
    readable_secrets("")
}

fn f_secrets_proc() -> R {
    readable_secrets("/proc/self/root")
}

fn f_write_home() -> R {
    let Some(home) = env("PROBE_HOST_HOME") else {
        return (Na, "PROBE_HOST_HOME not set".into());
    };
    let path = format!("{home}/.plybox-probe-{}", std::process::id());
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => {
            let _ = std::fs::remove_file(&path);
            (Allowed, "created and removed a file in the host home".into())
        }
        Err(e) => (Blocked, format!("{home}: {e}")),
    }
}

fn f_write_outside() -> R {
    let Some(dir) = env("PROBE_OUTSIDE") else {
        return (Na, "PROBE_OUTSIDE not set".into());
    };
    let path = format!("{dir}/written-by-probe");
    match std::fs::write(&path, b"probe\n") {
        Ok(()) => {
            let _ = std::fs::remove_file(&path);
            (Allowed, "wrote a file outside the workspace".into())
        }
        Err(e) => (Blocked, format!("{dir}: {e}")),
    }
}

fn f_inject_githook() -> R {
    if !std::path::Path::new(".git").exists() {
        return (Na, "workspace is not a git repository".into());
    }
    let _ = std::fs::create_dir_all(".git/hooks");
    match std::fs::write(".git/hooks/pre-commit", b"#!/bin/sh\n# plybox probe: this line would run on the host\n") {
        Ok(()) => (Allowed, "wrote .git/hooks/pre-commit: it runs on the host at the next commit".into()),
        Err(e) => (Blocked, format!(".git/hooks/pre-commit: {e}")),
    }
}

fn f_inject_agentcfg() -> R {
    let _ = std::fs::create_dir_all(".claude");
    match std::fs::write(".claude/settings.json", b"{\"_plybox_probe\": \"a hook here would run outside the box\"}\n") {
        Ok(()) => (Allowed, "wrote .claude/settings.json in the workspace".into()),
        Err(e) => (Blocked, format!(".claude/settings.json: {e}")),
    }
}

fn f_ipc_dbus() -> R {
    let Some(uid) = env("PROBE_HOST_UID") else {
        return (Na, "PROBE_HOST_UID not set".into());
    };
    unix_connect(&format!("/run/user/{uid}/bus"), "the session bus")
}

fn f_ipc_docker() -> R {
    unix_connect("/var/run/docker.sock", "the Docker socket")
}

fn f_ipc_abstract() -> R {
    use std::os::linux::net::SocketAddrExt;
    let table = match std::fs::read_to_string("/proc/net/unix") {
        Ok(t) => t,
        Err(e) => return (Na, format!("/proc/net/unix: {e}")),
    };
    let mut names: Vec<&str> = table
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter(|p| p.starts_with('@') && p.len() > 1)
        .collect();
    names.sort();
    names.dedup();
    if names.is_empty() {
        return (Blocked, "no abstract sockets visible in this network namespace".into());
    }
    for name in names.iter().take(12) {
        let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(&name[1..]) else {
            continue;
        };
        if UnixStream::connect_addr(&addr).is_ok() {
            return (Allowed, format!("connected to {name} ({} abstract sockets visible)", names.len()));
        }
    }
    (Blocked, format!("{} abstract sockets visible, none accepted a connection", names.len()))
}

fn f_ipc_agent() -> R {
    match env("PROBE_SSH_AUTH_SOCK") {
        Some(path) => unix_connect(&path, "ssh-agent"),
        None => (Na, "no ssh-agent on this host".into()),
    }
}

// ------------------------------------------------------------ network

// Port 80: a plain HTTP request gets a real reply (a redirect), which is the
// evidence `reach` needs; on 443 the server would only answer a TLS hello.
fn n_tcp_public() -> R {
    tcp_probe("1.1.1.1:80", "a public address")
}

fn n_tcp_v6() -> R {
    tcp_probe("[2606:4700:4700::1111]:80", "a public IPv6 address")
}

fn n_dns_direct() -> R {
    match dns_query("1.1.1.1:53".parse().unwrap(), "example.com") {
        Ok((n, _)) => (Allowed, format!("1.1.1.1 answered ({n} bytes)")),
        Err(e) => (Blocked, format!("1.1.1.1:53: {e}")),
    }
}

fn n_dns_system() -> R {
    let conf = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let server = conf
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .find_map(|v| v.trim().parse::<IpAddr>().ok());
    let Some(ip) = server else {
        return (Blocked, "no nameserver in /etc/resolv.conf".into());
    };
    let name = format!("plybox-probe-{}.example.com", std::process::id());
    match dns_query(SocketAddr::new(ip, 53), &name) {
        Ok((_, rcode)) => (Allowed, format!("{ip} resolved an arbitrary name (rcode {rcode}): data can leave inside DNS names")),
        Err(e) => (Blocked, format!("{ip}:53: {e}")),
    }
}

fn n_host_lo() -> R {
    match env("PROBE_HOST_LO") {
        Some(addr) => tcp_probe(&addr, "a host loopback service"),
        None => (Na, "PROBE_HOST_LO not set".into()),
    }
}

fn n_host_lan() -> R {
    match env("PROBE_HOST_LAN") {
        Some(addr) => tcp_probe(&addr, "a service on the host's LAN address"),
        None => (Na, "PROBE_HOST_LAN not set".into()),
    }
}

fn n_metadata() -> R {
    match reach("169.254.169.254:80") {
        Reach::Replied(n) => (Allowed, format!("169.254.169.254:80 answered ({n} bytes)")),
        Reach::Silent(why) => (Blocked, format!("169.254.169.254:80: connected but {why}")),
        Reach::NoConnect(e) => match e.raw_os_error() {
            Some(libc::ENETUNREACH) | Some(libc::EPERM) | Some(libc::EACCES) => (Blocked, e.to_string()),
            _ => (Na, format!("no metadata service answers here ({e})")),
        },
    }
}

// ---------------------------------------------------------- resources

/// Fork paused children until the kernel refuses or the cap is reached.
/// Children die with us (PR_SET_PDEATHSIG) and are killed and reaped here.
fn q_pids() -> R {
    let cap: usize = env("PROBE_FORK_CAP").and_then(|v| v.parse().ok()).unwrap_or(2000);
    let mut kids: Vec<libc::pid_t> = Vec::with_capacity(cap);
    let mut refused = String::new();
    while kids.len() < cap {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            refused = os_err();
            break;
        }
        if pid == 0 {
            unsafe {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                libc::pause();
                libc::_exit(0);
            }
        }
        kids.push(pid);
    }
    for pid in &kids {
        unsafe { libc::kill(*pid, libc::SIGKILL) };
    }
    for pid in &kids {
        unsafe { libc::waitpid(*pid, std::ptr::null_mut(), 0) };
    }
    let limit = cgroup_limit("pids.max").flatten().map(|n| format!(" (pids.max {n})")).unwrap_or_default();
    if kids.len() >= cap {
        (Allowed, format!("created {cap} extra processes without hitting a limit{limit}"))
    } else {
        (Blocked, format!("fork refused after {} extra processes: {refused}{limit}", kids.len()))
    }
}

/// Map and touch memory in 64 MiB steps up to the cap. Under a cgroup
/// memory limit the kernel OOM-kills this child, which the runner reports
/// as "killed by SIGKILL"; without one the whole cap is reached.
fn q_mem() -> R {
    let cap_mb: usize = env("PROBE_MEM_MB").and_then(|v| v.parse().ok()).unwrap_or(1024);
    const CHUNK: usize = 64 * 1024 * 1024;
    let mut held: Vec<*mut u8> = Vec::new();
    let mut mb = 0;
    while mb < cap_mb {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                CHUNK,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return (Blocked, format!("allocation refused at {mb} MiB: {}", os_err()));
        }
        let p = p as *mut u8;
        let mut off = 0;
        while off < CHUNK {
            unsafe { p.add(off).write_volatile(1) };
            off += 4096;
        }
        held.push(p);
        mb += 64;
    }
    let limit = cgroup_limit("memory.max").flatten().map(|n| format!(" (memory.max {} MiB)", n / (1024 * 1024))).unwrap_or_default();
    (Allowed, format!("allocated and touched {mb} MiB with no limit hit{limit}"))
}
