//! `plybox __inner` — the first process inside the box.
//!
//! Two jobs, then it steps aside:
//!   1. bridge 127.0.0.1:3128 inside the box to the proxy's unix socket, so
//!      ordinary HTTPS_PROXY settings reach the proxy outside;
//!   2. start the workload under the kernel-surface layer (Landlock,
//!      no_new_privs, the seccomp allowlist) and wait for it, forwarding
//!      SIGTERM/SIGINT and returning its exit code.
//!
//! Order matters for safety with threads: the listener is bound and the
//! seccomp program and Landlock ruleset are built BEFORE the fork; the child
//! only applies them and execs; the accept thread starts in the parent
//! AFTER the fork. Nothing allocates in the child after fork.

use std::ffi::CString;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, Ordering};

use landlock::RulesetStatus;

use crate::{landlock_fs, seccomp};

const LISTEN: &str = "127.0.0.1:3128";
// Directories only: a Landlock rule with directory rights on a FILE is
// rejected and would downgrade the whole ruleset to "partially enforced".
const RO: &[&str] = &["/usr", "/etc", "/proc", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/run/plybox"];
const RW: &[&str] = &["/work", "/tmp", "/home", "/dev"];

static CHILD: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    let pid = CHILD.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe { libc::kill(pid, sig) };
    }
}

pub fn main(args: &[String]) -> Result<i32, String> {
    let mut sock: Option<PathBuf> = None;
    let mut ro_root = false;
    let mut cmd: Vec<String> = vec![];
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--proxy-sock" => sock = it.next().map(PathBuf::from),
            "--ro-root" => ro_root = true,
            "--" => {
                cmd = it.cloned().collect();
                break;
            }
            other => return Err(format!("__inner: unknown flag {other}")),
        }
    }
    if cmd.is_empty() {
        return Err("__inner: nothing to run".into());
    }

    // HOME may be a fresh tmpfs (gVisor tier): make the directory exist.
    if let Ok(home) = std::env::var("HOME") {
        let _ = std::fs::create_dir_all(&home);
    }
    let listener = TcpListener::bind(LISTEN).map_err(|e| format!("forwarder bind {LISTEN}: {e}"))?;
    let program = seccomp::program()?;
    // With an image as the root, all of it is the image (read-only to the
    // workload); with host tools, only the directories plybox bound.
    let ruleset = landlock_fs::build(if ro_root { &["/"] } else { RO }, RW)?;

    let prog = CString::new(cmd[0].as_str()).unwrap();
    let argv: Vec<CString> = cmd.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // --- the workload: apply the layer, exec. No allocation past here. ---
        drop(listener);
        match landlock_fs::apply(ruleset) {
            Ok(RulesetStatus::FullyEnforced) => {}
            Ok(RulesetStatus::PartiallyEnforced) => eprintln!("plybox: warning: landlock partially enforced by this kernel"),
            Ok(RulesetStatus::NotEnforced) => eprintln!("plybox: warning: landlock not enforced by this kernel"),
            Err(e) => {
                eprintln!("plybox: {e}");
                unsafe { libc::_exit(126) };
            }
        }
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            eprintln!("plybox: no_new_privs: {}", std::io::Error::last_os_error());
            unsafe { libc::_exit(126) };
        }
        if let Err(e) = seccomp::apply(&program) {
            eprintln!("plybox: {e}");
            unsafe { libc::_exit(126) };
        }
        unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
        eprintln!("plybox: exec {}: {}", cmd[0], std::io::Error::last_os_error());
        unsafe { libc::_exit(127) };
    }

    // --- the parent: forwarder + reaper ---
    CHILD.store(pid, Ordering::SeqCst);
    let handler = forward as extern "C" fn(libc::c_int) as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGHUP, handler);
    }
    let sock = sock.ok_or("__inner: --proxy-sock is required")?;
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let sock = sock.clone();
            std::thread::spawn(move || bridge(conn, &sock));
        }
    });

    loop {
        let mut status = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else if libc::WIFSIGNALED(status) {
                128 + libc::WTERMSIG(status)
            } else {
                1
            });
        }
        if r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err(format!("waitpid: {}", std::io::Error::last_os_error()));
        }
    }
}

/// One in-box TCP connection ↔ the proxy's unix socket.
fn bridge(tcp: TcpStream, sock: &PathBuf) {
    let unix = match UnixStream::connect(sock) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("plybox: forwarder: cannot reach the proxy at {}: {e}", sock.display());
            let _ = tcp.shutdown(Shutdown::Both);
            return;
        }
    };
    let (Ok(mut t2), Ok(mut u2)) = (tcp.try_clone(), unix.try_clone()) else { return };
    let (mut t1, mut u1) = (tcp, unix);
    let th = std::thread::spawn(move || {
        let _ = std::io::copy(&mut t1, &mut u1);
        let _ = u1.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut u2, &mut t2);
    let _ = t2.shutdown(Shutdown::Write);
    let _ = th.join();
}

// Keep the Read/Write imports honest for std::io::copy on these types.
#[allow(dead_code)]
fn _types_implement_io(_: &dyn Read, _: &dyn Write) {}
