//! boxer — plybox lab, step 3.
//!
//! Applies the kernel-surface layer, then execs the target. It expects to run
//! already inside the namespaces/mounts of step 2 (bubblewrap), so it adds
//! only what step 2 does not: a Landlock filesystem policy and a seccomp
//! syscall allowlist.
//!
//!   boxer [--rw PATH]... [--ro PATH]... [--no-landlock] [--no-seccomp] -- CMD...
//!
//! Order matters and matches a real launcher: Landlock first (needs no
//! privilege beyond the ruleset), then no_new_privs, then seccomp, then exec.
//! no_new_privs is set regardless, so a setuid binary cannot regain anything.

mod seccomp;

use std::ffi::CString;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};

struct Args {
    rw: Vec<String>,
    ro: Vec<String>,
    landlock: bool,
    seccomp: bool,
    cmd: Vec<String>,
}

fn parse() -> Args {
    let mut a = Args {
        // Sensible defaults for the lab box; overridable on the command line.
        rw: vec!["/work".into(), "/tmp".into(), "/home".into(), "/dev".into(), "/proxy".into()],
        ro: vec!["/usr".into(), "/etc".into(), "/opt".into(), "/proc".into(), "/bin".into(), "/sbin".into(), "/lib".into(), "/lib64".into()],
        landlock: true,
        seccomp: true,
        cmd: vec![],
    };
    let mut it = std::env::args().skip(1);
    let (mut rw, mut ro) = (vec![], vec![]);
    let (mut set_rw, mut set_ro) = (false, false);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--rw" => { set_rw = true; rw.push(it.next().expect("--rw needs a path")); }
            "--ro" => { set_ro = true; ro.push(it.next().expect("--ro needs a path")); }
            "--no-landlock" => a.landlock = false,
            "--no-seccomp" => a.seccomp = false,
            "--" => { a.cmd = it.collect(); break; }
            other => { eprintln!("boxer: unknown flag {other}"); std::process::exit(2); }
        }
    }
    if set_rw { a.rw = rw; }
    if set_ro { a.ro = ro; }
    if a.cmd.is_empty() { eprintln!("boxer: nothing to run (expected -- CMD...)"); std::process::exit(2); }
    a
}

/// Restrict the filesystem to the declared paths. Best-effort on the ABI the
/// running kernel supports: a newer binary still runs on an older kernel,
/// enforcing what it can. Returns the enforcement status for the caller to
/// report, so a silently-unenforced run is never mistaken for a safe one.
fn apply_landlock(rw: &[String], ro: &[String]) -> Result<RulesetStatus, String> {
    let abi = ABI::V5;
    let rw_access = AccessFs::from_all(abi);
    let ro_access = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| format!("landlock handle_access: {e}"))?
        .create()
        .map_err(|e| format!("landlock create: {e}"))?;

    for p in ro {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, ro_access))
                .map_err(|e| format!("landlock ro {p}: {e}"))?;
        }
    }
    for p in rw {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, rw_access))
                .map_err(|e| format!("landlock rw {p}: {e}"))?;
        }
    }
    let status = ruleset
        .restrict_self()
        .map_err(|e| format!("landlock restrict_self: {e}"))?;
    Ok(status.ruleset)
}

fn set_no_new_privs() -> Result<(), String> {
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r == 0 { Ok(()) } else { Err(format!("no_new_privs: {}", std::io::Error::last_os_error())) }
}

fn main() {
    let a = parse();

    if a.landlock {
        match apply_landlock(&a.rw, &a.ro) {
            Ok(RulesetStatus::FullyEnforced) => {}
            Ok(other) => eprintln!("boxer: warning: landlock {other:?} (kernel enforces less than asked)"),
            Err(e) => { eprintln!("boxer: {e}"); std::process::exit(1); }
        }
    }

    if let Err(e) = set_no_new_privs() {
        eprintln!("boxer: {e}");
        std::process::exit(1);
    }

    if a.seccomp {
        match seccomp::program() {
            Ok(prog) => {
                if let Err(e) = seccompiler::apply_filter(&prog) {
                    eprintln!("boxer: seccomp apply: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => { eprintln!("boxer: {e}"); std::process::exit(1); }
        }
    }

    let prog = CString::new(a.cmd[0].clone()).unwrap();
    let argv: Vec<CString> = a.cmd.iter().map(|s| CString::new(s.as_str()).unwrap()).collect();
    let err = exec(&prog, &argv);
    eprintln!("boxer: exec {}: {err}", a.cmd[0]);
    std::process::exit(127);
}

/// execvp, searching PATH, keeping the current environment.
fn exec(prog: &CString, argv: &[CString]) -> std::io::Error {
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { libc::execvp(prog.as_ptr(), ptrs.as_ptr()) };
    std::io::Error::last_os_error()
}
