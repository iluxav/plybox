//! Per-box resource limits: memory, processes, CPU — cgroup v2, no root.
//!
//! Two ways to get a cgroup of our own, tried in order:
//!   1. **direct**: make a child of the cgroup we are in and write the limits.
//!      cgroup v2 forbids a cgroup from holding processes once it delegates
//!      controllers to children, so this works only when plybox is alone in
//!      its cgroup (a container's init, a systemd-launched job). On a desktop
//!      terminal with 20 other processes the kernel answers EBUSY.
//!   2. **systemd-run --user --scope**: ask the user's systemd for a transient
//!      scope with the limits as properties. OOMPolicy=continue, so when the
//!      kernel kills one process for exceeding MemoryMax the box carries on
//!      (the lab's first run showed the default stops the whole scope).
//!
//! If neither works, the run proceeds and says so — the probe suite will
//! show the two resource doors open, which is the honest outcome.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct Limits {
    pub mem_bytes: Option<u64>,
    pub pids: Option<u32>,
    pub cpu: Option<f64>,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        self.mem_bytes.is_none() && self.pids.is_none() && self.cpu.is_none()
    }
}

/// "512M", "2G", "1048576" → bytes.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('K') | Some('k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') | Some('m') => (&s[..s.len() - 1], 1u64 << 20),
        Some('G') | Some('g') => (&s[..s.len() - 1], 1u64 << 30),
        _ => (s, 1),
    };
    num.parse::<u64>().ok().and_then(|n| n.checked_mul(mult))
        .ok_or_else(|| format!("size `{s}`: expected a number with K/M/G that fits in u64"))
}

pub enum Mode {
    Direct(PathBuf),
    SystemdRun,
    None,
}

pub struct Enforcer {
    pub limits: Limits,
    pub mode: Mode,
}

impl Enforcer {
    pub fn prepare(limits: Limits, id: &str) -> Enforcer {
        if limits.is_empty() {
            return Enforcer { limits, mode: Mode::None };
        }
        if let Some(cg) = try_direct(&limits, id) {
            return Enforcer { limits, mode: Mode::Direct(cg) };
        }
        if systemd_run_works() {
            return Enforcer { limits, mode: Mode::SystemdRun };
        }
        Enforcer { limits, mode: Mode::None }
    }

    pub fn describe(&self) -> String {
        match &self.mode {
            Mode::Direct(p) => format!("cgroup {}", p.display()),
            Mode::SystemdRun => "systemd-run scope".into(),
            Mode::None if self.limits.is_empty() => "none requested".into(),
            Mode::None => "NOT ENFORCED (no cgroup available; run inside a container or with systemd --user)".into(),
        }
    }

    /// Turn `engine ARGS` into the command that runs it under the limits.
    pub fn command(&self, engine: &Path, args: &[String]) -> Command {
        let mut c = Command::new(engine);
        c.args(args);
        self.wrap(&mut c)
    }

    /// Apply the limits to an already-built command. systemd-run mode
    /// returns a new command that wraps it; the others modify it in place.
    pub fn wrap(&self, inner: &mut Command) -> Command {
        match &self.mode {
            Mode::SystemdRun => {
                let mut c = Command::new("systemd-run");
                c.args(["--user", "--scope", "-q", "-p", "OOMPolicy=continue", "-p", "MemorySwapMax=0"]);
                if let Some(b) = self.limits.mem_bytes {
                    c.arg("-p").arg(format!("MemoryMax={b}"));
                }
                if let Some(p) = self.limits.pids {
                    c.arg("-p").arg(format!("TasksMax={p}"));
                }
                if let Some(cpu) = self.limits.cpu {
                    c.arg("-p").arg(format!("CPUQuota={}%", (cpu * 100.0).round() as u64));
                }
                c.arg("--").arg(inner.get_program()).args(inner.get_args());
                c
            }
            Mode::Direct(cg) => {
                let procs = cg.join("cgroup.procs");
                let mut c = Command::new(inner.get_program());
                c.args(inner.get_args());
                // Runs in the child between fork and exec: join the box's
                // cgroup before the engine starts, so nothing escapes the limit.
                unsafe {
                    c.pre_exec(move || std::fs::write(&procs, "0"));
                }
                c
            }
            Mode::None => {
                let mut c = Command::new(inner.get_program());
                c.args(inner.get_args());
                c
            }
        }
    }

    /// Remove the box's cgroup once it is empty.
    pub fn finish(&self) {
        if let Mode::Direct(cg) = &self.mode {
            let _ = std::fs::remove_dir(cg);
        }
    }
}

use std::os::unix::process::CommandExt;

fn own_cgroup() -> Option<PathBuf> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = text.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    Some(PathBuf::from(format!("/sys/fs/cgroup{rel}")))
}

/// Make `own/plybox-<id>` with the limits applied, moving ourselves into a
/// sibling first (the rule: a cgroup that delegates controllers holds no
/// processes). Returns None, with everything undone, if the kernel refuses.
fn try_direct(limits: &Limits, id: &str) -> Option<PathBuf> {
    let own = own_cgroup()?;
    let ctl = own.join("plybox-ctl");
    let box_cg = own.join(format!("plybox-{id}"));
    if std::fs::create_dir(&ctl).is_err() && !ctl.is_dir() {
        return None;
    }
    if std::fs::write(ctl.join("cgroup.procs"), "0").is_err() {
        let _ = std::fs::remove_dir(&ctl);
        return None;
    }
    let mut wanted = String::new();
    if limits.mem_bytes.is_some() {
        wanted.push_str("+memory ");
    }
    if limits.pids.is_some() {
        wanted.push_str("+pids ");
    }
    if limits.cpu.is_some() {
        wanted.push_str("+cpu ");
    }
    if std::fs::write(own.join("cgroup.subtree_control"), wanted.trim()).is_err() {
        // EBUSY: other processes live here. Move back and leave no trace.
        let _ = std::fs::write(own.join("cgroup.procs"), "0");
        let _ = std::fs::remove_dir(&ctl);
        return None;
    }
    if std::fs::create_dir(&box_cg).is_err() {
        return None;
    }
    let w = |name: &str, v: String| std::fs::write(box_cg.join(name), v);
    let ok = limits.mem_bytes.map_or(Ok(()), |b| w("memory.max", b.to_string()).and_then(|_| w("memory.swap.max", "0".into())))
        .and(limits.pids.map_or(Ok(()), |p| w("pids.max", p.to_string())))
        .and(limits.cpu.map_or(Ok(()), |c| w("cpu.max", format!("{} 100000", (c * 100_000.0) as u64))));
    if ok.is_err() {
        let _ = std::fs::remove_dir(&box_cg);
        return None;
    }
    Some(box_cg)
}

fn systemd_run_works() -> bool {
    Command::new("systemd-run")
        .args(["--user", "--scope", "-q", "--", "/bin/true"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sizes_reject_overflow_instead_of_wrapping() {
        assert_eq!(parse_size("2G").unwrap(), 2147483648);
        assert_eq!(parse_size(" 0 ").unwrap(), 0);
        for invalid in ["", "-1", "1.5G", "18446744073709551616", "18446744073709551615G"] {
            assert!(parse_size(invalid).is_err(), "accepted {invalid}");
        }
    }
}
