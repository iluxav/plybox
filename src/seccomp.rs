//! The seccomp allowlist, as measured in the lab (`lab/boxer`).
//!
//! Default action for anything not listed is **ENOSYS**, not EPERM: it reads
//! as "the kernel does not have this", so libraries that feature-probe a
//! syscall (libuv trying io_uring, glibc trying clone3) fall back to the old
//! path instead of treating the box as broken. Dangerous syscalls are simply
//! absent and return ENOSYS too.
//!
//! Argument rules:
//!   * `socket` — only AF_UNIX / AF_INET / AF_INET6, plus AF_NETLINK limited
//!     to NETLINK_ROUTE (interface enumeration). Closes AF_PACKET, AF_VSOCK,
//!     AF_ALG and NETLINK_NETFILTER.
//!   * `clone` — only when CLONE_NEWUSER is clear. `clone3` is off the list
//!     → ENOSYS → glibc falls back to `clone`.
//!   * `ioctl` — exact terminal and descriptor I/O requests only; all
//!     other requests return ENOSYS, including filesystem/device controls.
//!
//! x86_64 for now: the list names `libc::SYS_*` constants.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond,
    SeccompFilter, SeccompRule,
};

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const NETLINK_ROUTE: u64 = 0;
const CLONE_NEWUSER: u64 = 0x1000_0000;

#[rustfmt::skip]
const ALLOW: &[libc::c_long] = &[
    // file I/O
    libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
    libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_preadv, libc::SYS_pwritev,
    libc::SYS_preadv2, libc::SYS_pwritev2,
    libc::SYS_open, libc::SYS_openat, libc::SYS_openat2, libc::SYS_close,
    libc::SYS_close_range, libc::SYS_creat, libc::SYS_lseek,
    libc::SYS_stat, libc::SYS_fstat, libc::SYS_lstat, libc::SYS_newfstatat,
    libc::SYS_statx, libc::SYS_statfs, libc::SYS_fstatfs,
    libc::SYS_access, libc::SYS_faccessat, libc::SYS_faccessat2,
    libc::SYS_getdents, libc::SYS_getdents64, libc::SYS_getcwd,
    libc::SYS_chdir, libc::SYS_fchdir,
    libc::SYS_rename, libc::SYS_renameat, libc::SYS_renameat2,
    libc::SYS_mkdir, libc::SYS_mkdirat, libc::SYS_rmdir,
    libc::SYS_link, libc::SYS_linkat, libc::SYS_unlink, libc::SYS_unlinkat,
    libc::SYS_symlink, libc::SYS_symlinkat, libc::SYS_readlink, libc::SYS_readlinkat,
    libc::SYS_chmod, libc::SYS_fchmod, libc::SYS_fchmodat,
    libc::SYS_chown, libc::SYS_fchown, libc::SYS_lchown, libc::SYS_fchownat,
    libc::SYS_umask, libc::SYS_truncate, libc::SYS_ftruncate,
    libc::SYS_fsync, libc::SYS_fdatasync, libc::SYS_sync, libc::SYS_syncfs,
    libc::SYS_sync_file_range, libc::SYS_fallocate, libc::SYS_fadvise64,
    libc::SYS_copy_file_range, libc::SYS_sendfile, libc::SYS_splice, libc::SYS_tee,
    libc::SYS_dup, libc::SYS_dup2, libc::SYS_dup3, libc::SYS_fcntl, libc::SYS_flock,
    libc::SYS_pipe, libc::SYS_pipe2,
    libc::SYS_utime, libc::SYS_utimes, libc::SYS_futimesat, libc::SYS_utimensat,
    libc::SYS_getxattr, libc::SYS_lgetxattr, libc::SYS_fgetxattr,
    libc::SYS_listxattr, libc::SYS_llistxattr, libc::SYS_flistxattr,
    // memory
    libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mremap, libc::SYS_mprotect,
    libc::SYS_madvise, libc::SYS_mincore, libc::SYS_brk, libc::SYS_msync,
    libc::SYS_mlock, libc::SYS_munlock, libc::SYS_mlockall, libc::SYS_munlockall,
    libc::SYS_memfd_create, libc::SYS_membarrier,
    // signals
    libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigpending, libc::SYS_rt_sigtimedwait, libc::SYS_rt_sigsuspend,
    libc::SYS_rt_sigqueueinfo, libc::SYS_rt_tgsigqueueinfo, libc::SYS_sigaltstack,
    libc::SYS_signalfd, libc::SYS_signalfd4,
    // process / threads
    libc::SYS_fork, libc::SYS_vfork, libc::SYS_execve, libc::SYS_execveat,
    libc::SYS_exit, libc::SYS_exit_group, libc::SYS_wait4, libc::SYS_waitid,
    libc::SYS_kill, libc::SYS_tkill, libc::SYS_tgkill,
    libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid,
    libc::SYS_getuid, libc::SYS_geteuid, libc::SYS_getgid, libc::SYS_getegid,
    libc::SYS_getpgrp, libc::SYS_getpgid, libc::SYS_getsid, libc::SYS_setsid,
    libc::SYS_setpgid, libc::SYS_getgroups,
    libc::SYS_set_tid_address, libc::SYS_set_robust_list, libc::SYS_get_robust_list,
    libc::SYS_rseq, libc::SYS_futex, libc::SYS_futex_waitv,
    libc::SYS_restart_syscall,
    // scheduling / limits / info
    libc::SYS_sched_yield, libc::SYS_sched_getaffinity, libc::SYS_sched_setaffinity,
    libc::SYS_sched_getparam, libc::SYS_sched_getscheduler,
    libc::SYS_sched_get_priority_max, libc::SYS_sched_get_priority_min,
    libc::SYS_getpriority, libc::SYS_setpriority,
    libc::SYS_getrlimit, libc::SYS_setrlimit, libc::SYS_prlimit64,
    libc::SYS_getrusage, libc::SYS_sysinfo, libc::SYS_times, libc::SYS_uname,
    libc::SYS_getcpu, libc::SYS_getrandom,
    libc::SYS_prctl, libc::SYS_arch_prctl,
    // time
    libc::SYS_gettimeofday, libc::SYS_time, libc::SYS_nanosleep,
    libc::SYS_clock_gettime, libc::SYS_clock_getres, libc::SYS_clock_nanosleep,
    libc::SYS_timer_create, libc::SYS_timer_settime, libc::SYS_timer_gettime,
    libc::SYS_timer_getoverrun, libc::SYS_timer_delete,
    libc::SYS_timerfd_create, libc::SYS_timerfd_settime, libc::SYS_timerfd_gettime,
    libc::SYS_getitimer, libc::SYS_setitimer, libc::SYS_alarm,
    // polling / events
    libc::SYS_poll, libc::SYS_ppoll, libc::SYS_select, libc::SYS_pselect6,
    libc::SYS_epoll_create, libc::SYS_epoll_create1, libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait, libc::SYS_epoll_pwait, libc::SYS_epoll_pwait2,
    libc::SYS_eventfd, libc::SYS_eventfd2,
    libc::SYS_inotify_init, libc::SYS_inotify_init1,
    libc::SYS_inotify_add_watch, libc::SYS_inotify_rm_watch,
    // sockets (families filtered on `socket` below)
    libc::SYS_connect, libc::SYS_accept, libc::SYS_accept4,
    libc::SYS_bind, libc::SYS_listen, libc::SYS_shutdown,
    libc::SYS_getsockname, libc::SYS_getpeername, libc::SYS_socketpair,
    libc::SYS_setsockopt, libc::SYS_getsockopt,
    libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg, libc::SYS_recvmsg,
    libc::SYS_sendmmsg, libc::SYS_recvmmsg,
];

/// Build the filter program. Done in the parent, before fork, so the child
/// only has to apply it (no allocation after fork).
pub fn program() -> Result<BpfProgram, String> {
    let mut rules: BTreeMap<libc::c_long, Vec<SeccompRule>> = BTreeMap::new();
    for nr in ALLOW {
        rules.insert(*nr, vec![]);
    }
    let fam = |d: u64| Cond::new(0, Len::Dword, Op::Eq, d).unwrap();
    rules.insert(
        libc::SYS_socket,
        vec![
            SeccompRule::new(vec![fam(AF_UNIX)]).unwrap(),
            SeccompRule::new(vec![fam(AF_INET)]).unwrap(),
            SeccompRule::new(vec![fam(AF_INET6)]).unwrap(),
            SeccompRule::new(vec![fam(AF_NETLINK), Cond::new(2, Len::Dword, Op::Eq, NETLINK_ROUTE).unwrap()]).unwrap(),
        ],
    );
    rules.insert(
        libc::SYS_clone,
        vec![SeccompRule::new(vec![Cond::new(0, Len::Qword, Op::MaskedEq(CLONE_NEWUSER), 0).unwrap()]).unwrap()],
    );
    // Requests are unsigned int in the Linux ABI: compare the low 32 bits.
    // No wildcard families, device administration, terminal injection,
    // descriptor-based namespace access or filesystem flag manipulation.
    let ioctls: &[u64] = &[
        0x5401, // TCGETS: isatty / terminal attributes
        0x5402, 0x5403, 0x5404, // TCSETS, TCSETSW, TCSETSF
        0x802c542a, 0x402c542b, 0x402c542c, 0x402c542d, // TCGETS2 / TCSETS*2 (newer libc)
        0x540f, 0x5410, // TIOCGPGRP, TIOCSPGRP: shell job control
        0x5413, 0x5414, // TIOCGWINSZ, TIOCSWINSZ: terminal dimensions
        0x541b, 0x5421, // FIONREAD, FIONBIO: buffered bytes / nonblocking I/O
        0x5450, 0x5451, // FIONCLEX, FIOCLEX: descriptor close-on-exec
        0x80045430, 0x40045431, // TIOCGPTN, TIOCSPTLCK: openpty
    ];
    rules.insert(libc::SYS_ioctl, ioctls.iter().map(|&request|
        SeccompRule::new(vec![Cond::new(1, Len::Dword, Op::Eq, request).unwrap()]).unwrap()
    ).collect());
    // login_tty/forkpty need to acquire their own controlling terminal.
    // Only argument zero: never request stealing another session's tty.
    rules.get_mut(&libc::SYS_ioctl).unwrap().push(SeccompRule::new(vec![
        Cond::new(1, Len::Dword, Op::Eq, 0x540e).unwrap(), // TIOCSCTTY
        Cond::new(2, Len::Qword, Op::Eq, 0).unwrap(),
    ]).unwrap());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into().map_err(|e| format!("seccomp arch: {e:?}"))?,
    )
    .map_err(|e| format!("seccomp filter: {e}"))?;
    filter.try_into().map_err(|e| format!("seccomp compile: {e:?}"))
}

pub fn apply(program: &BpfProgram) -> Result<(), String> {
    seccompiler::apply_filter(program).map_err(|e| format!("seccomp apply: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_ioctl_allowlist() {
        if std::env::var_os("PLYBOX_IOCTL_TEST_CHILD").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "seccomp::tests::kernel_ioctl_allowlist", "--nocapture"])
                .env("PLYBOX_IOCTL_TEST_CHILD", "1").status().unwrap();
            assert!(status.success());
            return;
        }
        apply(&program().unwrap()).unwrap();
        unsafe {
            let mut pipe = [0; 2];
            assert_eq!(libc::pipe(pipe.as_mut_ptr()), 0);
            assert_eq!(libc::write(pipe[1], b"hello".as_ptr().cast(), 5), 5);
            let mut bytes = 0i32;
            assert_eq!(libc::ioctl(pipe[0], libc::FIONREAD, &mut bytes), 0);
            assert_eq!(bytes, 5);
            // Invalid fd means these calls are harmless even without a filter.
            // ENOSYS rather than EBADF proves rejection by the filter.
            for request in [0x5412u64, 0x541c, 0x40086602, 0x40045441, 0xdeadbeef] {
                assert_eq!(libc::syscall(libc::SYS_ioctl, -1, request, 0), -1);
                assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOSYS));
            }
            assert_eq!(libc::syscall(libc::SYS_ioctl, -1, 0x540e, 1), -1);
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ENOSYS));
            // Match the kernel's unsigned-int request conversion.
            assert_eq!(libc::syscall(libc::SYS_ioctl, pipe[0], 0x10000541bu64, &mut bytes), 0);
            let mut master = -1; let mut slave = -1;
            assert_eq!(libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null(), std::ptr::null()), 0);
            let mut term: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave, &mut term), 0, "{}", std::io::Error::last_os_error());
            assert_eq!(libc::tcsetattr(slave, libc::TCSANOW, &term), 0);
            for fd in [pipe[0], pipe[1], master, slave] { libc::close(fd); }
        }
    }
}
