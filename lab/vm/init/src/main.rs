//! vminit — plybox lab, step 5: PID 1 inside the Firecracker guest.
//!
//! The guest has one job: run the probe and report. So init mounts the
//! handful of filesystems the probe reads, prints a timing marker, runs
//! `/probe` with its output on the serial console, prints a second marker,
//! and reboots — which Firecracker treats as "the VM is done" and exits.
//!
//! The markers carry CLOCK_MONOTONIC in ms, which starts at kernel boot, so
//! "init up at N ms" is the kernel's own boot time inside the VM.

use std::ffi::CString;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn mount(src: &str, dst: &str, fstype: &str, flags: libc::c_ulong) {
    let _ = std::fs::create_dir_all(dst);
    let r = unsafe {
        libc::mount(c(src).as_ptr(), c(dst).as_ptr(), c(fstype).as_ptr(), flags, std::ptr::null())
    };
    if r != 0 {
        eprintln!("vminit: mount {fstype} on {dst}: {}", std::io::Error::last_os_error());
    }
}

fn now_ms() -> i64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec * 1000 + ts.tv_nsec / 1_000_000
}

fn main() {
    mount("devtmpfs", "/dev", "devtmpfs", 0);
    mount("proc", "/proc", "proc", 0);
    mount("sysfs", "/sys", "sysfs", 0);
    mount("tmpfs", "/tmp", "tmpfs", 0);
    mount("tmpfs", "/work", "tmpfs", 0); // the probe writes scratch files in its cwd
    let _ = std::env::set_current_dir("/work");

    let up = now_ms();
    println!("vminit\tup\t{up}");

    let status = std::process::Command::new("/probe")
        .env("PROBE_FORK_CAP", "2000")
        .env("PROBE_MEM_MB", "1024")
        .status();
    let done = now_ms();
    match status {
        Ok(s) => println!("vminit\tprobe-exit\t{done}\t{}", s.code().unwrap_or(-1)),
        Err(e) => println!("vminit\tprobe-failed\t{done}\t{e}"),
    }

    unsafe {
        libc::sync();
        // Firecracker exits when the guest reboots (there is no ACPI power
        // button with pci=off), so "reboot" is how the VM says goodbye.
        libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
    }
}
