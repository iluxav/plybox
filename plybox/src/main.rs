//! plybox — run an AI agent in a box whose only way out is through plybox.
//!
//! Slice 1 (this file set): `plybox run` builds the box the lab proved —
//! own user/mount/pid/net/ipc/uts namespaces, loopback-only network, a
//! hostname-deciding CONNECT proxy outside the box reached over a unix
//! socket, a seccomp allowlist and Landlock around the workload, and a
//! JSONL record of the session. Secrets, the copy-on-write workspace,
//! limits and the gVisor tier follow as later slices, each gated by the
//! probe suite in `lab/`.
//!
//! Process tree:
//!
//!   plybox run (supervisor: proxy threads, record)
//!   └─ bwrap (namespaces, mounts, loopback-only network)
//!      └─ plybox __inner (forwarder 127.0.0.1:3128 → proxy socket, reaper)
//!         └─ the workload: landlock + no_new_privs + seccomp, then exec

mod inner;
mod landlock_fs;
mod launch;
mod policy;
mod proxy;
mod record;
mod seccomp;

use std::process::exit;

fn usage() -> ! {
    eprintln!(
        "usage: plybox run [--policy FILE] [--rootfs host|DIR] [--work DIR] [--allow HOST[:PORT]]...\n\
         \x20                 [--ro-bind HOST:BOX]... [--env K=V | --env K]... [--session DIR] [--quiet]\n\
         \x20                 -- COMMAND [ARGS...]\n\
         \x20      plybox version"
    );
    exit(2)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => {
            let (pol, cmd, session, quiet) = policy::from_args(&args[1..]).unwrap_or_else(|e| {
                eprintln!("plybox: {e}");
                usage()
            });
            match launch::run(pol, cmd, session, quiet) {
                Ok(code) => exit(code),
                Err(e) => {
                    eprintln!("plybox: {e}");
                    exit(1)
                }
            }
        }
        Some("__inner") => match inner::main(&args[1..]) {
            Ok(code) => exit(code),
            Err(e) => {
                eprintln!("plybox: {e}");
                exit(1)
            }
        },
        Some("version") => println!("plybox {}", env!("CARGO_PKG_VERSION")),
        _ => usage(),
    }
}
