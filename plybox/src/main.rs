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
mod limits;
mod policy;
mod proxy;
mod record;
mod seccomp;
mod secrets;
mod workspace;

use std::process::exit;

fn usage() -> ! {
    eprintln!(
        "usage: plybox run [--policy FILE] [--rootfs host|DIR] [--work DIR] [--workspace-mode overlay|bind]\n\
         \x20                 [--allow HOST[:PORT]]... [--secret NAME[=VALUE]@HOST]... [--ro-bind HOST:BOX]...\n\
         \x20                 [--env K=V | --env K]... [--mem SIZE] [--pids N] [--cpu CORES]\n\
         \x20                 [--session DIR] [--quiet] -- COMMAND [ARGS...]\n\
         \x20      plybox diff  SESSION|--last     what the box changed in its workspace copy\n\
         \x20      plybox apply SESSION|--last     copy those changes onto the real workspace\n\
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
        Some("diff") | Some("apply") => {
            let which = args[0].as_str();
            let target = args.get(1).map(String::as_str).unwrap_or("--last");
            let session = workspace::Session::open(target).unwrap_or_else(|e| {
                eprintln!("plybox: {e}");
                exit(1)
            });
            let result = if which == "diff" { session.changes() } else { session.apply() };
            match result {
                Ok(changes) => {
                    workspace::print_changes(&changes);
                    if which == "apply" {
                        eprintln!("plybox: applied {} change(s) to {}", changes.len(), session.workspace.display());
                    }
                }
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
