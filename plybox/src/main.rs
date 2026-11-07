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

mod gvisor;
mod image;
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
        "usage: plybox run [--policy FILE] [--image IMAGE] [--isolation ns|gvisor] [--runsc PATH]\n\
         \x20                 [--rootfs host|DIR] [--work DIR] [--workspace-mode overlay|bind]\n\
         \x20                 [--allow HOST[:PORT]]... [--secret NAME[=VALUE]@HOST]... [--secret-file NAME=PATH@HOST]... [--ro-bind HOST:BOX]...\n\
         \x20                 [--env K=V | --env K]... [--mem SIZE] [--pids N] [--cpu CORES]\n\
         \x20                 [--learn [FILE]] [--session DIR] [--quiet] -- COMMAND [ARGS...]\n\
         \x20      plybox pull IMAGE               fetch an OCI image (e.g. python:3.13-slim) for --image\n\
         \x20      plybox images                   list pulled images\n\
         \x20      plybox sessions [--prune]       list sessions and their status; --prune removes applied/empty ones\n\
         \x20      plybox discard SESSION|--last   delete a session and its unapplied changes\n\
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
            let (pol, cmd, opts) = policy::from_args(&args[1..]).unwrap_or_else(|e| {
                eprintln!("plybox: {e}");
                usage()
            });
            match launch::run(pol, cmd, opts) {
                Ok(code) => exit(code),
                Err(e) => {
                    eprintln!("plybox: {e}");
                    exit(1)
                }
            }
        }
        Some("pull") => {
            let Some(spec) = args.get(1) else { usage() };
            let dir = image::images_base().join(image::slug(spec));
            match image::pull(spec, &dir, false) {
                Ok(img) => println!("{}  {}", img.meta.reference, img.meta.digest),
                Err(e) => {
                    eprintln!("plybox: {e}");
                    exit(1)
                }
            }
        }
        Some("images") => {
            for m in image::list() {
                println!("{:<40} {}", m.reference, &m.digest[..19.min(m.digest.len())]);
            }
        }
        Some("sessions") => {
            if args.get(1).map(String::as_str) == Some("--prune") {
                let removed = workspace::prune();
                for (id, why) in &removed {
                    println!("removed {id}  ({why})");
                }
                println!("{} session(s) removed; pending and running sessions kept", removed.len());
            } else {
                let all = workspace::list();
                if all.is_empty() {
                    println!("(no sessions)");
                }
                for i in &all {
                    let age = workspace::now().saturating_sub(i.meta.last_started.max(i.meta.started));
                    let age = if age < 3600 { format!("{}m", age / 60) } else if age < 86400 { format!("{}h", age / 3600) } else { format!("{}d", age / 86400) };
                    let cmd: String = i.meta.cmd.join(" ").chars().take(48).collect();
                    println!("{:<18} {:>4} ago  {:<12} {}  — {}", i.id, age, i.status(), i.meta.workspace.display(), cmd);
                }
                let pending = all.iter().filter(|i| i.pending()).count();
                if pending > 0 {
                    println!("\n{pending} session(s) hold changes never applied: `plybox diff ID`, then `plybox apply ID` or `plybox discard ID`");
                }
            }
        }
        Some("discard") => {
            let target = args.get(1).map(String::as_str).unwrap_or("--last");
            match workspace::resolve(target).and_then(|dir| workspace::discard(&dir).map(|_| dir)) {
                Ok(dir) => println!("discarded session {}", workspace::session_name(&dir)),
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
            let name = workspace::session_name(&session.dir);
            if name != target {
                eprintln!("plybox: session {name}");
            }
            let result = if which == "diff" { session.changes() } else { session.apply() };
            match result {
                Ok(changes) => {
                    workspace::print_changes(&changes);
                    if which == "apply" {
                        eprintln!("plybox: applied {} change(s) from session {} to {}", changes.len(), name, session.workspace.display());
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
