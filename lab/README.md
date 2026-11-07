# plybox lab

Facts before design. Every security claim plybox makes starts here as a
probe: a small, harmless attempt at one step an attacker inside a sandbox
would take. The lab runs every probe under every sandbox config and prints
which steps worked.

```sh
./run.sh                # all configs, no root needed
./run.sh host tight     # only these
```

Results land in `results/<timestamp>/`: one `.tsv` per config and
`matrix.md`.

## Reading a result

- **OPEN** — the attacker step worked.
- **closed** — it failed.
- **n/a** — this run cannot tell.

`host` (no sandbox) is the control. A probe that is not OPEN on the host
gives no signal on this machine; the matrix marks those with `*`.

## Adding things

- **A probe:** one function and one line in `PROBES` in
  `probe/src/main.rs`. It must be harmless, print no secret contents, and
  remove what it creates.
- **A config:** a `config_<name>` function in `run.sh`, plus its name in
  `ALL`.

## Steps

1. Baseline: the attack suite against existing setups. **Done** — `run.sh`.
   On this machine, full namespaces alone leave 11 of 41 doors open (8 of
   them kernel entry points), and a shared network reopens all 5 network
   doors.
2. Network: a loopback-only box with a proxy outside it, no root. **Done** —
   `net/run.sh`. Result: 0 of 7 network doors open inside the box (public
   TCP, attacker DNS, system DNS, host loopback, host LAN all closed), while
   curl to an allow-listed host, npm to its registry, and a refused denied
   host all behave correctly. The proxy decides by hostname before it
   connects, and logs every allow/refuse (`proxy.jsonl`) — the audit trail.
   No root was used.
3. Kernel surface: syscall allowlist + Landlock. **Done** — `kern/run.sh`,
   enforced by `boxer` (`boxer/`). A seccomp allowlist with an ENOSYS
   default closes all 8 kernel doors that survived step 1 (io_uring,
   userfaultfd, perf, netfilter socket, AF_ALG, AF_VSOCK, ptrace, keyrings)
   and installs the filter (`p.seccomp`), taking the box from 11 open doors
   to 2 — and the two left are step 4's target. `socket` is allowed only for
   UNIX/INET/INET6 and NETLINK_ROUTE; `clone` only without CLONE_NEWUSER;
   `clone3` is off the list so glibc falls back to `clone`. All four
   workloads (curl, npm, denied host, direct TCP) still behave correctly.
   Landlock (ABI best-effort) restricts the filesystem to declared paths as
   a second layer. No root. x86_64 only for now (the allowlist names
   `libc::SYS_*`).
4. Files, secrets, limits. **Done** — `full/run.sh`. The box reaches
   **0 open doors of 41** (1 n/a: no ssh-agent on this host), still with no
   root:
   - *Workspace overlay* (`BOX_OVERLAY=1`): `/work` is an overlay over the
     real directory; writes land in an upper layer only. The two planted
     files (`.git/hooks/pre-commit`, `.claude/settings.json`) are written
     inside but never reach the real workspace — measured on the host after
     the box exits. The upper layer is the review list for a future
     `plybox apply`.
   - *Secrets kept outside* (`--secret NAME=VALUE@HOST`): the box holds a
     placeholder; the proxy terminates TLS for that host only (lab CA, leaf
     per host), swaps the placeholder for the value in the request head, and
     re-encrypts. A TLS upstream that knows the real value reports `key=ok`
     from its own host and `key=placeholder` from any other. Works through
     curl and through node's `fetch` (`NODE_EXTRA_CA_CERTS`). The real value
     never appeared in the box's output, stderr or written files.
   - *Resource limits* via `systemd-run --user --scope -p TasksMax=512
     -p MemoryMax=512M -p OOMPolicy=continue` around the whole box. The
     probes now test actively: fork was refused after 504 extra processes;
     a 1 GiB allocation was OOM-killed at the limit while the box carried on.
     (`OOMPolicy=stop`, systemd's default, killed the entire box on the
     first run — a design fact worth remembering.)
5. Second kernel. **Done** — `gv/run.sh` (gVisor) and `vm/run.sh`
   (Firecracker); binaries via `tools/fetch.sh`. No root for either:
   gVisor runs `--rootless`, Firecracker uses the world-readable `/dev/kvm`.

   **Start latency** (median of 10, spawn → `/bin/true` exits): host 0 ms,
   namespaces 1 ms, namespaces + boxer 2 ms, gVisor 12 ms, Firecracker
   544 ms to init / 726 ms boot+probe+exit (untuned 6.1 CI kernel).

   **gVisor** (`gv.box` = gVisor + proxy + boxer + limits): all 4 workloads
   pass; a TLS fetch costs the same (206 vs 205 ms), npm +34 % (415 vs
   309 ms), tiny operations ~10 ms slower each. Of the 8 kernel doors our
   seccomp allowlist had to close, gVisor's user-space kernel closes 6 by
   simply not implementing them (io_uring, userfaultfd, perf, netfilter
   socket, AF_ALG/AF_VSOCK, keyrings); boxer's seccomp still applies inside
   and closes the rest; Landlock does not exist there (boxer reports
   `NotEnforced`). Read the `gv` column with care: an OPEN door inside
   gVisor (mount, mknod, nested userns, ptrace) leads into the *sentry*, a
   user-space program, not into the host kernel — the probe cannot tell the
   two apart. What is real: `runsc do` exposes the host filesystem
   read-only and, with `--host-uds=all` (needed for the proxy socket),
   every host unix socket incl. the session bus — so `f.secrets` and
   `f.ipc.dbus` read OPEN. That is `do`'s convenience mount policy, not a
   gVisor weakness; a real integration hands runsc an OCI bundle with the
   same mounts as the bwrap box and `--host-uds=open` on one socket.
   Resources: the memory limit bit (OOM kill — of the whole sandbox, since
   the sentry is one host process); `TasksMax` did not stop a 2000-process
   fork inside, because guest processes are not host tasks. The host is
   protected by construction there, but this lab did not measure the
   sentry's own host-thread count.

   **Firecracker**: boots and runs all 41 probes from a 64 MiB ext4 built
   without root (`mkfs.ext4 -d`) and a 40-line PID 1 (`vm/init`). The
   `vm (guest view)` column shows the guest kernel wide open — the probe ran
   as root in a plain Linux. That is the correct reading: a VM protects the
   *host*; it does nothing for what runs *inside* unless the same box layers
   are rebuilt there. No network without root (tap devices), so the proxy
   path is untested in the VM; vsock plumbing would be the next experiment.

   **What works best:** for *your agent with hostile inputs*, the
   namespaces box (step 4): 0 doors, 2 ms, every tool works. gVisor is the
   right second tier when the code itself is untrusted and KVM is absent:
   rootless, 12 ms, a genuine second kernel, modest slowdown, needs the same
   mount policy. Firecracker is the strongest wall at ~0.5 s and needs KVM,
   and still wants a box inside.

## Known limits (updated after step 5)

- **The probe cannot see the boundary it sits behind.** Inside gVisor or a
  VM, "OPEN" means the emulated or guest kernel allowed it, not the host.
  Cross-tier comparisons of the kernel class need that caveat every time.
- **gVisor's `do` mode is not the integration.** Host filesystem read-only,
  all unix sockets with `--host-uds=all`, root with capabilities inside:
  all defaults of the convenience command, all fixable with an OCI bundle.
- **`f.write.*` is an inside view.** Under gVisor's overlay the write
  succeeds inside and never reaches the host (verified by hand); the probe
  needs a host-side check like the one `f.inject.*` already has.
- **Firecracker here has no network and no in-guest box.**

- **Secret substitution is deliberately narrow.** It rewrites the request
  head only, forces one request per connection (`Connection: close`),
  speaks HTTP/1.1, and terminates TLS only for hosts that carry a secret.
  Websockets, HTTP/2 and request bodies are untouched.
- **Proxy log noise.** Each box start pokes the forwarder once to see it is
  up; that reaches the proxy as an empty request and is logged as
  `refused: request head missing`. Harmless, but it inflates the refused
  count by one per box.
- **Limits are per box, not per process.** `MemoryMax` covers bwrap, the
  forwarder and the workload together; the kernel chooses what to kill.
- **Exfiltration through an allowed host is not stopped.** The proxy caps
  nothing: data can leave inside a legitimate-looking request to any name
  on the allow list. This is inherent to name-based allowlisting.
- **No IP pinning.** The proxy connects to whatever an allowed name resolves
  to (public addresses only); client TLS validation is what catches a DNS
  compromise.
- **`ioctl` is allowed for every request code.** Wider than the rest of the
  allowlist; `--new-session` blocks the classic TIOCSTI trick, but this
  deserves its own probe and a request-code filter.
- **Landlock's in-box effect is unverified.** It is on and works on the host,
  but no probe yet shows it closing a door the mount namespace had not
  already closed.
- **The socat forwarder runs unconfined** inside the box (it must outlive
  boxer). Real plybox should confine or replace it.
- 13 of 41 probes give no signal on this machine (IPv6, cloud metadata,
  anything needing root).

## Comparison with other sandboxes (`compare/run.sh`)

Same 41 doors, same workloads, each tool with its own defaults plus the same
allow list (api.anthropic.com, *.anthropic.com, registry.npmjs.org).
Binaries pinned in `tools/fetch.sh`: Anthropic sandbox-runtime 0.0.81,
Greywall 0.3.7 + greyproxy 0.4.5. One machine, one day; not an audit.

| | host | ours (box.full) | ours (gv.box) | srt | greywall |
|---|---:|---:|---:|---:|---:|
| open doors of 41 | 28 | **0** | 7 | 10 | 12 |
| start latency (median) | 0 ms | 2 ms | 12 ms | 91 ms | 1248 ms |
| workloads correct | — | 4/4 | 4/4 | 4/4 | 4/4 (each ~2 s) |

- **srt** closes the network completely (it removes the network namespace,
  as we do) and keeps planted files off the host, but reads the host home
  by default (`.ssh`, Claude credentials, shell history), leaves 6 kernel
  doors open (userfaultfd, perf, netfilter socket, AF_ALG, ptrace,
  keyrings — its seccomp filter targets unix sockets and nested userns, not
  the kernel surface), and has no resource limits.
- **Greywall** denies credential files and git hooks by default (good
  mandatory rules) and has a learning mode, but routes traffic through a
  TUN device: 1.2 s per start, the agent keeps CAP_NET_ADMIN inside, nested
  user namespaces and io_uring stay open, its DNS proxy resolves arbitrary
  names (data can leave inside names), the agent-settings file landed on the
  host, a session-bus socket was reachable (possibly its xdg-dbus-proxy —
  unverified), and no resource limits.
- **Ours** closes everything measurable at 2 ms, because three things the
  others lack are first-class: a syscall allowlist, a workspace that is a
  copy by construction, and cgroup limits.

**A probe fix the comparison forced.** A bare `connect()` always succeeds
behind a TUN device (the device completes the handshake before any policy
runs), so `n.tcp.*` and `n.host.*` now require a reply, and the host
stand-in listeners answer. Fairer to every tool, ours included.

**What the build should borrow:** Greywall's mandatory denies and learning
mode (audit → profile → enforce; ply had this for egress); srt's settings
schema (`allowedDomains`, `allowWrite`, `denyRead`) as an input format
people already know.

Not compared: Docker Sandboxes (needs KVM and a Docker account) and nono.

## The binary (`v0/run.sh`)

Runs the real `plybox` against the same 41 probes and workloads and diffs it
against the lab's proven bwrap+boxer box. Slice 1 (2026-11-06): identical on
every measurable door, 0 kernel / 0 process / 0 network doors, 2 ms start;
still open: the two planted-file probes and the two resource probes — the
targets of slices 2–3.

Slices 2–3 (2026-11-07): secrets substituted at the proxy (TLS terminated
per secret host, verified through curl and node), copy-on-write workspace
(`plybox diff`/`apply`; the planted files stay in the session), and cgroup
limits (direct when the kernel allows, else `systemd-run --user`). Result:
**0 open doors of 41** for the binary, all 7 workloads correct, 3 ms start.
Untested so far: `apply` of a deletion (overlay whiteout) — the smoke test
that would have covered it was blocked by a safety check on `rm` in a
script and was not run.

Slice 4 (2026-11-07): `--isolation gvisor`. plybox writes a real OCI bundle
(same mounts as the bubblewrap box, no host filesystem, only the proxy's
socket directory, uid with no capabilities, `--host-uds=open`,
`--overlay2=root:memory`, RLIMIT_NPROC from `--pids`). Result: **0 open
doors of 41** in the gVisor tier too, all 7 workloads correct, 19 ms start.
Three facts learned the hard way: an overlay over every mount copies the
proxy socket up into memory and kills it (rootfs-only overlay instead); a
unix-socket connect needs write permission and gVisor enforces it, while
our files appear root-owned inside, so the socket is world-connectable
behind a 0700 sessions base; a host cgroup's pids.max does not bound
guest processes, but RLIMIT_NPROC inside the sandbox does (fork refused at
508 of 512). In this tier the workspace is read-only unless
`--workspace-mode bind`.
