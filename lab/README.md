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
4. Files and secrets: workspace overlay (changes land on the host only on
   apply), secrets added at the proxy so they never enter the box. Targets:
   the two doors still open after step 3 — `f.inject.githook`,
   `f.inject.agentcfg` — and keeping credential files unreadable.
5. Second kernel: the same probes under gVisor and KVM, with start time and
   overhead measured.

## Known limits (from the step-3 review)

- **No resource limits yet.** `q.pids` / `q.mem` read n/a inside every box:
  the probe cannot see cgroups from inside, and bubblewrap sets none. A
  runaway process in the box can still exhaust the host. Reports show n/a
  separately from closed for exactly this reason. Needs real cgroup limits
  plus a probe that measures them (step 4/5).
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
