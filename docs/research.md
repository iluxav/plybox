> **Historical record.** This is the research log that shaped plybox: each
> design decision was measured here first. The research scripts it names
> (`run.sh`, `net/`, `kern/`, `full/`, `gv/`, `vm/`, `compare/`, `boxer/`)
> were removed once the binary replaced them; they remain in git history.
> The suites still in use live in `tests/` — see the README.
> The early measurements predate the default-tier change: new runs now use
> gVisor; namespace overlays require explicit `--isolation ns`. The dated
> steady-state benchmark below measures the current embedded default.

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
- **Historical gap, now narrowed:** `ioctl` originally allowed every
  request code. The workload now uses an exact-request filter, tested with
  harmless denied requests and real terminal I/O. See [current limits](limits.md)
  for this filter and the storage/traffic controls.
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

Slice 5 (2026-11-07): `--learn [FILE]`. The proxy lets every public
destination through, records each (verdict `learned` in the record), and
at exit writes the policy the run would have needed — the given policy
with the observed hosts merged into `net.allow`, secrets by name only. The
run announces loudly that it is not contained. Smoke: a learn run reached
two hosts and wrote them; the next run with `--policy` allowed those two
and refused a third. The full suite is unchanged: 0 open doors, both tiers.

Images (2026-11-07, `image/run.sh`): `plybox pull` / `--image` make an OCI
image the box's root, no Docker. Every layer is sha256-verified; paths that
leave the rootfs (`..`, through a planted symlink, a hardlink to a host
file) are refused before anything is written or deleted — ply's importer
lacked those checks — and setuid bits are dropped (unit tests in
`plybox/src/image.rs`). Inside `python:3.13-slim`: **0 open doors** in both
tiers, workloads pass, 3 ms / 18 ms start once cached. Facts learned:
bubblewrap cannot create mount points in a read-only image (fixed with
`--tmp-overlay /` over the image); the binary must be static to run inside
images (static glibc broke DNS on the host side; static musl works, with
the host gcc for ring/zstd); gVisor creates missing mount points in the
image directory itself (plybox now creates its fixed ones once, at pull).

Sessions (2026-11-07, `sessions/run.sh`): `plybox sessions`, `discard`,
`sessions --prune`; `apply` marks a session applied. 12 checks pass,
including `apply` of a deletion (untested until now) and two apply-safety
cases: a repo symlink pointing out of the workspace is replaced, not written
through — the previous build (b85fb87) wrote through it and overwrote the
outside file, measured — and a tampered upper layer that would write under a
directory symlink pointing out is refused before anything is applied.

## 2026-11-07: gVisor bind workspace ownership

The old `runsc --rootless` invocation mapped the host caller to UID/GID 0,
while the OCI process used the caller's original IDs. A caller-owned 0755
workspace appeared root-owned and `touch /work/x` failed; owner-only files
were unreadable too.

The fix enters an outer user namespace using util-linux `unshare` with
`--user --map-current-user --keep-caps --net` and supplies matching
single-ID mappings in the OCI bundle. Setup capabilities belong to the runtime's user namespace; the
workload still has empty capability sets and no_new_privs. Retaining a
non-root workload matters for RLIMIT_NPROC. See the upstream
[discussion of preserving the caller's identity](https://github.com/google/gvisor/issues/13564)
and [rootless behavior](https://gvisor.dev/docs/user_guide/rootless/).

`tests/policy/gvisor.py` reproduces the old failure and checks bind edits,
private files, unchanged host permissions, read-only mounts, proxy access,
workload restrictions and a bounded process-limit test. The default
gVisor workspace remains read-only; staged edits are still unsupported.
The identity fix also removes the need for world-connectable proxy sockets.

Earlier throughput measurements on this machine (12 cores, writes in tmpfs):
`npm ci` of 6,886 files took 0.56 s (namespaces) versus 1.03 s (gVisor);
a debug `cargo build` of plybox took 6.3 s (host/namespaces) versus 8.8 s
(gVisor). These are historical measurements, not a benchmark of this fix.

Validation on runsc release-20261102.0: ownership checks pass with host
Python and `python:3.13-slim`; 26 unit, 35 policy, 26 session, 35 resume,
and 13 limits checks pass. The security suite used a synthetic home and
credentials: 40/41 probes blocked in both tiers, with the SSH-agent probe
unavailable (no SSH agent); all seven network/secret workloads pass in each
tier. The measured startup median was 21 ms for gVisor and 4 ms for the
namespace tier (10 runs each). These probes are regression checks, not a
proof of isolation against every possible attack.


## 2026-11-07: steady-state overhead with embedded gVisor

Python API calls pay about 1–1.2 ms extra on gVisor; the whole box uses 3.4–3.5 CPU seconds per 1,000 requests versus 0.48 on the host.
Seven milliseconds of streaming gaps reduce the relative latency penalty to 13%; real model inference and internet latency were not measured.
The loopback service delivers 10,798 requests/s at 0.216 ms p99, about half the host throughput and 4.3× its CPU use.
JSON computation is essentially unchanged; tmpfs file work takes 5.34× as long and uses 11.90× the CPU.
Ten sleeping boxes use 333 MiB PSS, about 31/GiB before headroom; one idle box uses 0.177 ms CPU per minute.

### Machine and method

- AMD Ryzen 5 9600X: 6 physical cores, 12 logical CPUs; 60.48 GiB RAM.
  Linux `7.2.15-1-omarchy`, x86_64; `performance` CPU governor, boost enabled,
  no CPU affinity or frequency changes. This was a live desktop, not an
  otherwise empty machine.
- plybox `8b480a7023b445cfbf879f57f3f884f5ff184b63`, static musl release;
  embedded gVisor `release-20261102.0`, default `systrap` platform.
  Python 3.14.8, OpenSSL 3.6.5, bubblewrap 0.13.1. All HTTPS clients
  negotiated TLS 1.3 / `TLS_AES_256_GCM_SHA384`.
- Reproduce with `make bench` (this run: 22.2 minutes). Workloads and
  controls are in [tests/bench](../tests/bench/README.md). The benchmark
  used only a local HTTPS fixture mapped by test-only `net.map`; the host
  baseline connected directly to that same fixture. No real credentials,
  model API, DNS or internet requests were involved.
- Five trials per case/tier, 195 trials total. Tier order rotates. Each
  cell below is **median [minimum–maximum]** across the five trials;
  request p50/p99 are computed inside each trial before taking that median.
- Every invocation has its own systemd user scope. CPU is the delta of
  cgroup v2 `cpu.stat usage_usec` around the measured work. It includes
  the supervisor/proxy, launcher, gofer, sentry, systrap processes, forwarder
  and workload. In the service case it includes both client and server.
  The fixture server and measurement controller are outside the scope.
- READY/GO/DONE barriers exclude process/sandbox startup, runtime
  extraction/hash checks, imports, certificate setup and warmup. Counters
  are read before process teardown. API trials warm up 20 requests;
  transfer trials warm up 1 MB; service trials warm up 30 requests.
  No plybox resource-limit flags move descendants into another scope.
- Raw process membership, per-process RSS/PSS, cgroup counters, audit
  checks and stderr logs remain in `tests/results/bench-20261107T223654Z/`.
  [Committed trial metrics and machine metadata](bench-2026-11-07.json)
  preserve all 195 trials, source hashes, parameters and the binary hash.
  All measured gVisor invocations selected the embedded runtime. Responses,
  byte counts, secret substitution and proxy modes were checked, with no
  fixture errors. Cgroup accounting and all smaps reads were available;
  no partial-tree fallback was used.

### Python agent loop: small JSON and streaming responses

500 sequential POSTs per trial, small JSON request, 16,335-byte JSON
response. `JSON` returns it immediately; `stream` uses eight HTTP chunks
with seven 1 ms gaps. Latency includes receiving and validating the whole
response, not time to first token. `secret` verifies placeholder replacement
at the TLS-terminating proxy. All three tiers create a fresh TCP/TLS
connection per request, with a reused SSL context: the terminated proxy
currently closes after one request. This comparison does not measure the
advantage that connection pooling could give direct/CONNECT clients.
CPU milliseconds/request is numerically CPU seconds/1,000 requests.

| Case / metric | Host | Namespace | gVisor |
|---|---:|---:|---:|
| JSON, CONNECT — p50 ms | 0.766 [0.763–0.783] | 0.996 [0.986–1.019] | 1.775 [1.768–1.785] |
| JSON, CONNECT — p99 ms | 0.997 [0.987–1.322] | 1.229 [1.217–1.250] | 2.282 [2.203–3.089] |
| JSON, CONNECT — requests/s | 1269.3 [1254.2–1292.0] | 998.4 [980.7–1008.2] | 554.3 [546.2–560.0] |
| JSON, CONNECT — CPU ms/request | 0.476 [0.473–0.485] | 0.857 [0.849–0.876] | 3.366 [3.331–3.382] |
| JSON, secret — p50 ms | 0.776 [0.768–0.786] | 1.194 [1.177–1.205] | 1.951 [1.919–2.004] |
| JSON, secret — p99 ms | 0.999 [0.937–1.252] | 1.428 [1.416–1.881] | 3.067 [2.434–3.706] |
| JSON, secret — requests/s | 1278.3 [1240.1–1285.1] | 835.7 [815.1–842.8] | 502.8 [477.7–514.3] |
| JSON, secret — CPU ms/request | 0.476 [0.474–0.493] | 1.046 [1.037–1.065] | 3.477 [3.423–3.627] |
| Stream, CONNECT — p50 ms | 8.328 [8.326–8.357] | 8.622 [8.617–8.625] | 9.284 [9.270–9.319] |
| Stream, CONNECT — p99 ms | 8.630 [8.545–9.024] | 9.624 [9.181–9.728] | 10.489 [10.382–10.823] |
| Stream, CONNECT — requests/s | 119.9 [119.4–119.9] | 115.6 [115.6–115.7] | 107.1 [106.7–107.3] |
| Stream, CONNECT — CPU ms/request | 0.629 [0.623–0.658] | 1.086 [1.081–1.090] | 4.320 [4.312–4.367] |
| Stream, secret — p50 ms | 8.331 [8.321–8.338] | 8.808 [8.802–8.813] | 9.430 [9.424–9.450] |
| Stream, secret — p99 ms | 9.003 [8.908–9.188] | 9.555 [9.110–9.728] | 10.597 [10.186–10.898] |
| Stream, secret — requests/s | 119.8 [119.6–119.9] | 113.2 [113.1–113.4] | 105.5 [105.3–105.8] |
| Stream, secret — CPU ms/request | 0.628 [0.626–0.640] | 1.264 [1.251–1.269] | 4.422 [4.373–4.497] |

### Proxy throughput

One transfer per trial, without a disk source/sink: 200 MB download and
upload through CONNECT; 200 MB secret-bearing download; 32 MB
secret-bearing upload. The host does the identical transfer directly.
Secret-bearing requests are deliberately buffered and capped at 64 MiB,
so a single 200 MB terminated upload is outside the supported path; the
32 MB case measures its supported throughput. MB and GB here are decimal.
CPU seconds/GB includes every box process and excludes the fixture server.
These short, memory-to-memory loopback transfers are not WAN bandwidth.

| Case / metric | Host | Namespace | gVisor |
|---|---:|---:|---:|
| CONNECT download, 200 MB — MB/s | 5701.6 [4868.0–5967.3] | 4629.8 [3894.0–5171.5] | 984.4 [975.2–997.8] |
| CONNECT download, 200 MB — CPU s/GB | 0.158 [0.152–0.186] | 0.449 [0.411–0.525] | 3.281 [3.239–3.320] |
| CONNECT upload, 200 MB — MB/s | 5879.7 [4417.5–6192.0] | 5392.3 [4925.4–5681.5] | 1025.4 [510.8–1055.2] |
| CONNECT upload, 200 MB — CPU s/GB | 0.120 [0.117–0.159] | 0.428 [0.391–0.471] | 3.091 [3.019–3.123] |
| Secret download, 200 MB — MB/s | 5961.2 [5757.6–6060.2] | 2407.1 [2332.5–2457.7] | 976.5 [899.5–995.7] |
| Secret download, 200 MB — CPU s/GB | 0.152 [0.149–0.155] | 0.723 [0.702–0.737] | 3.622 [3.534–3.752] |
| Secret upload, 32 MB — MB/s | 4658.8 [4493.4–5164.3] | 662.8 [619.6–692.1] | 426.5 [408.9–451.1] |
| Secret upload, 32 MB — CPU s/GB | 0.149 [0.141–0.152] | 1.764 [1.707–1.875] | 4.883 [4.629–4.934] |

One gVisor CONNECT upload reached only 510.8 MB/s, about half the median,
while its CPU/GB remained close to the other trials. It is retained in the
range above. No trace was collected to attribute that wall-time stall.

### In-box HTTP service

A Python HTTP server and a separate client both run in the same box over
loopback: one persistent connection, 10,000 sequential requests, ~1 KiB
JSON replies. Both processes' CPU is counted. This is concurrency one,
without TLS, proxying or inbound host ports. It is not a maximum-concurrency
service-capacity test.

| Case / metric | Host | Namespace | gVisor |
|---|---:|---:|---:|
| Requests/s | 22347.5 [21482.4–22437.7] | 22397.2 [22155.8–23101.3] | 10798.4 [10694.2–11023.8] |
| p99 ms | 0.127 [0.105–0.128] | 0.116 [0.094–0.124] | 0.216 [0.213–0.219] |
| CPU ms/request | 0.0485 [0.0483–0.0513] | 0.0493 [0.0469–0.0496] | 0.2069 [0.2037–0.2086] |

### CPU and filesystem work

CPU: 100,000 fixed Python JSON encode/decode cycles over a 16-message
object. Files: 20,000 write/read/unlink cycles of a 4 KiB file in `/tmp`,
without fsync. `/tmp` is tmpfs on the host and in both box tiers, so this
compares syscall/metadata work, not disk hardware. Ratios are ratios of
medians; the full range of each time/CPU measurement is shown.

**JSON CPU loop**

| Case / metric | Host | Namespace | gVisor |
|---|---:|---:|---:|
| Wall time, s | 1.112 [1.102–1.121] | 1.113 [1.098–1.137] | 1.108 [1.097–1.129] |
| Whole-box CPU, s | 1.109 [1.100–1.119] | 1.110 [1.096–1.134] | 1.110 [1.099–1.131] |
| Wall time / host | 1.000× | 1.001× | 0.996× |
| CPU / host | 1.000× | 1.001× | 1.000× |

**Small-file loop**

| Case / metric | Host | Namespace | gVisor |
|---|---:|---:|---:|
| Wall time, s | 0.122 [0.120–0.126] | 0.127 [0.125–0.128] | 0.651 [0.646–0.660] |
| Whole-box CPU, s | 0.119 [0.117–0.123] | 0.124 [0.122–0.126] | 1.414 [1.404–1.436] |
| Wall time / host | 1.000× | 1.038× | 5.343× |
| CPU / host | 1.000× | 1.044× | 11.901× |

### Idle CPU and memory

Actual `sleep` workloads, with no resident Python measurement helper.
Single-box trials settle for two seconds and run for 60 seconds; ten-box
trials settle after all ten have started and sample for 10 seconds.
Each trial takes six memory snapshots and uses their median, then the
five trial medians are summarized below. Idle CPU is the scope-counter
delta over the stated window; zero means no microsecond-counter increment.

PSS from every process's `smaps_rollup` is the primary density metric.
RSS is also summed, but double-counts shared pages. Cgroup memory.current
is shown separately: file-cache charging to the original cgroup can make
it differ substantially from PSS. Startup memory.peak is preserved in the
JSON but is not used as steady-state memory. Shared code explains why ten
boxes cost less than ten times the PSS of a box running alone. All ten
run as the same host user and share the extracted runtime cache; separate
users with separate caches may share less memory.

| Case / metric | Host | Namespace | gVisor |
|---|---:|---:|---:|
| One box — CPU ms/60s | 0.000 [0.000–0.000] | 0.000 [0.000–0.000] | 0.177 [0.137–0.198] |
| One box — RSS MiB | 2.29 [2.27–2.29] | 13.52 [13.51–13.54] | 84.47 [82.32–87.07] |
| One box — PSS MiB | 0.22 [0.22–0.24] | 6.73 [6.71–6.74] | 67.62 [65.65–70.27] |
| One box — cgroup memory.current MiB | 0.20 [0.19–0.20] | 5.34 [5.33–5.36] | 33.45 [31.33–35.45] |
| Ten boxes, total — CPU ms/10s | 0.000 [0.000–0.000] | 0.000 [0.000–0.000] | 0.000 [0.000–0.000] |
| Ten boxes, total — RSS MiB | 22.89 [22.86–22.90] | 133.19 [131.24–135.27] | 857.20 [838.55–867.57] |
| Ten boxes, total — PSS MiB | 1.48 [1.47–1.49] | 46.22 [44.21–48.21] | 333.03 [316.66–343.17] |
| Ten boxes, total — cgroup memory.current MiB | 1.91 [1.90–1.92] | 51.41 [49.35–53.39] | 334.01 [318.11–344.57] |

The ten-box PSS median implies 33.30 MiB per sleeping gVisor
box and 30.7 such boxes per GiB. This is a memory-only
extrapolation on this CPU/core configuration, not a supported tenant
count: loaded Python heaps, request buffers, kernel memory, CPU and
operating-system headroom still need a budget. No real provider latency,
external inbound service path, high-concurrency load, or other machine
was measured. No production source changes were needed.
