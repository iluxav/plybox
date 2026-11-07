# Steady-state overhead

Run `make bench` on a Linux host with the build dependencies, bubblewrap,
util-linux `unshare`, Python 3.11+, OpenSSL, and a working systemd user
manager. It takes about 20–25 minutes. After the build, all traffic is to
a local HTTPS fixture: no model credentials, DNS or internet endpoints.
Do not run other benchmarks or builds alongside it.

Results go to `tests/results/bench-<UTC timestamp>/`: `machine.json`, one
validated trial per line in `raw.jsonl`, a machine-readable `summary.json`,
`report.md`, and stderr logs. A failure stops the run rather than timing
an unsuccessful operation. Temporary scopes, fixtures and sessions are
cleaned up. Record dated findings and interpretations in `docs/research.md`.

## Workloads

Each case runs five times under host, namespace isolation, and default
embedded gVisor. Tier order rotates each trial. Defaults:

- Agent: 500 sequential HTTPS POSTs with a small JSON request and a 16,335
  byte JSON response. Ordinary CONNECT and TLS termination with verified
  placeholder substitution are separate cases. Each request makes a new
  TCP/TLS connection in every tier, since the terminated proxy deliberately
  closes connections after one request. The SSL context is reused.
- Stream: the same response in eight HTTP chunks with seven 1 ms gaps.
  Latency means receipt and validation of the complete JSON response,
  not time to first token. This is a fast synthetic stream, not inference.
- Throughput: one 200,000,000-byte HTTPS download and upload over CONNECT;
  a 200,000,000-byte terminated download and 32,000,000-byte terminated
  upload. The latter stays below the proxy's intentional 64 MiB request
  cap. Host baselines transfer the same byte count directly. Units are
  decimal MB/s and CPU seconds per decimal GB.
- Service: one Python HTTP server process and one persistent, sequential
  client in the same box, 10,000 loopback requests, ~1 KiB JSON replies.
  Both processes are counted. This is concurrency one, without TLS or
  the proxy; it measures the currently supported in-box service path.
- CPU: 100,000 fixed JSON encode/decode cycles over a 16-message object.
- Files: 20,000 write/read/unlink cycles over a 4 KiB file in `/tmp`, no
  fsync. The host's `/tmp` filesystem type is recorded; the measured host
  uses tmpfs, matching the boxes' scratch storage.
- Idle: an actual `sleep` (no resident Python helper) for 60 seconds,
  five trials per tier. Then ten simultaneous independent boxes, five
  trials per tier, with a 10-second memory sampling window. Each trial
  settles for two seconds before accounting and samples memory six times.

For development, shorten a run explicitly, e.g.:

```sh
make bench BENCH_ARGS='--repeats 1 --requests 5 --transfer-bytes 1000000 --secret-upload-bytes 1000000 --service-requests 50 --cpu-iterations 1000 --file-iterations 100 --idle-seconds 1 --multi-idle-seconds 1'
```

Use `--cases agent-tunnel,agent-secret` or `--tiers host,gvisor` to select
cases. Short runs validate the harness; they are not the published sample.
The underlying command is `python3 tests/bench/run.py PATH_TO_PLYBOX`.

## Accounting and interpretation

Each invocation runs in its own `systemd-run --user --scope` with memory
accounting enabled. The harness reads cgroup v2 `cpu.stat`'s `usage_usec`,
not the workload's getrusage. Scope membership captures plybox's
supervisor/proxy, bubblewrap or runsc launcher, gofer, sentry, systrap
processes, in-box forwarder and workload, including daemonized children.
The external HTTPS fixture and the measurement controller are outside
the scope. Snapshots preserve every PID/command and check that gVisor's
sentry and gofer are present. No plybox cgroup limit flags are set, so
processes cannot move into separate systemd limit scopes.

Imports, sandbox startup, extraction, runtime hashing, certificate setup,
and warmup are before the READY/GO barrier. CPU is the scope delta from
GO to DONE; wall time is measured inside the workload. Workloads wait
after DONE so counters are read before process teardown. There is no
CPU affinity or frequency override. Run metadata records the machine,
kernel, CPU governor, binary hash, plybox commit and benchmark source hashes.

Memory includes all processes. Summed `/proc/PID/smaps_rollup` PSS is the
primary density metric: it apportions shared resident pages. Summed RSS
is also reported and double-counts shared pages. `memory.current` and
`memory.peak` are retained for comparison, but cgroup file-cache charging
and startup peaks are not equivalent to steady-state PSS. In ten-box
trials, the PSS/RSS and CPU of all ten independent scopes are summed.
The boxes run as one host user and share one extracted runtime cache,
matching the current default deployment; separate users/caches can share
less physical memory.
If any smaps read fails, the aggregate RSS/PSS is marked unavailable,
never silently reported as a partial tree. Cgroup accounting is required;
the harness stops if it cannot get it rather than substituting an
incomplete process tree.

Every table cell is the median and min–max across five trials. p50/p99
are calculated within each trial first, not pooled across trials. CPU
seconds may exceed wall seconds because multiple box processes run at
once. Idle CPU is the actual cgroup delta during the stated window;
zero means no increment in the microsecond counter. Boxes per GiB from
ten-box PSS is a memory-only extrapolation, with no workload headroom,
kernel/cgroup overhead budget, or claim that loaded boxes cost the same.
