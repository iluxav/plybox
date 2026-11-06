# plybox

Run an AI agent in a box whose only way out is through plybox.

- **Files**: the box sees the host's tools read-only (or a directory you
  give it) and one writable workspace at `/work`. Your home does not exist
  inside.
- **Network**: the box has loopback only. Its one exit is plybox's proxy,
  which allows destinations **by hostname** and refuses everything else —
  including public names that resolve to private addresses.
- **Kernel**: a seccomp allowlist (default `ENOSYS`) and Landlock around the
  workload. Nested user namespaces, io_uring, ptrace, keyrings, raw and
  exotic sockets are gone.
- **Record**: every connection decision and the session's start and exit,
  one JSON line each.

No root. No daemon. Namespaces come from bubblewrap, the same engine
Anthropic's sandbox-runtime and Greywall use; everything around it is
plybox.

```sh
cd plybox && cargo build --release
plybox run --allow api.anthropic.com --allow registry.npmjs.org -- claude -p "fix the tests"
plybox run --policy agent.toml -- sh
```

```toml
# agent.toml
[fs]
rootfs    = "host"
workspace = "."
ro_bind   = ["/home/me/.local/share/mise/installs/node:/opt/node"]
[net]
allow = ["api.anthropic.com", "*.anthropic.com", "registry.npmjs.org"]
[env]
PATH = "/opt/node/latest/bin:/usr/local/bin:/usr/bin:/bin"
```

## Status

Slice 1. Measured by `lab/v0/run.sh` against 41 attacker probes: the
binary reproduces the lab's proven box — 0 kernel doors, 0 process doors,
0 network doors, 2 ms start — with four doors still open that the next
slices close:

2. secrets kept outside the box, substituted at the proxy;
3. copy-on-write workspace (`plybox diff` / `apply`) and cgroup limits;
4. gVisor tier for untrusted code; learning mode (audit → policy).

Everything claimed here has a probe in `lab/`. Read `lab/README.md`.

Requires: Linux x86_64, bubblewrap, unprivileged user namespaces.
