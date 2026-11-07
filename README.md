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
- **Secrets**: never inside. The box holds a placeholder; the proxy
  terminates TLS for the one host a secret belongs to, swaps the real value
  in, and re-encrypts. Any other host receives the worthless placeholder.
- **Workspace**: a copy. The box writes to an overlay; nothing reaches your
  directory until `plybox apply`. `plybox diff` shows what it changed.
- **Limits**: memory, processes and CPU per box (cgroup v2; direct when the
  kernel allows, else through `systemd-run --user`).
- **Record**: every connection decision, every substitution, start and
  exit — one JSON line each, kept with the session.
- **Second kernel, when the code itself is untrusted**: `--isolation gvisor`
  runs the same box under gVisor's user-space kernel (rootless, no KVM),
  with a real OCI bundle — the same mounts, no host filesystem, one socket.
  19 ms instead of 3. In this tier the workspace is read-only unless you
  choose `--workspace-mode bind`.

No root. No daemon. Namespaces come from bubblewrap, the same engine
Anthropic's sandbox-runtime and Greywall use; everything around it is
plybox.

```sh
cd plybox && cargo build --release
ANTHROPIC_API_KEY=sk-… plybox run --secret ANTHROPIC_API_KEY@api.anthropic.com \
  --allow api.anthropic.com --allow registry.npmjs.org --mem 2G --pids 512 \
  -- claude -p "fix the tests"
plybox diff --last      # what it changed, held in the session
plybox apply --last     # copy those changes onto your directory

# Don't know what the agent needs to reach? Learn it once, then enforce it.
plybox run --learn agent.toml -- claude -p "fix the tests"   # allows + records every destination
plybox run --policy agent.toml -- claude -p "fix the tests"  # only those, from now on
```

```toml
# agent.toml  →  plybox run --policy agent.toml -- claude
[fs]
rootfs         = "host"
workspace      = "."
workspace_mode = "overlay"
ro_bind        = ["/home/me/.local/share/mise/installs/node:/opt/node"]
[net]
allow = ["api.anthropic.com", "*.anthropic.com", "registry.npmjs.org"]
[secrets]
ANTHROPIC_API_KEY = { only = "api.anthropic.com" }   # value from your environment
[limits]
mem = "2G"
pids = 512
[env]
PATH = "/opt/node/latest/bin:/usr/local/bin:/usr/bin:/bin"
```

## Status

v0 complete (slices 1–5). Measured by `lab/v0/run.sh` against 41 attacker
probes on one machine, both tiers: **0 open doors** (1 unmeasurable: no
ssh-agent there) — 0 kernel, 0 process, 0 files/secrets/IPC, 0 network, 0
resources — with curl, npm and node working, a secret substituted toward
its host and withheld from another; 3 ms start (namespaces), 19 ms
(gVisor). `--learn` records what a run reached and writes the policy for
the next one; the record marks those connections `learned`, and the run
itself is loudly not contained.

Known gaps: `apply` of a deletion is untested; `ioctl` is allowed for every
request code; x86_64 only; exfiltration *through an allowed host* is not
something any sandbox stops — keep the allow list short.

Everything claimed here has a probe in `lab/`. Read `lab/README.md`.

Requires: Linux x86_64, bubblewrap, unprivileged user namespaces; for
limits on a desktop, a user systemd session; for `--isolation gvisor`,
gVisor's `runsc` (`lab/tools/fetch.sh` shows how to fetch and verify it).
