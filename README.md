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

Slices 1–3 done. Measured by `lab/v0/run.sh` against 41 attacker probes on
one machine: **0 open doors** (1 unmeasurable: no ssh-agent there) — 0
kernel, 0 process, 0 files/secrets/IPC, 0 network, 0 resources — with
curl, npm and node working, a secret substituted toward its host and
withheld from another, and a 3 ms start.

Next: a gVisor tier for untrusted code, and a learning mode (run in audit,
generate the allow list, switch to enforce).

Everything claimed here has a probe in `lab/`. Read `lab/README.md`.

Requires: Linux x86_64, bubblewrap, unprivileged user namespaces; for
limits on a desktop, a user systemd session.
