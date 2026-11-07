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
- **Images instead of host tools**: `--image python:3.13-slim` (or `node:22`,
  an ffmpeg image, your own) makes an OCI image the box's `/`. plybox pulls
  it itself — no Docker — verifies every layer's sha256, refuses layers that
  try to write, delete or hardlink outside the image, and caches it. The
  image stays read-only and untouched; many boxes share one copy. A bare
  machine needs only plybox and bubblewrap.
- **Second kernel, when the code itself is untrusted**: `--isolation gvisor`
  runs the same box under gVisor's user-space kernel (rootless, no KVM),
  with a real OCI bundle — the same mounts, no host filesystem, one socket.
  19 ms instead of 3. In this tier the workspace is read-only unless you
  choose `--workspace-mode bind`.

No root. No daemon. Namespaces come from bubblewrap, the same engine
Anthropic's sandbox-runtime and Greywall use; everything around it is
plybox.

```sh
cd plybox && cargo build --release --target x86_64-unknown-linux-musl   # static: runs in any image

# Tools from an image — nothing installed on the host:
plybox run --image python:3.13-slim --allow pypi.org -- python3 script.py
plybox run --image node:22-slim --allow registry.npmjs.org -- sh -c 'npm install && node index.js'
plybox run --image mwader/static-ffmpeg:7.1 -- /ffmpeg -i in.mov out.mp4

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

Images (`lab/image/run.sh`): inside `python:3.13-slim` the same suite reads
**0 open doors** in both tiers, the network workloads pass, and a cached
image starts in 3 ms (namespaces) / 18 ms (gVisor). Verified by hand:
`node:22-slim` (npm install + node), `mwader/static-ffmpeg:7.1` (a
`FROM scratch` image — no shell, no libc — rendering and probing a video).

Known gaps: `apply` of a deletion is untested; `ioctl` is allowed for every
request code; x86_64 only; private registries (login) are not supported
yet; under gVisor, an extra `--ro-bind` target missing from an image is
created inside the cached image; exfiltration *through an allowed host* is
not something any sandbox stops — keep the allow list short.

Everything claimed here has a probe in `lab/`. Read `lab/README.md`.

Requires: Linux x86_64, bubblewrap, unprivileged user namespaces (kernel
5.11+ for unprivileged overlayfs); for limits on a desktop, a user systemd
session; for `--isolation gvisor`, gVisor's `runsc` (`lab/tools/fetch.sh`
shows how to fetch and verify it). Use the static musl build: images run
`plybox` inside themselves, so it must not depend on their libc (plybox
refuses `--image` with a dynamically linked build and says why).
