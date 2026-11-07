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
make install            # static build → ~/.local/bin/plybox (make uninstall removes it)

# Tools from an image — nothing installed on the host:
plybox run --image python:3.13-slim --allow pypi.org -- python3 script.py
plybox run --image node:22-slim --allow registry.npmjs.org -- sh -c 'npm install && node index.js'
plybox run --image mwader/static-ffmpeg:7.1 -- /ffmpeg -i in.mov out.mp4

ANTHROPIC_API_KEY=sk-… plybox run --secret ANTHROPIC_API_KEY@api.anthropic.com \
  --allow api.anthropic.com --allow registry.npmjs.org --mem 2G --pids 512 \
  -- claude -p "fix the tests"
plybox diff --last      # what it changed, held in the session (--patch: line by line)
plybox apply --last     # copy those changes onto your directory; the session keeps only its record
plybox sessions         # every session: PENDING n / applied / no changes
plybox discard ID       # drop a session's changes; `plybox sessions --prune` clears applied + empty
plybox --resume ID      # restart the last command with that session's saved workspace
plybox run --resume ID -- claude -p "continue fixing the tests"  # or choose a new command

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

## Resuming a session

`plybox --resume quiet-heron` (also `plybox run --resume quiet-heron`)
starts a fresh process using the same saved workspace. With no command it
repeats the last command. Supply `-- COMMAND [ARGS...]` to change it. A
unique name prefix, a session directory, or `--resume --last` also works.

The effective policy is saved: image, network rules, mounts, environment
and limits are reused even from another working directory. Normal run
flags can override it; `--policy FILE` replaces the saved policy. The
workspace directory, namespace isolation and overlay mode must stay the
same. Explicit secret values are never saved: supply them again or use
an environment variable or secret file. File secrets are read again each
run. Ordinary `--env` values **are** saved; use `--secret` for credentials.
Learn mode is never automatically resumed; it requires an explicit `--learn`.

Older sessions have no saved policy. Supply it once:

```sh
plybox --resume rosy-heron --policy examples/claude.toml
```

Only unapplied namespace sessions with an overlay can resume. After
`apply`, start a new session on the updated project. A session in use
cannot be resumed, applied or discarded by another command; pruning keeps
running sessions. The audit record appends each run and its result.

This restores workspace files, including deletions. It does not restore
processes, `$HOME`, `/tmp`, or an agent's conversation history. The original
workspace remains the live lower layer, so external edits are visible
where the saved overlay has not replaced a file. A changed Git HEAD
produces a warning; uncommitted host edits are not detected or merged.

Run `make test-sessions` to check the lifecycle and resume with disposable
workspaces and state directories. These checks make no network requests.

## Status

v0 complete (slices 1–5). Measured by `make test-security` against 41 attacker
probes on one machine, both tiers: **0 open doors** (1 unmeasurable: no
ssh-agent there) — 0 kernel, 0 process, 0 files/secrets/IPC, 0 network, 0
resources — with curl, npm and node working, a secret substituted toward
its host and withheld from another; 4 ms start (namespaces), 20 ms
(gVisor). `--learn` records what a run reached and writes the policy for
the next one; the record marks those connections `learned`, and the run
itself is loudly not contained.

Images (`make test-image`): inside `python:3.13-slim` the same suite reads
**0 open doors** in both tiers, the network workloads pass, and a cached
image starts in 4 ms (namespaces) / 18 ms (gVisor). Verified by hand:
`node:22-slim` (npm install + node), `mwader/static-ffmpeg:7.1` (a
`FROM scratch` image — no shell, no libc — rendering and probing a video).

`apply` treats the session as untrusted: it carries deletions, never writes
through a symlink (a repo symlink pointing out of the workspace is replaced,
not followed — the earlier build did follow it, measured), and refuses the
whole apply if any change would land outside the workspace
(`make test-sessions`: 22 session checks, 35 resume checks).

Known gaps: resume restores only workspace files, not processes or agent
conversation history; `ioctl` is allowed for every
request code; x86_64 only; private registries (login) are not supported
yet; under gVisor, an extra `--ro-bind` target missing from an image is
created inside the cached image; exfiltration *through an allowed host* is
not something any sandbox stops — keep the allow list short.

## Layout

```
src/            the plybox binary (Rust)
tests/          the suites behind every claim above
  probe/          the 41 attacker probes (a small static binary)
  security/       probes + workloads against plybox, both tiers
  image/          the same inside an OCI image
  sessions/       session lifecycle (run.sh) and resume (resume.py)
  helpers/        test CA, a TLS stand-in for an API, in-box workloads
  tools/          fetch.sh for gVisor's runsc (downloads are gitignored)
examples/       policy files (claude.toml: Claude Code on a Rust project)
docs/           research.md: the measurements that shaped the design
```

`make test-all` runs every suite. Everything claimed here has a test in
`tests/`; the reasons behind the design are in `docs/research.md`.

Requires: Linux x86_64, bubblewrap, unprivileged user namespaces (kernel
5.11+ for unprivileged overlayfs); for limits on a desktop, a user systemd
session; for `--isolation gvisor`, gVisor's `runsc` (`make tools` fetches
and verifies it for the tests). Use the static musl build: images run
`plybox` inside themselves, so it must not depend on their libc (plybox
refuses `--image` with a dynamically linked build and says why).
