# TODO

## Next: policy guard for `ro_bind` (after the TOML review)

The policy file is trusted input: `ro_bind` exposes any host path it names,
read-only, so a policy can hand the box `~/.ssh`. Fine when the machine
owner writes every policy; a hole once someone else can.

1. **Refuse sensitive binds by default** — `~/.ssh`, `~/.aws`, `~/.gnupg`,
   `~/.config/gh`, `~/.claude`, plybox's own sessions/state dirs,
   `/etc/shadow`, … (and any path *containing* one of them, e.g. `~`).
   Override only with an explicit `--allow-sensitive-bind`.
2. **Print every bind at startup** (unless `--quiet`) and record them in the
   session's start event, so what the box can read is visible and audited.
3. **Operator allow-list (for hosting others' code)** — the host owner lists
   the folders that may ever be bound (e.g. `/etc/plybox/operator.toml`);
   plybox refuses anything else, whatever the policy or flags ask. Until
   this exists, a hosting service must never pass user-supplied flags
   (`--ro-bind`, `--allow`, `--env`, `--secret`) through to plybox.

## Known, documented

- An idle proxy connection holds up to 16 KB of the `--bytes-in` budget
  while blocked in read; very small budgets can refuse new connections
  early. The cap itself is never exceeded. (Fix: wait for readability
  before reserving.)
