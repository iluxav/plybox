# Operator rules

A policy file decides what a box may reach, and several of its fields reach
into the host: `workspace`, `ro_bind`, a rootfs directory, secret files, the
supervisor's own environment, `map`, `trust_ca`. That is fine when you write
every policy yourself. It is not fine once someone else writes them, for
example when users of a hosted service define their own agents.

The operator file is the machine owner's ceiling. plybox applies it to every
run, whatever the policy file or the flags say.

## Where it is read from

1. `$PLYBOX_OPERATOR`, if set. It must exist; an empty value is an error.
2. Otherwise `/etc/plybox/operator.toml`, if it exists.
3. Neither: no ceiling. This is one person's own machine, behaving as before.

Any problem with the file refuses the run: unreadable, an unknown key (a
typo), or a bad value. Make it root-owned and not writable by the user plybox
runs as.

## The rule of thumb

- **Lists are allowlists.** Absent or empty allows nothing: no paths, no
  hosts, no images, no host-sourced secrets.
- **`[max]` caps each limit.** A policy asking for more is refused. A policy
  silent on a limit gets the maximum. When `mem`, `pids` or `cpu` come from
  here and this machine cannot enforce them (no cgroup of plybox's own, no
  `systemd --user`), the run is refused rather than run unlimited.

## Example

```toml
# /etc/plybox/operator.toml
isolation = "gvisor"                      # forced, whatever the policy says
runsc = "/usr/local/bin/runsc"            # the only runsc; a policy may not name one

images = ["python:3.13-slim", "node:22-slim", "ghcr.io/acme/*"]   # `*` = prefix
host_rootfs = false                       # true lets the box use the host's /usr

paths = ["/srv/plybox/work"]              # workspace, ro_bind sources, rootfs dirs
hosts = ["api.anthropic.com", "registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
sessions = "/srv/plybox/sessions"         # where --session may point (absent: refused)
resume = false                            # allow --resume

[secrets]   # the only secrets read from a file or from plybox's environment
ANTHROPIC_API_KEY = { only = "api.anthropic.com", file = "/etc/plybox/keys/anthropic" }

[max]
mem = "4G"
pids = 1024
cpu = 2.0
file_size = "1G"
bytes_out = "200M"
bytes_in = "2G"
# tmpfs and disk too (namespace tier only; disk needs a provisioned volume)
```

## What each rule does

| Rule | Effect |
|---|---|
| `isolation`, `runsc` | The tier is forced. A policy may not choose its own `runsc`. |
| `images` | `--image` must match: an exact reference (`python:3.13-slim` and `docker.io/library/python:3.13-slim` are the same image), or a prefix ending in `*`. Tags can move, so pin `@sha256:` digests for a fixed image. |
| `host_rootfs` | Without it, a box must use an approved image. |
| `paths` | The workspace, each `ro_bind` source and a rootfs directory are resolved (symlinks and all) and must lie under one of these. The resolved path is what gets mounted, so a symlink swapped later changes nothing. |
| `hosts` | Every `net.allow` entry must fall inside: `api.example.com` inside `*.example.com`, `*.a.example.com` inside `*.example.com`. A wildcard does not cover its apex, and ports must match (443 by default). |
| `[secrets]` | A secret read from a host file or from plybox's environment must be declared here. A policy naming one gets exactly the operator's source and host. A value the user typed (`NAME=VALUE@HOST`) is allowed, but only to a host within `hosts`. |
| `sessions` | `--session` must stay under it; the existing part of the path is resolved first, so nothing is created through a symlink. |
| `resume` | `--resume` is refused unless this is `true`. |
| always | `net.map`, `net.trust_ca` and `--learn` are refused. |

Startup prints `rules operator ceiling from …`, and the session's start event
records the file's path along with the run's full exposure (every host path,
secret source and destination).

## What it does not cover

- **Separating tenants from each other.** `paths` applies to every run, so
  one user's policy can name another user's directory under the same root.
  Run each tenant as its own Unix user, or have the service choose the
  workspace and pass no user paths at all.
- **`env` values.** They are inside the box only, but they are saved in
  plain text in the session: never put secrets there.
- **`plybox pull` / `images`.** These are operator commands, not runs.

`make test-policy` measures these rules: 26 operator checks, plus 6 on what
any policy can do to the box.
