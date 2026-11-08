# Policy and command reference

[Back to the README](../README.md).

## Policy files

Run settings can live in a TOML file. Treat it as trusted host input;
see [operator rules](operator.md). Use
`--policy FILE`; flags given alongside it add to it or override it.

```toml
image = "python:3.13-slim"

[fs]
workspace = "."
workspace_mode = "bind"       # direct writes; default is read-only

[net]
allow = ["api.anthropic.com"]

[secrets]
ANTHROPIC_API_KEY = { only = "api.anthropic.com" }

[limits]
mem = "512M"
pids = 256
cpu = 1.0
file_size = "16M"
bytes_out = "10M"

[env]
PYTHONUNBUFFERED = "1"
```

| Section | Key | Meaning | Default |
|---|---|---|---|
| top | `image` | OCI image to use as the box's root | none: host tools |
| top | `isolation` | `ns` or `gvisor` | `gvisor` |
| top | `runsc` | path to gVisor's `runsc` | bundled runtime; `PATH` in unbundled dev builds |
| `[fs]` | `rootfs` | `host` (your `/usr`, read-only) or a directory | `host` |
| `[fs]` | `workspace` | folder mounted at `/work` | `.` |
| `[fs]` | `workspace_mode` | `readonly` (gVisor), `overlay` (ns copy), or `bind` (direct) | `auto`: readonly for gVisor, overlay for ns |
| `[fs]` | `ro_bind` | extra read-only mounts, `HOST:BOX` (`~/` allowed) | none |
| `[net]` | `allow` | `host`, `*.domain` (subdomains only), `host:port` | none: no network |
| `[secrets]` | `NAME = { only = HOST }` | value from plybox's environment variable `NAME` | |
| `[secrets]` | `NAME = { only = HOST, file = PATH }` | value from a file you own (mode 600, one line) | |
| `[limits]` | `mem`, `pids`, `cpu` | memory, process count, CPU cores | unlimited |
| `[limits]` | `file_size`, `tmpfs`, `disk` | per-file size, scratch space, total session disk | unlimited |
| `[limits]` | `bytes_out`, `bytes_in` | network traffic for the whole run | unlimited |
| `[env]` | `KEY = "value"` | environment inside the box | |

Sizes take `K`, `M` and `G` (binary). Allowed hosts default to port 443.
`[env]` values are saved in plain text with the session, so put credentials in
`[secrets]`, never in `[env]`.

## Command reference

```
plybox run [OPTIONS] -- COMMAND [ARGS...]     run a command in a box
plybox diff    [SESSION] [--patch]            what a session changed
plybox apply   [SESSION]                      copy those changes onto the folder
plybox discard [SESSION]                      delete a session and its changes
plybox sessions [--prune]                     list sessions
plybox --resume SESSION [-- COMMAND...]       run again on a session's saved copy
plybox pull IMAGE                             fetch an OCI image ahead of time
plybox images                                 list pulled images
plybox version · plybox help
```

`SESSION` is a session's name (`lively-fern`), a unique prefix of at least
3 characters (`liv`), a session directory, or `--last`. When omitted, the
most recent session is used.

### `plybox run`

**Policy and isolation**

| Option | Meaning |
|---|---|
| `--policy FILE` | load a TOML policy; other flags add to or override it |
| `--isolation ns\|gvisor` | gVisor’s user-space kernel (default), or explicit namespace opt-in |
| `--runsc PATH` | override the bundled gVisor runtime |
| `--image IMAGE` | use an OCI image as the box's root (pulled and cached on first use) |
| `--rootfs host\|DIR` | the host's `/usr` read-only (default), or a directory |

**Files**

| Option | Meaning |
|---|---|
| `--work DIR` | folder mounted at `/work` (default: current directory) |
| `--workspace-mode auto\|readonly\|overlay\|bind` | `auto` (default): readonly for gVisor, overlay for ns · `bind`: write directly · explicit `overlay` requires ns |
| `--ro-bind HOST:BOX` | mount a host path read-only inside the box (repeatable) |

**Network and secrets**

| Option | Meaning |
|---|---|
| `--allow HOST[:PORT]` | allow a destination: `api.example.com`, `*.example.com`, `host:8443` (repeatable) |
| `--secret NAME@HOST` | secret from plybox's environment variable `NAME`, sent only to `HOST` |
| `--secret NAME=VALUE@HOST` | the same, with the value inline (visible in `ps`; prefer the other forms) |
| `--secret-file NAME=PATH@HOST` | secret read from a file (mode 600, one line) |
| `--learn [FILE]` | allow every public destination, record each, write a policy to `FILE` |

**Environment**

| Option | Meaning |
|---|---|
| `--env KEY=VALUE` | set a variable inside the box (repeatable) |
| `--env KEY` | pass your own value of `KEY` through |

**Limits**

Host memory, task and CPU limits require an available cgroup v2 backend.
Without one, ordinary requested limits warn and continue without host
cgroup enforcement; mandatory operator ceilings refuse the run. See
[requirements](requirements.md#resource-limits-and-optional-namespace-tier).

| Option | Meaning |
|---|---|
| `--mem SIZE` | memory limit, no swap (`512M`, `4G`) |
| `--pids N` | maximum number of processes |
| `--cpu CORES` | CPU limit in cores (`0.5`, `2`) |
| `--file-size SIZE` | largest file the box may write |
| `--tmpfs SIZE` | total size of `/tmp`, `$HOME` and `/dev/shm`; requires `--isolation ns` |
| `--disk SIZE` | namespace tier only; total session disk; needs a provisioned volume (see [limits.md](limits.md)) |
| `--bytes-out SIZE`, `--bytes-in SIZE` | network traffic budget for the whole run |

**Sessions and output**

| Option | Meaning |
|---|---|
| `--session DIR` | keep this session in `DIR` instead of the default location |
| `--resume SESSION` | continue a namespace overlay session: same saved copy, same policy, fresh processes |
| `--quiet` | hide plybox's status lines (warnings and errors still print) |

### Inside the box

| Path or variable | What it is |
|---|---|
| `/work` | your folder, and the working directory |
| `$HOME` (`/home/box`), `/tmp` | empty and writable; gone when the box exits |
| `/run/plybox/` | plybox's socket and the session's files (read-only) |
| `HTTPS_PROXY`, `HTTP_PROXY` | point at plybox's proxy. HTTPS only; plain HTTP is refused |
| `SSL_CERT_FILE` and similar | set when secrets are used, so TLS clients trust the session CA |

### Sessions

Each run is a session, stored in `~/.local/state/plybox/sessions/<name>/`
(`$XDG_STATE_HOME`). Every tier keeps a record; only namespace overlay
sessions hold a saved copy for `diff`, `apply` and resume.

- **`plybox sessions`** lists every session: `PENDING n` (changes not applied
  yet), `applied`, `no changes`, `running`, `no copy (bind)`, or `no copy (gvisor)`.
- **`plybox sessions --prune`** removes sessions that are applied or empty.
  Pending ones stay.
- **`plybox apply`** treats the session as untrusted. It never writes through
  a symlink and refuses if any change would land outside your folder. After
  applying, only the record is kept.
- **`plybox --resume SESSION`** starts fresh processes on the session's saved
  copy, with the saved policy. Add `-- COMMAND` to run something else. Files
  are restored; processes, `$HOME` and `/tmp` are not.

Details, including every record event: [sessions.md](sessions.md).

### Exit codes and files

| | |
|---|---|
| exit code | the box's own (128 + N if it was killed by signal N); `1` if plybox refused or failed; `2` for a usage error |
| `~/.local/state/plybox/sessions/` | sessions (`$XDG_STATE_HOME`) |
| `~/.local/state/plybox/runtimes/` | verified bundled runtime cache (`$XDG_STATE_HOME`) |
| `~/.local/share/plybox/images/` | pulled images (`$XDG_DATA_HOME`) |
| `/etc/plybox/operator.toml` | operator rules, if present (`$PLYBOX_OPERATOR` overrides) |
