<h1 align="center">plybox</h1>

<p align="center">
  <b>Let an AI agent run code on your machine — without giving it your machine.</b>
</p>

<p align="center">
  <a href="https://github.com/iluxav/plybox/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/iluxav/plybox/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/iluxav/plybox/releases"><img alt="Release" src="https://img.shields.io/github/v/release/iluxav/plybox?include_prereleases&sort=semver"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Platform: Linux x86_64" src="https://img.shields.io/badge/platform-linux%20x86__64-informational">
  <img alt="No root, no daemon" src="https://img.shields.io/badge/no%20root-no%20daemon-success">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-orange">
</p>

plybox runs a command (an agent, a script, a build) in a box that:

- **reaches only the hosts you name.** Everything else is refused, and every
  connection is logged.
- **never sees your API keys.** The box holds a placeholder; plybox swaps in
  the real key on the way out, and only toward the host the key belongs to.
- **can't touch your files.** It works on a copy of your folder. You review
  the changes, then apply them or throw them away.

It is one static binary. No root, no daemon, no Docker. A box starts in about
4 ms.

```console
$ plybox run --policy claude.toml -- claude -p "fix the failing tests" --dangerously-skip-permissions
$ plybox diff        # what the agent changed, held in the session
M  src/parser.rs
A  tests/parser_edge_cases.rs
$ plybox apply       # copy it onto your folder (or: plybox discard)
```

---

- [Why](#why)
- [Install](#install)
- [Quick start](#quick-start)
- [What you can use it for](#what-you-can-use-it-for)
- [How it works](#how-it-works)
- [Policy files](#policy-files)
- [Command reference](#command-reference)
- [Security model](#security-model)
- [Requirements](#requirements)
- [FAQ](#faq)

## Why

Coding agents are most useful when they stop asking for permission: they
install packages, run tests and edit files on their own. That also means
running code nobody reviewed, with your shell's access to everything: your
SSH keys, your cloud credentials, your other projects, and the open internet.

A prompt injection in a README, a malicious package or a confused agent can
then do whatever you can do. plybox makes the unattended mode safe to use.
The agent gets a folder, the tools it needs and the hosts it needs. Nothing
else exists inside the box.

## Install

**1. Get bubblewrap 0.11 or newer**, which plybox uses for Linux namespaces:

```sh
sudo pacman -S bubblewrap        # Arch
sudo dnf install bubblewrap      # Fedora
sudo apt install bubblewrap      # Debian, Ubuntu
bwrap --version                  # needs 0.11+
```

<details>
<summary>Older distributions ship an older bubblewrap (Ubuntu 24.04: 0.9, Debian 12: 0.8). Build a current one:</summary>

```sh
sudo apt install git meson ninja-build pkg-config libcap-dev
git clone --depth 1 --branch v0.11.2 https://github.com/containers/bubblewrap
cd bubblewrap && meson setup _build -Dman=disabled -Dtests=false
ninja -C _build && sudo ninja -C _build install      # → /usr/local/bin/bwrap
```

With an older bubblewrap, only `--workspace-mode bind` on your own tools
works: no workspace copy, no images.
</details>

**2. Get plybox**, a single static binary:

```sh
curl -fsSLo plybox https://github.com/iluxav/plybox/releases/latest/download/plybox-linux-x86_64
chmod +x plybox && mv plybox ~/.local/bin/
plybox version
```

<details>
<summary>Build from source instead</summary>

```sh
git clone https://github.com/iluxav/plybox && cd plybox
rustup target add x86_64-unknown-linux-musl
make install        # → ~/.local/bin/plybox   (make uninstall removes it)
```
</details>

## Quick start

Run something in a box. With no flags, the box has no network, sees your
system tools read-only, and works on a copy of the current folder:

```console
$ plybox run -- sh -c 'echo hello > note.txt; curl -sS https://example.com'
plybox: box up (ns) — network: none; secrets: 0; workspace /home/me/demo at /work (overlay); …
curl: (7) CONNECT tunnel failed, response 403
plybox: box exited 7; 1 workspace change(s) held in session lively-fern
```

Allow a host, and the request goes through:

```console
$ plybox run --quiet --allow example.com -- curl -s -o /dev/null -w '%{http_code}\n' https://example.com
200
```

See what a box changed, then keep it or drop it:

```console
$ plybox diff lively-fern
A  note.txt
$ plybox diff lively-fern --patch     # line by line
$ plybox apply lively-fern            # copy the changes onto your folder
$ plybox discard lively-fern          # or throw them away
```

Without a name, `diff`, `apply` and `discard` use the most recent session.

Every session keeps a record of what happened:

```console
$ cat ~/.local/state/plybox/sessions/lively-fern/record.jsonl
{"event":"start", … every host path, secret and limit of the run …}
{"event":"net","host":"example.com","port":443,"verdict":"refused","reason":"not in the allow list",…}
{"event":"exit","code":7,"workspace_changes":1,…}
```

## What you can use it for

### Run a coding agent unattended

Give Claude Code, Codex or any agent CLI full autonomy inside the box. It
reaches its API and your package registry, and nothing else:

```sh
plybox run --policy examples/claude.toml --mem 4G --pids 1024 \
  -- claude -p "upgrade the dependencies and fix what breaks" --dangerously-skip-permissions
plybox diff --patch && plybox apply
```

[`examples/claude.toml`](examples/claude.toml) is a complete policy for Claude
Code on a Rust project. It mounts in the agent's install directory and the
Rust toolchain, allows `api.anthropic.com` and crates.io, and passes your
subscription token as a secret the box never sees.

Tools installed under your home (`~/.local`, mise, nvm, rustup) don't exist in
the box until you mount them with `--ro-bind`, or run an image that has them.

### Give an agent an API key it can't steal

The box only ever sees a placeholder. plybox replaces it with the real value
on requests to the one host you name. Sent anywhere else, the placeholder is
worthless.

```console
$ export DEMO_TOKEN=real-value-123
$ plybox run --quiet --secret DEMO_TOKEN@postman-echo.com --allow postman-echo.com -- sh -c '
    echo "inside the box: $DEMO_TOKEN"
    curl -s https://postman-echo.com/headers -H "Authorization: Bearer $DEMO_TOKEN"'
inside the box: PLYBOX_SECRET_DEMO_TOKEN_997bcab1fa787fb8
{"headers":{"host":"postman-echo.com","authorization":"Bearer real-value-123", …}}
```

Read the key from a file instead of your environment with
`--secret-file NAME=PATH@HOST`. The file must be readable by you only
(`chmod 600`).

### Run untrusted or AI-generated code

A script from a chat, a repo you just cloned, a package's install hooks:

```sh
plybox run -- python3 generated_script.py
plybox run --image python:3.13-slim --allow pypi.org --allow files.pythonhosted.org \
  -- sh -c 'pip install -r requirements.txt && python3 main.py'
```

For code you trust even less, add `--isolation gvisor`. The box then runs on
gVisor's user-space kernel, so the workload never talks to your kernel
directly. It starts in about 20 ms.

### Use any tool without installing it: OCI images, no Docker

`--image` makes a container image the box's filesystem. plybox pulls it
itself, checks every layer's sha256 and caches it:

```sh
plybox run --image python:3.13-slim -- python3 script.py
plybox run --image node:22-slim --allow registry.npmjs.org -- sh -c 'npm install && node index.js'
plybox run --image mwader/static-ffmpeg:7.1 -- /ffmpeg -i in.mov out.mp4
```

### Find out what an agent needs, then lock it down

Not sure which hosts a tool talks to? Run it once in learn mode. Every public
destination is allowed and recorded, and a policy file is written for you:

```sh
plybox run --learn agent.toml -- ./my-agent      # open network, everything recorded
plybox run --policy agent.toml -- ./my-agent     # only what it used, from now on
```

Learn mode doesn't contain the network. Use it only with code you trust.

### Host agents for other people

When users define their own agents on your server, an operator file
(`/etc/plybox/operator.toml`) puts a ceiling over every run:

- approved images and folders;
- the hosts users may allow;
- secrets only from sources you declare;
- maximum limits;
- a forced gVisor tier.

plybox enforces the ceiling whatever a user's policy says. See
[docs/operator.md](docs/operator.md).

### Batch jobs and CI

plybox passes the box's stdout and stderr through and exits with the box's
exit code, so it slots into scripts as-is. `--quiet` hides plybox's own
messages, and `--workspace-mode bind` writes straight into the folder when
there's nothing to review.

```sh
plybox run --quiet --image node:22-slim --allow registry.npmjs.org -- sh -c 'npm ci && npm test'
```

## How it works

```
 plybox run: the supervisor, outside the box ────────────────────────────┐
 │                                                                         │
 │  proxy ── allow list ──► api.anthropic.com    ✔ allowed, recorded       │
 │    │                     github.com           ✘ refused, recorded       │
 │    │      secret placeholder ──► real key, only toward its own host     │
 │    │                                                                    │
 │    │ one unix socket: the box's only way out                            │
 │  ┌─┴───────────────────────────────────────────────────────────────┐    │
 │  │ the box (bubblewrap namespaces, or gVisor)                      │    │
 │  │   /work        a copy of your folder; edits held for review     │    │
 │  │   /usr         host tools or an OCI image, read-only            │    │
 │  │   $HOME, /tmp  empty, gone at exit                              │    │
 │  │   loopback only · no capabilities · seccomp · Landlock          │    │
 │  └─────────────────────────────────────────────────────────────────┘    │
 └─────────────────────────────────────────────────────────────────────────┘
```

- **Files.** The box gets its own mount namespace. Your folder is mounted at
  `/work` as an overlay: reads come from your folder, writes land in the
  session. Your home, other projects and `/etc` (apart from a few basics like
  CA certificates) don't exist inside.
- **Network.** The box has loopback only. Programs reach out through
  `HTTPS_PROXY`, which plybox sets. The proxy decides by **hostname**, before
  any connection exists. It refuses names that resolve to private or loopback
  addresses, so an allowed name can't be pointed at your LAN or the host.
- **Secrets.** For the host a secret belongs to, the proxy terminates TLS with
  a per-session CA that the box trusts, replaces placeholders in the request,
  and re-encrypts toward the real server.
- **Kernel.** A seccomp allowlist (unknown syscalls fail), no capabilities,
  `no_new_privs`, no nested user namespaces, and Landlock where the kernel has
  it. io_uring, ptrace, keyrings, raw sockets and the like are gone.
- **Limits.** Memory, processes and CPU through cgroup v2. plybox uses its own
  cgroup when it can, otherwise `systemd-run --user`. You can also cap file
  sizes, scratch space and network traffic.
- **Record.** At start, plybox prints and records everything the box can
  reach on your machine. During the run, every connection decision and
  secret substitution is one JSON line in the session.

## Policy files

Everything you can pass as a flag can also live in a TOML file. Use
`--policy FILE`; flags given alongside it add to it or override it.

```toml
# agent.toml — plybox run --policy agent.toml -- claude -p "…"

image = "node:22-slim"          # optional: an OCI image as the box's root
isolation = "ns"                # "ns" (namespaces) or "gvisor"

[fs]
workspace = "."                 # the folder mounted at /work
workspace_mode = "overlay"      # "overlay": a copy you apply · "bind": write directly
ro_bind = ["~/.local/share/mise/installs/claude:/opt/claude"]   # HOST:BOX, read-only

[net]
allow = ["api.anthropic.com", "registry.npmjs.org", "*.githubusercontent.com"]

[secrets]
ANTHROPIC_API_KEY = { only = "api.anthropic.com" }                           # from your environment
GITHUB_TOKEN      = { only = "api.github.com", file = "~/.config/gh-token" }  # from a file (mode 600)

[limits]
mem = "4G"
pids = 1024
cpu = 2.0
file_size = "1G"
bytes_out = "50M"

[env]
PATH = "/opt/claude/latest:/usr/local/bin:/usr/bin:/bin"
NODE_ENV = "development"
```

| Section | Key | Meaning | Default |
|---|---|---|---|
| top | `image` | OCI image to use as the box's root | none: host tools |
| top | `isolation` | `ns` or `gvisor` | `ns` |
| top | `runsc` | path to gVisor's `runsc` | found on `PATH` |
| `[fs]` | `rootfs` | `host` (your `/usr`, read-only) or a directory | `host` |
| `[fs]` | `workspace` | folder mounted at `/work` | `.` |
| `[fs]` | `workspace_mode` | `overlay` (copy, review, apply) or `bind` (direct) | `overlay` |
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
| `--isolation ns\|gvisor` | namespaces (default), or gVisor's user-space kernel |
| `--runsc PATH` | gVisor's `runsc` binary |
| `--image IMAGE` | use an OCI image as the box's root (pulled and cached on first use) |
| `--rootfs host\|DIR` | the host's `/usr` read-only (default), or a directory |

**Files**

| Option | Meaning |
|---|---|
| `--work DIR` | folder mounted at `/work` (default: current directory) |
| `--workspace-mode overlay\|bind` | `overlay`: writes held for `diff`/`apply` (default) · `bind`: write directly |
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

| Option | Meaning |
|---|---|
| `--mem SIZE` | memory limit, no swap (`512M`, `4G`) |
| `--pids N` | maximum number of processes |
| `--cpu CORES` | CPU limit in cores (`0.5`, `2`) |
| `--file-size SIZE` | largest file the box may write |
| `--tmpfs SIZE` | total size of `/tmp`, `$HOME` and `/dev/shm` |
| `--disk SIZE` | total session disk; needs a provisioned volume (see [docs/limits.md](docs/limits.md)) |
| `--bytes-out SIZE`, `--bytes-in SIZE` | network traffic budget for the whole run |

**Sessions and output**

| Option | Meaning |
|---|---|
| `--session DIR` | keep this session in `DIR` instead of the default location |
| `--resume SESSION` | continue a session: same saved copy, same policy, fresh processes |
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
(`$XDG_STATE_HOME`). It holds the copy of your changes and the record.

- **`plybox sessions`** lists every session: `PENDING n` (changes not applied
  yet), `applied`, `no changes`, `running`, or `no copy (bind)`.
- **`plybox sessions --prune`** removes sessions that are applied or empty.
  Pending ones stay.
- **`plybox apply`** treats the session as untrusted. It never writes through
  a symlink and refuses if any change would land outside your folder. After
  applying, only the record is kept.
- **`plybox --resume SESSION`** starts fresh processes on the session's saved
  copy, with the saved policy. Add `-- COMMAND` to run something else. Files
  are restored; processes, `$HOME` and `/tmp` are not.

Details, including every record event: [docs/sessions.md](docs/sessions.md).

### Exit codes and files

| | |
|---|---|
| exit code | the box's own (128 + N if it was killed by signal N); `1` if plybox refused or failed; `2` for a usage error |
| `~/.local/state/plybox/sessions/` | sessions (`$XDG_STATE_HOME`) |
| `~/.local/share/plybox/images/` | pulled images (`$XDG_DATA_HOME`) |
| `/etc/plybox/operator.toml` | operator rules, if present (`$PLYBOX_OPERATOR` overrides) |

## Security model

**What plybox stops.** The test suite runs 41 attacks from inside the box, in
both tiers. None get through. (One of them, reaching an ssh-agent, can't be
measured on the test machine.) The attacks try to:

- read your home, SSH keys, cloud credentials or other projects;
- reach hosts you didn't allow, your LAN, or services on the host;
- steal the API keys you hand the box;
- escalate through the kernel's riskier interfaces (io_uring, ptrace,
  keyrings, nested user namespaces, raw sockets);
- exhaust memory or processes, when limits are set;
- write outside your folder through `apply`.

A separate suite checks that a hostile **policy file** can't weaken the box
either.

**What it does not stop.**

- **Exfiltration through a host you allowed.** If the box may reach
  `github.com`, it can post data there. Keep the allow list short.
- **Kernel bugs.** In the namespace tier the box shares your kernel. For
  hostile code, use `--isolation gvisor`.
- **Bad changes you approve.** `apply` copies what the agent wrote. Read
  `plybox diff` first.

Found a hole? Please report it privately; see [SECURITY.md](SECURITY.md).

## Requirements

- Linux on x86_64, with unprivileged user namespaces (kernel 5.11+).
- For the default namespace tier:
  [bubblewrap](https://github.com/containers/bubblewrap) 0.11 or newer. The
  workspace copy and `--image` use its overlay mounts. See
  [Install](#install) for Ubuntu 24.04 and Debian 12.
- For memory, process and CPU limits: cgroup v2, plus a user systemd session
  on desktops.
- For `--isolation gvisor`: gVisor's
  [`runsc`](https://gvisor.dev/docs/user_guide/install/) and `unshare` from
  util-linux (with `--map-current-user` and `--keep-caps` support).
  This tier does not use bubblewrap. The workload keeps your user ID,
  so bind-mode files remain yours on the host.
- Optional: Landlock (kernel 5.13+). plybox applies it when the kernel has it.

So far plybox has been tested on Arch-based Linux (kernel 6.x–7.x). If
bubblewrap fails with `setting up uid map: Permission denied`, your
distribution restricts unprivileged user namespaces. Ubuntu 23.10+ does this
through AppArmor.

### Known limitations

- x86_64 only, for now.
- Private registries (registry login) aren't supported yet.
- `--resume` restores files, not processes or an agent's conversation.
- In the gVisor tier the default workspace is read-only. Add
  `--workspace-mode bind` to write directly into your folder; those edits
  take effect immediately, without a review/apply step. Writes to `$HOME`
  and `/tmp` vanish at exit. Staged workspace edits, `--tmpfs` and `--disk`
  are namespace-tier only.

## FAQ

**Does it need Docker or root?** No. plybox is a regular user program. It
pulls OCI images itself and needs neither a daemon nor root.

**My command isn't found in the box.** The box sees `/usr`, not your home.
Tools installed under `~` (mise, nvm, rustup, `~/.local/bin`) need a
`--ro-bind` and a `PATH` entry. Or run an `--image` that has them.

**Why can't some tools connect?** The box reaches the network only through
`HTTPS_PROXY`. Most tools honour it: curl, git, pip, npm, and Python's
requests and httpx. Plain HTTP, SSH and raw TCP are refused by design. Tools
that ignore proxy settings fail closed: they get no network, rather than
getting around the proxy.

**Does it work on macOS or Windows?** Not natively; it's built on Linux kernel
features. It should work in a Linux VM or WSL2 with user namespaces enabled,
but that is untested.

**Can it run inside a Docker container?** Not tested yet. It needs
unprivileged user namespaces inside the container, which Docker's default
security profile blocks.

**Is the namespace tier enough?** For an agent you trust that might be
manipulated, yes: it closes every door the test suite measures. For code that
is hostile on purpose, add `--isolation gvisor`.

## Documentation

- [docs/sessions.md](docs/sessions.md): diff, apply, resume, and the record
- [docs/operator.md](docs/operator.md): operator rules for hosting other people's agents
- [docs/limits.md](docs/limits.md): storage and traffic limits in detail
- [examples/](examples/): a Claude Code policy, and a hosted Python agent
- [CONTRIBUTING.md](CONTRIBUTING.md): building, testing and the design log
- [SECURITY.md](SECURITY.md): reporting vulnerabilities

## License

[MIT](LICENSE)
