<h1 align="center">plybox</h1>

plybox runs untrusted AI agents on any Linux box. One binary. No KVM, no Docker, no daemon. Each agent gets its own gVisor kernel, a hostname allowlist, and API keys it can use but never see.

<p align="center">
  <a href="https://github.com/iluxav/plybox/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/iluxav/plybox/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/iluxav/plybox/releases"><img alt="Release" src="https://img.shields.io/github/v/release/iluxav/plybox?include_prereleases&sort=semver"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
  <img alt="Platform: Linux x86_64" src="https://img.shields.io/badge/platform-linux%20x86__64-informational">
  <img alt="No root, no daemon" src="https://img.shields.io/badge/no%20root-no%20daemon-success">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-orange">
</p>

<a id="why"></a>

- The box reaches only the HTTPS hosts you allow. Other destinations,
  direct internet connections, your LAN and host services are blocked.
- API keys stay in the supervisor. The box gets placeholders; the proxy
  substitutes each key only on requests to its assigned host.
- It sees the workspace and selected tools, not your host home or other
  projects. The workspace is read-only unless you enable direct writes.
- Each box runs through gVisor's user-space kernel, with no workload
  capabilities and a seccomp allowlist.

**“Any Linux box”, with limits:** x86_64 only, and the host must allow
user namespaces. Ubuntu 24.04+ needs a one-time AppArmor profile, which
ships with plybox. See [Requirements](#requirements).

## Quick start

A Python agent calls a model and writes `answer.txt`. Save this as
`agent-work/agent.py` after creating the `agent-work` directory. It uses
only Python's standard library; no package installation is needed.

```python
import json
import os
from pathlib import Path
from urllib.request import Request, urlopen

request = Request(
    "https://api.anthropic.com/v1/messages",
    data=json.dumps({
        "model": "claude-haiku-5-5",
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "Say hello in five words."}],
    }).encode(),
    headers={
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": os.environ["ANTHROPIC_API_KEY"],
    },
)
with urlopen(request, timeout=600) as response:
    message = json.load(response)
answer = "".join(b["text"] for b in message["content"] if b["type"] == "text")
Path("answer.txt").write_text(answer + "\n")
print("wrote answer.txt")
```

With `ANTHROPIC_API_KEY` set in your calling shell, run:

```sh
plybox run --quiet --image python:3.13-slim --work ./agent-work \
  --workspace-mode bind --allow api.anthropic.com \
  --secret ANTHROPIC_API_KEY@api.anthropic.com -- python3 agent.py
cat agent-work/answer.txt
```

Output captured using a **local API fixture**, with a fake key and the same
request format; no paid API call was made. Real model text will vary:

```text
wrote answer.txt
Hello from the local fixture.
```

`--work` selects the directory mounted at `/work`. `--workspace-mode bind`
makes `answer.txt` appear there immediately, owned by your user. It also
lets the agent change any other file in that directory: give it a dedicated
job directory. Without `bind`, the default gVisor workspace is read-only.
The key in the agent's environment is a placeholder, not your API key.

## Install

**Pre-release:** the download URL below returned HTTP 404 on 2026-11-07;
no public release asset is available yet. For this checkout, use the
[source build instructions](docs/recipes.md#build-plybox-from-source). Once published, the
release installs by downloading one file:

```sh
curl -fL -o plybox https://github.com/iluxav/plybox/releases/latest/download/plybox-linux-x86_64
chmod +x plybox
./plybox version
```

The version output from the current source-built release binary is:

```text
plybox 0.0.1
gVisor release-20261102.0 (embedded)
```

Put the executable on your `PATH` for the examples. It bundles `runsc` and
its helpers; the host needs util-linux's `unshare`, but no separate gVisor
install. On first use, plybox extracts the runtime into its private state
cache and checks compiled SHA-512 hashes before each launch. See
[runtime provenance and overrides](third_party/gvisor/README.md).

## Requirements

Linux **x86_64**, kernel **5.6+** per the pinned gVisor release, and
util-linux `unshare` with the flags below. User, network and the runtime's
nested namespaces must be permitted. The runtime cache must be writable
and executable. No KVM or nested hardware virtualization is needed.

The first two "Verified" rows were run; the rest are researched. Distro
defaults are evidence about prerequisites, not a claim that this exact
binary passed there:

| Host | Status and action |
|---|---|
| Omarchy 4.5 / Arch, kernel 7.2.15, util-linux 2.42.4 | **Verified locally:** default gVisor, Python image, bind output, proxy secrets and systemd cgroup limits |
| Ubuntu 23.10 | **Researched:** userns restriction was opt-in; check the actual host policy |
| Ubuntu 24.04+ | **Verified in CI** (24.04.5, kernel 7.0) with the restriction on: install the [bundled AppArmor profile](docs/requirements.md#ubuntu-2404-and-later) once; without it plybox stops and says so |
| Debian 12 / 13 | **Researched:** unprivileged user namespaces enabled by default; hardened images can differ |
| RHEL / Rocky / AlmaLinux 9 | **Researched:** Rocky explicitly documents userns enabled; RHEL rootless guidance suggests it; Alma's kernel supports it but the effective default quota was not established. SELinux policy also matters |
| Amazon Linux 2023 | **Researched:** kernel/cgroup prerequisites documented; default permission for this namespace sequence not established |
| Full VM / container VPS | Full VMs need no nested virtualization. Docker's default policy blocks required operations; LXC/LXD/OpenVZ depend on the provider's nesting and security policy |

On Ubuntu 24.04+, as root, once. The profile is
[`contrib/apparmor/plybox`](contrib/apparmor/plybox), also published with
each release as `plybox.apparmor`:

```sh
sudo install -o root -g root -m 0755 plybox /usr/local/bin/plybox
sudo install -m 0644 plybox.apparmor /etc/apparmor.d/plybox
sudo apparmor_parser -r /etc/apparmor.d/plybox
```

The profile allows user namespaces for that one path only; a copy
elsewhere and plain `unshare` stay blocked. See
[distro sources and the Ubuntu details](docs/requirements.md).

Check the actual user and network namespace combination, then the full box:

```sh
unshare --user --map-current-user --keep-caps --net -- true
plybox run --quiet --image python:3.13-slim -- python3 -c 'print("box ready")'
```

The first command produced no output; the second printed `box ready` on
the verified machine. With an AppArmor exception attached only to plybox,
standalone `unshare` may still fail while the full box works.
Resource limits also need delegated cgroup v2 controllers or a working
systemd user manager. Without those, CLI-requested host cgroup limits warn
and remain unenforced; [operator maxima](docs/operator.md) instead refuse the run.

## Cost

Measured on **AMD Ryzen 5 9600X, 60.48 GiB RAM, Linux 7.2.15-1-omarchy**,
2026-11-07. Five trials per case; medians below count the whole running box,
including its supervisor and proxy. Startup is excluded.

| Work | Host | Default gVisor box |
|---|---:|---:|
| Idle CPU, per minute | 0 ms | 0.177 ms |
| One sleeping box, memory (PSS) | 0.22 MiB | 67.62 MiB |
| Each extra sleeping box, from 1 to 10 | — | ~29.5 MiB PSS; 333.03 MiB total at 10 |
| Small HTTPS call, p50 | 0.77–0.78 ms | 1.78–1.95 ms; **+1.0–1.2 ms** |
| CPU per HTTPS call | 0.48 ms | 3.37–3.48 ms; **+2.9–3.0 ms** |
| CPU-bound JSON work, elapsed | 1.112 s | 1.108 s; essentially unchanged |
| Small-file work, elapsed / CPU | 0.122 / 0.119 s | 0.651 / 1.414 s; **5.34× slower, 11.90× CPU** |
| In-box service, requests/s | 22,348 | 10,798; **about half** |

Extra-box memory is derived from the one- and ten-box totals, with shared
runtime pages and one host user. Budget separately for the agent's heap,
request buffers and OS headroom. HTTPS used a local fixture and fresh TLS
connections in every tier; it does not measure internet or model latency,
or a direct client's connection-pooling advantage. The service used one
sequential client inside the same box, with no inbound host port.
[Full methods, ranges and trial data](docs/research.md#2026-11-07-steady-state-overhead-with-embedded-gvisor).

## What you can use it for

<a id="host-agents-for-other-people"></a>
<a id="give-an-agent-an-api-key-it-cant-steal"></a>

### Self-host an agent, or several agents

Keep the Python agent above in a separate directory for each job. Save the
[policy below](#policy-files) as `agent.toml`, then run:

```sh
plybox run --quiet --policy agent.toml --work ./agent-work -- python3 agent.py
```

It prints `wrote answer.txt`. Multiple invocations get separate boxes.
A service must choose each job's workspace and policy; untrusted users
must not supply arbitrary host paths. All boxes launched by one account
share its host uid. See [operator rules](docs/operator.md).

<a id="run-untrusted-or-ai-generated-code"></a>

### Run a third-party script, skill or harness

For a downloaded script in `third-party/script.py`:

```sh
plybox run --quiet --image python:3.13-slim --work ./third-party -- python3 script.py
```

This has no network and a read-only workspace. `$HOME` and `/tmp` are
writable and disappear at exit. Run a skill through its actual harness in
the same way. Add only the hosts and files it needs.
The verification script printed `read-only workspace; direct network blocked`;
your script's output depends on what it does.

### Run a small service inside a box

A service and its clients can share the box's loopback network. This starts
a local HTTP server, calls it from the same box, then shuts it down:

```sh
plybox run --quiet --image python:3.13-slim -- python3 -c '
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from urllib.request import urlopen
server = HTTPServer(("127.0.0.1", 8080), SimpleHTTPRequestHandler)
thread = Thread(target=server.handle_request)
thread.start()
print(urlopen("http://127.0.0.1:8080").status)
thread.join()
server.server_close()
'
```

Standard output: `200` (the server also logs the request). There are
**no inbound ports** today, so this
cannot serve callers on the host or internet.

## How it works

```text
agent in gVisor -> loopback proxy forwarder -> Unix socket
                                            |
                           host supervisor: allowlist + secret substitution
                                            |
                                      allowed HTTPS host
```

The embedded `runsc` uses gVisor's user-space kernel to handle the agent's
system calls before they reach the host kernel. The supervisor stays
outside: it holds the keys, runs the proxy and writes the audit record.
Each box has a separate filesystem view and loopback network. Its
workspace and selected tools are the only host paths mounted, apart from
runtime support files such as certificates. Startup lists that exposure.

HTTPS clients must use the proxy environment variables. Direct TCP, SSH
and external plain HTTP fail; loopback HTTP inside a box works. The proxy
checks the hostname and rejects destinations resolving to private or
loopback addresses. Secret-bearing requests use TLS termination, placeholder
replacement, then TLS to the upstream. Other HTTPS connections are tunnels.
Each connection decision and substitution count goes into `record.jsonl`.

## Security model

The checked-in security suites exercise 41 probes in both tiers. On the
verified machine, 40 were closed and the SSH-agent probe was unavailable;
this is evidence for those probes, not proof against every escape.
gVisor adds a kernel boundary; seccomp, empty capabilities and
`no_new_privs` restrict the workload further. Landlock is used where
available; gVisor does not depend on host Landlock support.

<a id="known-limitations"></a>

- **One host uid per invoking account.** There is no automatic separation
  between tenants. Workspaces, policies and Unix accounts need operator control.
- **Allowed hosts are trusted destinations.** The agent can send data and
  spend API quota there. Responses are not redacted: a server that echoes
  the injected key can reveal it to the agent.
- **Policies are trusted host input.** They can name host files, credentials,
  mounts and runtimes. Use [operator ceilings](docs/operator.md) when
  accepting user settings; see the [remaining policy guard](TODO.md#open-policy-guard).
- **No inbound ports**, and **x86_64 Linux only**.
- **One upstream TCP+TLS connection per secret-bearing request.** No
  keep-alive yet; this adds roughly 1–2 network round trips per call.
  Requests are buffered up to 64 MiB before substitution; upstream read
  stalls time out after 15 minutes.
- **Direct workspace writes are immediate.** `bind` provides no review or
  rollback. Private registry authentication is not implemented.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## When to use something else

- **You have KVM and want a microVM:** [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/install/) or [microsandbox](https://github.com/superradcompany/microsandbox) offer local VM isolation on supported Linux hosts.
- **A coding agent edits your laptop repo:** [Anthropic's sandbox-runtime](https://github.com/anthropics/sandbox-runtime) and [nono](https://nono.sh/) provide filesystem and network restrictions around local tools.
- **Kubernetes:** [kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox) manages sandbox workloads with runtimes such as gVisor or Kata.

## Policy files

Save as `agent.toml`. This is the first Python example with limits added:

```toml
image = "python:3.13-slim"

[fs]
workspace_mode = "bind"

[net]
allow = ["api.anthropic.com"]

[secrets]
ANTHROPIC_API_KEY = { only = "api.anthropic.com" }

[limits]
mem = "512M"
pids = 256
cpu = 1.0
```

Flags add to or override the policy. Put credentials in `[secrets]`, never
`[env]`: ordinary environment values are saved with the session.
[Complete policy fields](docs/reference.md#policy-files).

## Command reference

| Command | Purpose |
|---|---|
| `plybox run [OPTIONS] -- COMMAND` | Run a command; gVisor is the default |
| `plybox pull IMAGE` / `plybox images` | Fetch or list cached OCI images |
| `plybox version` / `plybox help` | Version, bundled runtime and CLI help |

<a id="plybox-run"></a>
<a id="inside-the-box"></a>
<a id="exit-codes-and-files"></a>

See [all flags, paths, environment and exit codes](docs/reference.md#command-reference).
`--quiet` hides status lines; stdout, stderr and the workload's exit code
pass through. Every run keeps a session record even without staged files.

<a id="use-any-tool-without-installing-it-oci-images-no-docker"></a>
<a id="find-out-what-an-agent-needs-then-lock-it-down"></a>
<a id="batch-jobs-and-ci"></a>

[Additional recipes](docs/recipes.md) cover OCI tools, learning a network
policy and batch jobs. Learn mode allows every public destination and is
only for code you trust.

## Namespace tier and sessions (opt-in)

<a id="sessions"></a>
<a id="run-a-coding-agent-unattended"></a>

`--isolation ns` shares the host kernel and uses bubblewrap 0.11+ for a
staged workspace copy. This tier and its session features are frozen;
they remain tested but are not receiving new features.

For the Python agent above, stage the output instead of writing directly:

```sh
plybox run --quiet --isolation ns --image python:3.13-slim \
  --work ./agent-work --allow api.anthropic.com \
  --secret ANTHROPIC_API_KEY@api.anthropic.com -- python3 agent.py
plybox diff --last
```

The fixture run printed `wrote answer.txt`; after changing the fixture's
reply, `diff` printed `M  answer.txt`. `apply` copies changes to the host;
`discard` deletes a session; `sessions --prune` removes applied or empty
sessions. `--resume` restarts processes on the saved namespace copy, with
its policy and files. It does not restore processes or conversation state.
See [sessions](docs/sessions.md) for the full workflow.

The [Claude Code policy](examples/claude.toml) and
[coding-agent example](docs/recipes.md#coding-agent-with-staged-edits) mount
an installed CLI and toolchain, restrict its hosts and stage its edits.
They require adapting those paths and supplying your own credential.

## FAQ

**A tool installed under my home is missing.** Mount it with `--ro-bind`
and set its in-box `PATH`, or use an image containing it. Your host home is
not mounted automatically.

**Can I run this in a container or on Windows/macOS?** There is no native
Windows/macOS build. A Linux VM can meet the requirements; a container
shares its host's restrictions. See the [support matrix](docs/requirements.md).

## Documentation

- [Requirements and distro setup](docs/requirements.md)
- [Policy and command reference](docs/reference.md)
- [Recipes](docs/recipes.md), [sessions](docs/sessions.md), [operator rules](docs/operator.md), [limits](docs/limits.md)
- [Examples](examples/), [building and tests](CONTRIBUTING.md), [measurements](docs/research.md)

## License

[MIT](LICENSE). The bundled gVisor runtime is [Apache-2.0](third_party/gvisor/LICENSE);
release assets include `gvisor-LICENSE`.
