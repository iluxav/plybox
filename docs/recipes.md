# Additional recipes

The [README](../README.md) starts with a Python agent using the default
gVisor tier. These examples preserve the more specialized workflows.
Adapt filenames, installed tools, credentials and image references before
running them. They are recipes, not captured output from paid model calls.

## OCI tools without Docker

`--image` supplies the box's filesystem. plybox pulls public OCI images,
checks each layer's SHA-256 and caches it. It does not need a Docker daemon
on the machine that runs the box. Private registry login is not supported.

```sh
plybox run --image python:3.13-slim -- python3 script.py
plybox run --image node:22-slim --workspace-mode bind --allow registry.npmjs.org -- sh -c 'npm install && node index.js'
plybox run --image mwader/static-ffmpeg:7.1 --workspace-mode bind -- /ffmpeg -i in.mov out.mp4
```

The workspace is read-only by default. `bind` permits immediate writes to
the selected directory; it does not stage changes for review. Use a
dedicated directory. Tools installed under your home are absent unless
explicitly mounted with `--ro-bind` and added to the in-box `PATH`.

## Learn a network policy

Use this only with code you trust. Learn mode allows every public
destination while recording which hosts were used:

```sh
plybox run --learn agent.toml -- ./my-agent
plybox run --policy agent.toml -- ./my-agent
```

Review the generated policy before reusing it. Hostname allowlists are not
URL, account or API-operation allowlists: an allowed host can receive data
from the box.

## Batch jobs and CI

Standard output, standard error and the workload's exit status pass
through. `--quiet` suppresses status messages, and `bind` writes directly:

```sh
plybox run --quiet --image node:22-slim --workspace-mode bind --allow registry.npmjs.org -- sh -c 'npm ci && npm test'
```

For Python packages, installation in a fresh box can use the writable
in-box home, while the project stays read-only:

```sh
plybox run --image python:3.13-slim --allow pypi.org --allow files.pythonhosted.org -- sh -c 'pip install --user -r requirements.txt && python3 main.py'
```

## Secret files and response handling

Use `--secret-file NAME=PATH@HOST` for an owner-only, single-line key file.
Ordinary `--env` values are visible inside and persisted in session metadata;
they are not a secret channel. Inline `--secret NAME=VALUE@HOST` exposes the
value in the host command line, so prefer environment or file sources.

The proxy replaces placeholders in outbound requests only. An allowed
echo service can return the real injected value to the box. Do not use
real credentials with an echo service or an untrusted destination. This
qualifies the README's shorthand that the agent cannot see the key.

## Coding agent with staged edits

This opt-in namespace workflow shares the host kernel. It is frozen but
still tested. The [Claude Code policy](../examples/claude.toml) selects
`isolation = "ns"`, mounts an installed CLI and Rust toolchain, names API
and package-registry hosts, and reads a credential from an owner-only file.
Adapt its paths, limits and credential source for your machine.

```sh
plybox run --isolation ns --policy examples/claude.toml -- claude -p "fix the failing tests" --dangerously-skip-permissions
plybox diff --last --patch
plybox apply --last
```

Inspect the patch before the last command. To discard the staged work,
use `plybox discard --last` instead of `apply`. `plybox --resume SESSION`
starts fresh processes on a namespace session's saved workspace. It does
not restore process state or the agent's conversation. See
[sessions and record events](sessions.md).

## Installing the optional namespace tier

The default gVisor tier needs no bubblewrap. Namespace staging and images
require bubblewrap 0.11+. Check your distribution's package version:

```sh
bwrap --version
```

Distribution package installation, if needed, is an administrator task:

```sh
sudo pacman -S bubblewrap
sudo dnf install bubblewrap
sudo apt install bubblewrap
```

Run only the line for your distribution. Older stable distributions can
ship versions below 0.11. An administrator can build a newer upstream
release; this is not needed for gVisor and was not done during the README
verification:

```sh
sudo apt install git meson ninja-build pkg-config libcap-dev
git clone --depth 1 --branch v0.11.2 https://github.com/containers/bubblewrap
cd bubblewrap
meson setup _build -Dman=disabled -Dtests=false
ninja -C _build
sudo ninja -C _build install
```

With older bubblewrap, host tools and `--workspace-mode bind` can work
without overlay/image support. Sized scratch mounts need at least 0.9.
See [host requirements](requirements.md) before changing host policy.

## Build plybox from source

With access to this repository, Rust and the musl build dependencies:

```sh
git clone https://github.com/iluxav/plybox
cd plybox
rustup target add x86_64-unknown-linux-musl
make build
```

The executable is `target/x86_64-unknown-linux-musl/release/plybox`.
`make install` copies it into `~/.local/bin`; `make uninstall` removes that
copy while retaining sessions and cached images. See
[build dependencies and tests](../CONTRIBUTING.md#build).
