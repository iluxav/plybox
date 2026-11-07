# Contributing to plybox

Thanks for helping. plybox is a security tool, so one rule comes before style:
**every claim has a test.** A feature, a fix or a sentence in the README that
says "the box cannot X" needs a check that fails on the code before the
change and passes after it. Measure first, then decide.

## Build

```sh
rustup target add x86_64-unknown-linux-musl
sudo apt install musl-tools   # Debian/Ubuntu: optional, the musl C compiler
make build          # static binary: target/x86_64-unknown-linux-musl/release/plybox
make install        # → ~/.local/bin/plybox
```

The release binary is static (musl) on purpose: with `--image`, plybox runs
itself inside the image, so it must not depend on the image's libc.

`make build` and `make install` fetch and embed the pinned gVisor runtime.
They require Python 3.11+ and curl for the first download. `make tools`
only fetches it into `tests/tools/`; it does not rebuild plybox. The pin,
archive checksum and executable checksums live in
[`third_party/gvisor/manifest.json`](third_party/gvisor/manifest.json).
The fetch checks the archive against both the committed pin and upstream
`SHA512SUMS`; the build checks each file again before embedding it.

Plain `cargo build` / `cargo test` remain offline development builds with
no embedded payload. Use `--runsc tests/tools/runsc` or install runsc on
`PATH` with those builds. Set `PLYBOX_EMBED_RUNSC="$PWD/tests/tools"` to
embed it in a direct Cargo invocation. `plybox version` says which kind of
build it is and names the embedded release. The payload is gzip-compressed
at build time and decoded with flate2's pure-Rust backend.

## Test

| Command | What it measures | Time |
|---|---|---|
| `make test` | unit tests, including the real seccomp filter | seconds |
| `make test-policy` | embedded runtime integrity and precedence; default tier, hostile policies, operator rules, gVisor ownership, writes and limits | seconds |
| `make test-sessions` | namespace session lifecycle, `apply` safety, resume (38 checks) | ~20 s |
| `make test-limits` | storage, ioctl and traffic caps (local fixtures, no internet) | under a minute |
| `make test-security` | 41 attacker probes + real workloads, both tiers (network) | ~2 min |
| `make test-image` | the same inside an OCI image (network) | ~2 min |
| `make test-all` | everything above | |

The `make test-*` integration targets build the embedded binary first.
The gVisor checks also need util-linux's `unshare`. CI runs the embedded
runtime checks too, including a fresh state directory with no runsc on
`PATH`, tampering, concurrent extraction and configured runtime overrides.
When invoked directly, scripts skip external-runtime checks if their
`tests/tools/runsc` fixture is absent.
Namespace-only tests explicitly pass `--isolation ns`. To repeat the
ownership checks with an image:

```sh
python3 tests/policy/gvisor.py target/x86_64-unknown-linux-musl/release/plybox tests/tools/runsc --image python:3.13-slim
```

The suites need a Linux machine with bubblewrap and unprivileged user
namespaces. `test-security` and `test-image` also use `socat` and network
access. Every suite works in throwaway directories and never touches your
real sessions.

## Layout

```
src/
  main.rs         CLI entry: subcommands
  policy.rs       TOML policy + flags → one Policy
  operator.rs     operator rules (the owner's ceiling)
  launch.rs       builds and runs the box (gVisor default, namespace opt-in)
  gvisor.rs       the same as an OCI bundle for runsc
  embedded.rs     private, hash-verified cache for the bundled runtime
  inner.rs        plybox __inner: in-box forwarder, Landlock, seccomp, exec
  seccomp.rs      the syscall allowlist
  landlock_fs.rs  Landlock rules
  proxy.rs        the hostname-deciding CONNECT proxy
  secrets.rs      placeholders, the session CA, TLS termination
  byte_budget.rs  run-wide traffic budgets
  limits.rs       cgroup v2 limits (direct, or systemd-run)
  storage.rs      file-size, scratch and disk caps
  image.rs        OCI registry pull, layer verification, cache
  workspace.rs    sessions: overlay copy, diff, apply, resume
  exposure.rs     what a run exposes from the host (printed + recorded)
  record.rs       the JSONL record
tests/
  probe/          the 41 attacker probes (a small static binary)
  security/       probes + workloads against plybox, both tiers
  image/          the same inside an OCI image
  policy/         hostile-policy and operator checks
  sessions/       lifecycle (run.sh) and resume (resume.py)
  limits/         storage, ioctl and traffic caps
  helpers/        test CA, a TLS stand-in for an API, in-box workloads
  tools/          verified gVisor download cache (not committed)
build.rs          verifies and compresses the optional embedded payload
scripts/          pinned runtime fetcher
third_party/      runtime manifest, provenance and license
docs/             user docs; research.md is the measurement log behind the design
examples/         ready-made policies
```

## Design notes

- **gVisor is the default engine.** `--isolation ns` opts into bubblewrap
  for namespaces and staged workspace edits. Both tiers use the proxy,
  forwarder, seccomp and record; the namespace tier is frozen but tested.
- **The supervisor stays outside the box.** Secrets, the proxy and the record
  never run where the workload can reach them.
- **Fail closed.** A rule that can't be enforced refuses the run; a tool
  that ignores the proxy gets no network.
- [`docs/research.md`](docs/research.md) is the lab log: the experiments and
  numbers that shaped these choices. [`TODO.md`](TODO.md) lists what's next.

## Pull requests

1. Open an issue first for anything bigger than a small fix.
2. Add or update the check that proves the change, and say in the PR which
   check fails without it.
3. Run `make test-all` (or say which suites you couldn't run, and why).
4. `cargo clippy --all-targets` must stay clean.

Security problems: please don't open a public issue; see
[SECURITY.md](SECURITY.md).
