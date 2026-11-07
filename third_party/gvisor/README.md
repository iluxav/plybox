# Bundled gVisor runtime

The single pin is [`manifest.json`](manifest.json): upstream release
`release-20261102.0`, Linux x86_64. `scripts/fetch-gvisor.py` checks the
download against both this committed archive SHA-512 and the release's
[`SHA512SUMS`](https://github.com/google/gvisor/releases/download/release-20261102.0/SHA512SUMS).
Per-file hashes were computed from that verified archive. `build.rs`
checks them again, then embeds gzip-compressed files when
`PLYBOX_EMBED_RUNSC` names the downloaded runtime directory.

The runtime needs these five files (74,363,494 bytes uncompressed):

| File | Used for |
|---|---|
| `runsc` | OCI launcher and gofer |
| `gvisor-bin/gvisor_sentry` | user-space kernel |
| `gvisor-bin/gvisor-sentry-prewarmer` | sentry startup |
| `gvisor-bin/runsc-fd-parking` | file descriptors during sandbox startup |
| `gvisor-bin/gvisor-proc-umounter` | removing the gofer's proc mount |

This selection was verified by starting rootless sandboxes with only
these files and by running the policy, security and image suites with the
embedded runtime.
Upstream's pinned [sandbox startup](https://github.com/google/gvisor/blob/release-20261102.0/runsc/sandbox/sandbox.go)
and [gofer startup](https://github.com/google/gvisor/blob/release-20261102.0/runsc/cmd/gofer.go)
use these helpers. The checkpoint gofer, metric server and containerd shim
are unused by plybox and excluded.

`src/embedded.rs` extracts into
`$XDG_STATE_HOME/plybox/runtimes/<SHA-512 of manifest.json>/` (default
`~/.local/state/plybox/runtimes/`). Directories are 0700, executables 0500.
A shared flock serializes verification and extraction. Each executable is
written to a new temporary file, checked against its compiled SHA-512,
fsynced, renamed and followed by a directory fsync. Every launch rechecks
all five files. Damaged regular files are replaced; unsafe permissions,
symlinks, hard links and non-regular entries are refused. Embedded cache
errors never fall back to another runtime.

The launcher pins `GVISOR_SIDECAR_BINARIES_DIR` and
`GVISOR_ENFORCE_RELEASE` so inherited environment variables cannot select
unchecked sidecars. The caller's host uid remains trusted, as it is for
the plybox executable itself; this cache does not protect against another
host process running as that uid and racing a launch.

## Measurements (2026-11-07)

Static musl release builds on the test host:

| Item | Bytes |
|---|---:|
| plybox before embedding (`8205514`) | 3,167,136 |
| plybox with the embedded runtime | 36,144,032 |
| Selected runtime files, uncompressed | 74,363,494 |
| Embedded gzip payload | 32,918,285 |

`tests/policy/embedded.py` measured a fresh-cache launch at 279.71 ms and
20 warm launches at a median 92.29 ms. Verification of all five cached
executables took a median 70.46 ms (range 69.77–71.16 ms). These are local
host measurements with a fresh state directory, not a cold machine or
fresh disk page cache. Compression saves 41.45 MB of payload; the first
launch adds about 187 ms over the measured warm median.

Verification exceeds the initial 30 ms guideline, but it still runs on
every launch: extraction-only verification cannot detect later tampering,
and the project's goal explicitly prioritizes security over startup time.
No verification or decompression runs in the steady-state workload path.

All suites passed: 28 unit tests; policy's 37 shell checks (including three
wrappers for 28 embedded-runtime, 22 default-tier and 6 gVisor checks);
26 session lifecycle and 38 resume checks; 13 limits checks. Security and
image suites each ran 41 probes per tier, with 40 closed and one unmeasured
(ssh-agent unavailable). Security also passed 7 workloads and 2 secret
checks per tier; images passed 3 workloads per tier. Clippy with
`-D warnings` passed for both embedded and unbundled builds. The unbundled
build separately passed all 22 default-tier checks; clean fetching,
tampered build-input rejection and temporary-prefix installation passed.
The GitHub release workflow and a fresh OS installation were not run.

## License and updates

[`LICENSE`](LICENSE) is copied unchanged from the
[pinned upstream source](https://github.com/google/gvisor/blob/release-20261102.0/LICENSE).
It includes Apache-2.0 and upstream's third-party notices. Neither the
binary archive nor the source tree at this tag contains a separate NOTICE
file. Release packaging ships `gvisor-LICENSE` alongside the executable
and includes `gvisor-NOTICE` if a future pin adds one.

To update the pin, verify the new archive against upstream SHA512SUMS,
review its required runtime files and licensing, update the manifest and
vendored license, then run all suites with `make test-all` and Clippy in
both embedded and unbundled modes. Never update a checksum just to make a
mismatched download pass.
