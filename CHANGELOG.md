# Changelog

All notable changes to plybox are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first public release.

### Changed

- New runs and policies default to gVisor. Namespace isolation requires
  explicit `--isolation ns` or `isolation = "ns"` (operator overrides still
  take precedence).
- The default gVisor workspace is recorded as `readonly`, with no saved
  copy for `diff`, `apply` or resume. Explicit overlay staging and disk/tmpfs
  caps require the namespace tier; `bind` still writes directly.
- Old saved policies and metadata without isolation retain namespace
  semantics, so existing overlay sessions remain resumable.

### Added

- Release builds bundle gVisor `release-20261102.0` and its required helpers,
  compressed with a pure-Rust decoder. The default tier needs only plybox
  and util-linux's `unshare`. A private cache verifies every executable's
  SHA-512 on every launch and atomically repairs damaged files. Configured
  runtimes still override the bundle; unbundled development builds retain
  `PATH` lookup. `version` names the release, the start event records the
  runtime path and hash, and release assets include gVisor's license.
- `plybox run`: a box with its own namespaces, loopback-only network, a
  seccomp allowlist, Landlock and no capabilities, around any command.
- A hostname allow-list proxy as the box's only way out; DNS-rebinding
  refusal; every decision recorded.
- Secrets the box never sees: placeholders inside, swapped for the real
  value only toward the secret's own host.
- The workspace as a copy: `diff` (`--patch`), `apply`, `discard`,
  `sessions` (`--prune`), and `--resume`.
- OCI images as the box's root (`--image`, `pull`, `images`), pulled and
  verified without Docker.
- gVisor tier (`--isolation gvisor`).
- Limits: memory, processes, CPU, file size, scratch space, session disk,
  and network traffic budgets.
- Learn mode (`--learn`) to write a policy from what a run reached.
- Exposure report: every host path, secret source and `map` printed at start
  and recorded.
- Operator rules (`/etc/plybox/operator.toml`) for hosting other people's
  agents.
