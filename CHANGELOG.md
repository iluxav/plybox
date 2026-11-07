# Changelog

All notable changes to plybox are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

The first public release.

### Added

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
