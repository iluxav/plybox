# Security policy

plybox exists to contain code you don't trust, so holes in it matter. Thank
you for looking.

## Reporting a vulnerability

Please report privately through GitHub:
**[Report a vulnerability](https://github.com/iluxav/plybox/security/advisories/new)**
(the repository's Security tab → *Report a vulnerability*). Don't open a
public issue.

Include what you can:

- the plybox version (`plybox version`), kernel (`uname -r`), distribution
  and `bwrap --version`;
- the tier (`ns` or `gvisor`) and the policy or flags used;
- steps or a script that reproduces it, and what it gets through.

You'll get an acknowledgement within a few days. Fixes come with a test that
fails before them, and the advisory credits you unless you'd rather not be
named.

## In scope

- Anything that lets the workload in the box get out:
  - read or write host files it wasn't given;
  - reach a destination the policy didn't allow;
  - learn a secret's real value;
  - escape seccomp, Landlock or the namespaces;
  - outlast its limits.
- A policy file or flags weakening the box beyond what they declare, or
  getting around [operator rules](docs/operator.md).
- `plybox apply`, `diff` or `resume` writing or reading outside the
  workspace or session because of something the box left behind.
- The proxy: a hostname or address check that can be bypassed, request
  smuggling, or secret substitution toward the wrong host.

## Out of scope

These are documented limits, not vulnerabilities:

- **exfiltration through a host the policy allowed;**
- **Linux kernel bugs** reachable from the namespace tier (use
  `--isolation gvisor` for hostile code), and bugs in bubblewrap or gVisor
  themselves (report those upstream; tell us too if plybox makes them worse);
- **learn mode** (`--learn`), which is not contained on the network by
  design;
- changes you approve with `plybox apply`.

## Supported versions

Only the latest release gets security fixes.
