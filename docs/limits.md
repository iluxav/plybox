# Storage and traffic limits

```toml
[limits]
file_size = "256M"
tmpfs = "192M"
bytes_out = "20M"
bytes_in = "200M"
# Optional: requires a separately provisioned bounded session volume.
# disk = "1G"
```

The matching flags are `--file-size`, `--tmpfs`, `--bytes-out`, `--bytes-in`,
and `--disk`. Sizes accept bytes or binary K/M/G suffixes. Omitted fields
leave that particular limit unset. Invalid sizes and integer overflow are
errors. Saved policies retain these values; normal flags can override them
on resume.

## What each limit means

| Setting | Scope | Enforcement |
| --- | --- | --- |
| `file_size` | Logical size of each regular file the workload writes, including sparse files | Linux hard and soft `RLIMIT_FSIZE`, inherited by children; exceeding it gives `EFBIG` or `SIGXFSZ` |
| `tmpfs` | Combined data capacity of `/tmp`, `/home`, `/dev/shm` | Three equally sized tmpfs mounts, each rounded down to whole 4 KiB pages; filling one gives `ENOSPC` |
| `disk` | Total data capacity of the filesystem containing the persistent session, including `upper/`, overlay work data and records | Verified capacity-limited ext4, XFS or tmpfs volume; filling it gives `ENOSPC` |
| `bytes_out` | Bytes written by the proxy to all upstream connections during one run | Shared reservation counter before socket writes |
| `bytes_in` | Bytes read by the proxy from all upstream connections during one run | Shared reservation counter before socket reads |

`file_size` alone is **not** a total disk limit: many small files can still
fill a filesystem. Zero is valid for file and traffic limits. A scratch
limit must be at least 12K. A disk limit must be positive and large enough
for its automatically selected scratch limit.

With `tmpfs`, the root mount and `/dev` are read-only. `/dev/shm` remains a
separate bounded writable mount. This prevents writes elsewhere in the
image's temporary root or ordinary files in `/dev` from escaping the
scratch budget. A mount cannot borrow unused capacity from another mount.
Tmpfs uses memory and may use swap; its data cap is not a total memory or
inode/metadata cap. Combine it with memory and process limits appropriate
to the host. Existing cgroup limits still have their existing warning-only
fallback when no cgroup can be obtained.

## Persistent disk storage

This version does **not** create a per-directory quota on an ordinary host
disk. Provision a bounded filesystem and put the session there:

```sh
plybox run --session /srv/agent-volume/session --disk 1G \
  --tmpfs 192M --file-size 256M -- python3 agent.py
```

The volume must already exist and have total data capacity no greater than
1 GiB in this example. A small ext4/XFS volume can preserve sessions across
reboots. A size-limited tmpfs works for testing, but unmounting it loses its
contents. Several sessions on the same volume share its available space;
use a separate volume per session when independent capacity is needed.

Plybox checks **total capacity**, not currently free space, before executing
the command, and repeats the check on resume. It rejects unsupported
filesystems, oversized volumes, and existing nested mounts within the session. Disk caps require namespace isolation and an overlay workspace;
bind mode and gVisor currently reject them. Scratch caps also currently
require namespace isolation, and bubblewrap 0.9 or newer for its tmpfs
`--size` option (Debian 12 ships 0.8, Ubuntu 22.04 0.6): plybox checks the
version and refuses with that reason instead of a bwrap "Unknown option". No automatic fallback to a disk-usage poller.
The host/operator remains trusted not to enlarge or replace mounts during
a run.

If `disk` is set and `tmpfs` is omitted, scratch defaults to the smaller of
`disk` and 64 MiB, divided among the three scratch mounts. Persistent data
and scratch have **separate** budgets; the disk value is not their sum.
Existing files in the workspace's read-only lower layer do not count until
copied into the upper layer. Allocated blocks count, including deleted files
still held open; sparse logical size is controlled separately by `file_size`.
Filesystem metadata is not included in the data capacity figure.

Image downloads/cache, terminal output captured by the caller, and the host
workspace updated by an explicit `apply` are outside these storage caps.
A completely full session volume can also prevent audit/metadata writes;
provision headroom and export audit records if durable external audit is
required. Disk caps are resource containment, not a guarantee of audit
availability.

## Traffic accounting

Budgets are shared across every allowed host and every connection, including
learn mode. A new connection does not reset them. Each invocation, including
a resume, starts a new traffic budget; disk usage persists with the session.

The proxy meters the upstream TCP transport **below TLS**. This includes
TLS handshakes, encrypted records and substituted secrets, consistently for
opaque tunnels and connections where secrets are inserted. TCP/IP headers,
retransmissions, DNS lookups and image downloads are outside these counters.
For inbound traffic this bounds reads accepted by the proxy; a remote peer
can still send extra data into the kernel socket buffers. It is not a
network-interface billing limit.

Reservations prevent concurrent I/O from exceeding the cap; short or failed
I/O refunds unused bytes. A connection can be refused when all remaining
budget is reserved by other connections, even if they later refund some.
Exhaustion closes the affected stream; later CONNECT requests are refused
when a direction has no budget left. It does not kill the agent. Incomplete
responses must be handled as errors by the application.

`net_limit` records the direction and limit when I/O cannot reserve more
bytes. `net_usage` records run-wide transport byte counts. Existing per-host
`net.bytes_*` fields describe forwarded content: on secret-bearing hosts
they count HTTP plaintext, so they are not interchangeable with the
transport totals. A snapshot marked `complete = false` means a connection
was still shutting down when the supervisor recorded the totals.

## Narrow ioctl policy

The workload filter allows only exact request codes for terminal attributes
(`TCGETS`, `TCSETS*` and their `*2` variants), terminal foreground groups and
window size, pipe/socket buffered-byte queries and nonblocking flags,
close-on-exec flags, opening a pseudoterminal, and acquiring its controlling
terminal (`TIOCSCTTY` only with argument zero, never a stealing request). All other requests return
`ENOSYS`, consistent with the existing syscall filter. This is not an
allowlist for whole ioctl families. Device administration, terminal input
injection, filesystem flag changes and descriptor-returning terminal peer
requests remain excluded. Request comparison uses the low 32 bits, matching
the Linux ioctl ABI. The filter applies after sandbox setup and is inherited
by workload descendants; it does not restrict the trusted supervisor.

## Validation

`make test` covers the actual kernel ioctl filter, shared byte counters,
concurrency, short writes, overflow and configuration errors.
`make test-limits` runs bounded integration tests with a private 16 MiB tmpfs
in a new user/mount namespace and local TCP/TLS fixtures. It verifies scratch
and aggregate disk exhaustion, per-file limits, descendants, resume/apply,
concurrent tunnels, TLS handshakes and secret substitution. It needs Linux
user namespaces, bubblewrap, Python 3, openssl, mount, unshare and setpriv; it makes no
external network requests and does not modify host mounts or real sessions.
If Python/Node images are already cached, or `tests/tools/runsc` exists, the
suite also checks those runtimes. It does not download them.

The implementation follows Linux's [tmpfs size semantics](https://man7.org/linux/man-pages/man5/tmpfs.5.html),
[filesystem capacity reporting](https://man7.org/linux/man-pages/man2/statfs.2.html),
and [resource-limit inheritance](https://man7.org/linux/man-pages/man2/getrlimit.2.html).
