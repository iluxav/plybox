#!/usr/bin/env bash
# All mounts are inside a fresh user+mount namespace; the host is unchanged.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
bin=${1:-"$root/target/x86_64-unknown-linux-musl/release/plybox"}
volume=$(mktemp -d /tmp/plybox-volume.XXXXXX)
trap 'rmdir "$volume"' EXIT
unshare --user --map-current-user --keep-caps --mount --fork bash -euc '
    mount --make-rprivate /
    mount -t tmpfs -o size=16M,nr_inodes=4096 tmpfs "$1"
    # Exercise the supervisor without namespace-root capabilities: otherwise
    # mode-000 overlay directories accidentally become readable in tests.
    setpriv --inh-caps=-all --ambient-caps=-all python3 "$2/tests/limits/run.py" "$3" --disk-volume "$1"
' bash "$volume" "$root" "$bin"
