#!/usr/bin/env bash
# Fetch gVisor (runsc and its gvisor-bin/ helpers) into this directory, for
# the gVisor-tier tests. The release's SHA512 is checked. Nothing is
# installed system-wide, and the files are gitignored.
#
#   tests/tools/fetch.sh        (or: make tools)
#
# Pinned to the version the test results were produced with; bump on purpose.
set -euo pipefail
cd "$(dirname "$0")"
ARCH="$(uname -m)"
GVISOR_TAG="release-20261102.0"

echo "gVisor $GVISOR_TAG"
B="https://github.com/google/gvisor/releases/download/$GVISOR_TAG"
curl -fsSL -o gvisor.tar.bz2 "$B/gvisor-$ARCH.tar.bz2"
curl -fsSL -o SHA512SUMS "$B/SHA512SUMS"
grep " gvisor-$ARCH.tar.bz2\$" SHA512SUMS | sed "s/gvisor-$ARCH.tar.bz2/gvisor.tar.bz2/" | sha512sum -c -
rm -rf gv && mkdir gv && tar xjf gvisor.tar.bz2 -C gv
SRC=$(dirname "$(find gv -name runsc -type f | head -1)")
cp -a "$SRC"/. . && rm -rf gv gvisor.tar.bz2 SHA512SUMS
rm -f containerd-shim-runsc-v1   # only for containerd; plybox runs runsc directly
chmod +x runsc gvisor-bin/*
./runsc --version | head -1
