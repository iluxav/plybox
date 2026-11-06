#!/usr/bin/env bash
# Fetch the third-party binaries step 5 needs, into this directory, verifying
# what the publishers let us verify. Nothing is installed system-wide.
#
#   tools/fetch.sh
#
#   runsc (+ gvisor-bin/ sidecars)  — gVisor, from the GitHub release, SHA512 checked
#   firecracker                      — Firecracker VMM, from the GitHub release
#   vmlinux                          — a guest kernel from Firecracker's CI bucket
#
# Pinned to the versions the lab's results were produced with; bump on purpose.
set -euo pipefail
cd "$(dirname "$0")"
ARCH="$(uname -m)"
GVISOR_TAG="release-20261102.0"
FC_TAG="v1.17.0"
FC_CI="v1.15"            # newest CI prefix with x86_64 kernels at the time

echo "gVisor $GVISOR_TAG"
B="https://github.com/google/gvisor/releases/download/$GVISOR_TAG"
curl -fsSL -o gvisor.tar.bz2 "$B/gvisor-$ARCH.tar.bz2"
curl -fsSL -o SHA512SUMS "$B/SHA512SUMS"
grep " gvisor-$ARCH.tar.bz2\$" SHA512SUMS | sed "s/gvisor-$ARCH.tar.bz2/gvisor.tar.bz2/" | sha512sum -c -
rm -rf gv && mkdir gv && tar xjf gvisor.tar.bz2 -C gv
SRC=$(dirname "$(find gv -name runsc -type f | head -1)")
cp -a "$SRC"/. . && rm -rf gv gvisor.tar.bz2 SHA512SUMS
chmod +x runsc gvisor-bin/*
./runsc --version | head -1

echo "Firecracker $FC_TAG"
curl -fsSL -o fc.tgz "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_TAG/firecracker-$FC_TAG-$ARCH.tgz"
tar xzf fc.tgz && mv "release-$FC_TAG-$ARCH/firecracker-$FC_TAG-$ARCH" firecracker && rm -rf "release-$FC_TAG-$ARCH" fc.tgz
chmod +x firecracker && ./firecracker --version | head -1

echo "guest kernel (firecracker-ci/$FC_CI)"
KEY=$(curl -fsSL "http://spec.ccfc.min.s3.amazonaws.com/?prefix=firecracker-ci/$FC_CI/$ARCH/vmlinux-&list-type=2" \
      | grep -oP '(?<=<Key>)[^<]+vmlinux-[0-9]+\.[0-9]+(\.[0-9]+)?(?=</Key>)' | sort -V | tail -1)
echo "  $KEY"
curl -fsSL -o vmlinux "https://s3.amazonaws.com/spec.ccfc.min/$KEY"
file vmlinux | cut -c1-80
