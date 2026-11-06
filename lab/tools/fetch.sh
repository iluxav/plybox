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

# --- the comparison column tools (compare/run.sh) ---
SRT_VERSION="0.0.81"          # @anthropic-ai/sandbox-runtime
GREYWALL_TAG="v0.3.7"; GREYPROXY_TAG="v0.4.5"

echo "Anthropic sandbox-runtime $SRT_VERSION (npm, local prefix)"
mkdir -p srt && npm install --silent --no-fund --no-audit --prefix srt "@anthropic-ai/sandbox-runtime@$SRT_VERSION"
srt/node_modules/.bin/srt --version

gh_asset() { # repo tag name-regex → download url
  curl -fsSL "https://api.github.com/repos/$1/releases/tags/$2" | grep -oP '"browser_download_url":\s*"\K[^"]+' | grep -E "$3" | head -1
}
for spec in "GreyhavenHQ/greywall:$GREYWALL_TAG:greywall:Linux_x86_64" "GreyhavenHQ/greyproxy:$GREYPROXY_TAG:greyproxy:linux_amd64"; do
  IFS=: read -r repo tag name pat <<<"$spec"
  echo "$name $tag"
  curl -fsSL -o "$name.tgz" "$(gh_asset "$repo" "$tag" "$pat\.tar\.gz$")"
  curl -fsSL -o "$name.sums" "$(gh_asset "$repo" "$tag" 'checksums')"
  grep "$pat" "$name.sums" | sed "s/${name}_[^ ]*/$name.tgz/" | sha256sum -c -
  mkdir -p "x-$name" && tar xzf "$name.tgz" -C "x-$name" && cp "$(find "x-$name" -name "$name" -type f | head -1)" "$name"
  chmod +x "$name"; rm -rf "x-$name" "$name.tgz" "$name.sums"
done
ln -sf greywall greywatch
./greywall --version | head -1; ./greyproxy --version | head -1
