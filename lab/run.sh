#!/usr/bin/env bash
# plybox lab, step 1: run the attack probes under each sandbox config and
# print a matrix of what each one stops.
#
#   ./run.sh              every config this machine can run without root
#   ./run.sh host tight   only the named configs
#
# Nothing here needs root. Each config gets a fresh throwaway workspace.
set -euo pipefail

LAB="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$RUN"' EXIT

# --- the probe: one static binary, so it runs inside any root filesystem ---
TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --quiet --target "$TARGET" )
cp "$LAB/probe/target/$TARGET/release/probe" "$RUN/probe"

# --- stand-ins for "a service running on the host" ---
LO_PORT=47801
LAN_PORT=47802
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
socat TCP-LISTEN:$LO_PORT,bind=127.0.0.1,fork,reuseaddr SYSTEM:'echo plybox-host' &
if [ -n "$LAN_IP" ]; then
  socat TCP-LISTEN:$LAN_PORT,bind="$LAN_IP",fork,reuseaddr SYSTEM:'echo plybox-host' &
fi
sleep 0.3

export PROBE_HOST_HOME="$HOME"
export PROBE_HOST_UID="$(id -u)"
export PROBE_HOST_LO="127.0.0.1:$LO_PORT"
export PROBE_HOST_LAN="${LAN_IP:+$LAN_IP:$LAN_PORT}"
export PROBE_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

# A fresh git workspace and a directory "outside" it, per config.
prepare() {
  WS="$RUN/ws-$1"
  export PROBE_OUTSIDE="$RUN/outside-$1"
  mkdir -p "$WS" "$PROBE_OUTSIDE"
  git -C "$WS" init -q
}

# --- configs -----------------------------------------------------------------

# No sandbox: the control. A probe that is not ALLOWED here proves nothing.
config_host() {
  ( cd "$WS" && "$RUN/probe" )
}

# What a quick wrapper does: host filesystem read-only, workspace writable,
# everything else (network, IPC, processes) shared with the host.
config_naive() {
  bwrap --ro-bind / / --dev /dev --proc /proc \
        --bind "$WS" "$WS" --chdir "$WS" \
        "$RUN/probe"
}

# Namespaces done properly, network left on (an agent must reach its API):
# own user/pid/ipc/uts namespaces, empty home, only /usr visible, no
# capabilities, no nested user namespaces.
config_tight_net() {
  bwrap --unshare-all --unshare-user --share-net --die-with-parent --new-session \
        --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib /lib64 \
        --symlink usr/bin /bin --symlink usr/bin /sbin \
        --ro-bind /etc/resolv.conf /etc/resolv.conf \
        --proc /proc --dev /dev --tmpfs /tmp --tmpfs /home \
        --bind "$WS" /work --ro-bind "$RUN/probe" /probe --chdir /work \
        --cap-drop ALL --disable-userns \
        /probe
}

# The same, with no network at all.
config_tight() {
  bwrap --unshare-all --unshare-user --die-with-parent --new-session \
        --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib /lib64 \
        --symlink usr/bin /bin --symlink usr/bin /sbin \
        --proc /proc --dev /dev --tmpfs /tmp --tmpfs /home \
        --bind "$WS" /work --ro-bind "$RUN/probe" /probe --chdir /work \
        --cap-drop ALL --disable-userns \
        /probe
}

ALL=(host naive tight_net tight)
CONFIGS=("${@:-${ALL[@]}}")

for c in "${CONFIGS[@]}"; do
  prepare "$c"
  echo "running: $c" >&2
  if ! "config_$c" > "$OUT/$c.tsv" 2> "$OUT/$c.err"; then
    echo "  $c failed to start — see $OUT/$c.err" >&2
  fi
  [ -s "$OUT/$c.err" ] || rm -f "$OUT/$c.err"
done

"$RUN/probe" --list > "$OUT/probes.tsv"
{
  echo "kernel: $(uname -r)  arch: $(uname -m)  date: $STAMP"
  echo "configs: ${CONFIGS[*]}"
} > "$OUT/machine.txt"

python3 "$LAB/matrix.py" "$OUT" "${CONFIGS[@]}" | tee "$OUT/matrix.md"
echo "results: $OUT" >&2
