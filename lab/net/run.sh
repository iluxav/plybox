#!/usr/bin/env bash
# plybox lab, step 2 driver: start the proxy, run the box against it, and
# show the attack probes and the workloads side by side.
#
#   net/run.sh
#
# Pass = the n.* probes read BLOCKED (no way around the proxy) while the
# allowed-host workloads read ok and the denied-host workload fails.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/net-$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$RUN"; }
trap cleanup EXIT

# Stand-ins for "a service listening on the host": one on loopback, one on
# the host's LAN address. The box must not reach either.
LO_PORT=47811; LAN_PORT=47812
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
socat -u TCP-LISTEN:$LO_PORT,bind=127.0.0.1,fork,reuseaddr OPEN:/dev/null & PIDS+=($!)
[ -n "$LAN_IP" ] && { socat -u TCP-LISTEN:$LAN_PORT,bind="$LAN_IP",fork,reuseaddr OPEN:/dev/null & PIDS+=($!); }
export PROBE_HOST_LO="127.0.0.1:$LO_PORT"
export PROBE_HOST_LAN="${LAN_IP:+$LAN_IP:$LAN_PORT}"
# Same inputs for the control and the box (see kern/run.sh).
export PROBE_HOST_HOME="$HOME"
export PROBE_HOST_UID="$(id -u)"
export PROBE_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe" && RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --quiet --target "$TARGET" )

# The box only ever reaches these names. Everything else must be refused.
ALLOW="api.anthropic.com,registry.npmjs.org,*.anthropic.com"
mkdir -p "$RUN/sock"
python3 "$LAB/net/proxy.py" --socket "$RUN/sock/sock" --allow "$ALLOW" --log "$OUT/proxy.jsonl" &
PIDS+=($!)
for i in $(seq 1 50); do [ -S "$RUN/sock/sock" ] && break; sleep 0.1; done
[ -S "$RUN/sock/sock" ] || { echo "proxy socket never appeared" >&2; exit 1; }

# A fresh git workspace and an "outside" directory per column.
prepare() {
  WORK="$RUN/work-$1"; export PROBE_OUTSIDE="$RUN/outside-$1"
  mkdir -p "$WORK" "$PROBE_OUTSIDE"; git -C "$WORK" init -q
}

# The work dir is bound writable at /work; put the scripts the box runs there.
prepare box
cp "$LAB/probe/target/$TARGET/release/probe" "$WORK/probe"
cp "$LAB/net/inside.sh" "$WORK/inside.sh"

echo "running box (allow: $ALLOW)" >&2
bash "$LAB/net/box.sh" "$RUN/sock" "$WORK" -- sh /work/inside.sh /work/probe \
  >"$OUT/inside.tsv" 2>"$OUT/box.err" || echo "  box exited nonzero — see $OUT/box.err" >&2

# The control: no sandbox, same inputs, from its own git workspace.
PROBE="$LAB/probe/target/$TARGET/release/probe"
prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

python3 "$LAB/net/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
