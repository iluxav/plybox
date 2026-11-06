#!/usr/bin/env bash
# plybox lab, step 3 driver: measure the kernel attack surface before and
# after boxer (seccomp allowlist + Landlock), with the network box from
# step 2 underneath both.
#
#   kern/run.sh
#
# Three columns:
#   host      — no sandbox (the control)
#   box.net   — step 2: namespaces + loopback-only + proxy, NO seccomp
#   box.boxer — step 3: the same box, workload wrapped in boxer
#
# Pass = the 8 kernel doors still open after step 1 read closed in
# box.boxer, p.seccomp reads closed, and the workloads still pass.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/kern-$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$RUN"; }
trap cleanup EXIT

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --quiet --target "$TARGET" )
( cd "$LAB/boxer" && cargo build --release --quiet )
PROBE="$LAB/probe/target/$TARGET/release/probe"
BOXER="$LAB/boxer/target/release/boxer"

LO_PORT=47821; LAN_PORT=47822
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
socat TCP-LISTEN:$LO_PORT,bind=127.0.0.1,fork,reuseaddr SYSTEM:'echo plybox-host' & PIDS+=($!)
[ -n "$LAN_IP" ] && { socat TCP-LISTEN:$LAN_PORT,bind="$LAN_IP",fork,reuseaddr SYSTEM:'echo plybox-host' & PIDS+=($!); }
export PROBE_HOST_LO="127.0.0.1:$LO_PORT"
export PROBE_HOST_LAN="${LAN_IP:+$LAN_IP:$LAN_PORT}"
# Same inputs for every column, so the no-sandbox control measures every door
# and the box's BLOCKED rows mean "tried the real path and failed".
export PROBE_HOST_HOME="$HOME"
export PROBE_HOST_UID="$(id -u)"
export PROBE_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

ALLOW="api.anthropic.com,registry.npmjs.org,*.anthropic.com"
mkdir -p "$RUN/sock"
python3 "$LAB/net/proxy.py" --socket "$RUN/sock/sock" --allow "$ALLOW" --log "$OUT/proxy.jsonl" & PIDS+=($!)
for i in $(seq 1 50); do [ -S "$RUN/sock/sock" ] && break; sleep 0.1; done

# A fresh git workspace and an "outside" directory per column.
prepare() {
  WORK="$RUN/work-$1"; export PROBE_OUTSIDE="$RUN/outside-$1"
  mkdir -p "$WORK" "$PROBE_OUTSIDE"; git -C "$WORK" init -q
}

run_box() { # outfile, extra-env...
  local out="$1"; shift
  prepare "$(basename "$out" .tsv)"
  cp "$PROBE" "$WORK/probe"; cp "$LAB/net/inside.sh" "$WORK/inside.sh"
  env "$@" bash "$LAB/net/box.sh" "$RUN/sock" "$WORK" -- sh /work/inside.sh /work/probe \
    >"$out" 2>"${out%.tsv}.err" || echo "  box exited nonzero — see ${out%.tsv}.err" >&2
}

echo "running box.net (no seccomp)" >&2
run_box "$OUT/box.net.tsv"
echo "running box.boxer (seccomp + landlock)" >&2
run_box "$OUT/box.boxer.tsv" BOXER_BIN="$BOXER"

# The control: no sandbox, same inputs, from its own git workspace.
prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

python3 "$LAB/kern/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
