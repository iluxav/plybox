#!/usr/bin/env bash
# plybox lab: the real binary against the same 41 probes and workloads.
#
#   v0/run.sh
#
# Columns: host (control), plybox (the binary, slice 1). The report adds the
# lab's own bwrap+boxer box (latest kern-* box.boxer) as the reference the
# binary must match or beat.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$LAB/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/v0-$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$RUN"; }
trap cleanup EXIT

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --quiet --target "$TARGET" )
( cd "$ROOT/plybox" && cargo build --release --quiet )
PROBE="$LAB/probe/target/$TARGET/release/probe"
PLYBOX="$ROOT/plybox/target/release/plybox"

LO_PORT=47871; LAN_PORT=47872
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
socat TCP-LISTEN:$LO_PORT,bind=127.0.0.1,fork,reuseaddr SYSTEM:'echo plybox-host' & PIDS+=($!)
[ -n "$LAN_IP" ] && { socat TCP-LISTEN:$LAN_PORT,bind="$LAN_IP",fork,reuseaddr SYSTEM:'echo plybox-host' & PIDS+=($!); }
export PROBE_HOST_LO="127.0.0.1:$LO_PORT"
export PROBE_HOST_LAN="${LAN_IP:+$LAN_IP:$LAN_PORT}"
export PROBE_HOST_HOME="$HOME"
export PROBE_HOST_UID="$(id -u)"
export PROBE_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

prepare() {
  WORK="$RUN/work-$1"; export PROBE_OUTSIDE="$RUN/outside-$1"
  mkdir -p "$WORK" "$PROBE_OUTSIDE"; git -C "$WORK" init -q
  cp "$PROBE" "$WORK/probe"; cp "$LAB/net/inside.sh" "$WORK/inside.sh"
}
hostcheck() {
  for pair in "f.inject.githook:.git/hooks/pre-commit" "f.inject.agentcfg:.claude/settings.json"; do
    id="${pair%%:*}"; rel="${pair#*:}"
    if [ -e "$WORK/$rel" ]; then printf '%s\tALLOWED\t%s exists in the real workspace\n' "$id" "$rel"
    else printf '%s\tBLOCKED\t%s never reached the real workspace\n' "$id" "$rel"; fi
  done > "$OUT/$1.host.tsv"
}

NODE_DIR="$HOME/.local/share/mise/installs/node"
echo "running plybox ($("$PLYBOX" version))" >&2
prepare plybox
SESSION="$RUN/session"
"$PLYBOX" run --quiet --session "$SESSION" --work "$WORK" \
  --allow api.anthropic.com --allow '*.anthropic.com' --allow registry.npmjs.org \
  --ro-bind "$NODE_DIR:/opt/node" --env PATH=/opt/node/latest/bin:/usr/local/bin:/usr/bin:/bin \
  --env PROBE_HOST_LO --env PROBE_HOST_LAN --env PROBE_HOST_HOME --env PROBE_HOST_UID \
  --env PROBE_SSH_AUTH_SOCK --env PROBE_OUTSIDE \
  -- sh /work/inside.sh /work/probe >"$OUT/plybox.tsv" 2>"$OUT/plybox.err" \
  || echo "  plybox exited nonzero — see $OUT/plybox.err" >&2
hostcheck plybox
cp "$SESSION/record.jsonl" "$OUT/record.jsonl" 2>/dev/null || true

prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

med() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
t() { local s; s=$(date +%s%N); "$@" >/dev/null 2>&1 || true; echo $(( ($(date +%s%N) - s) / 1000000 )); }
{
  echo "tier	median_ms"
  echo "host	$(for i in $(seq 10); do t /bin/true; done | med)"
  echo "plybox run	$(cd "$RUN" && for i in $(seq 10); do t "$PLYBOX" run --quiet --session "$RUN/lat-$i" --work "$RUN" -- /bin/true; done | med)"
} > "$OUT/latency.tsv"

python3 "$LAB/v0/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
