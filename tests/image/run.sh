#!/usr/bin/env bash
# plybox lab, images: the 41 probes and the network workloads inside an OCI
# image, in both tiers.
#
#   image/run.sh [IMAGE]        default python:3.13-slim
#
# Columns: host (control), image.ns (namespaces), image.gvisor (gVisor).
# The probe is a static binary, so it runs in any image; it is copied into
# the workspace and run as the box's command.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
ROOT="$(cd "$LAB/.." && pwd)"
IMAGE="${1:-python:3.13-slim}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/image-$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$RUN"; }
trap cleanup EXIT

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --quiet --target "$TARGET" )
( cd "$ROOT" && make build >/dev/null )
PROBE="$LAB/probe/target/$TARGET/release/probe"
PLYBOX="$ROOT/target/x86_64-unknown-linux-musl/release/plybox"
"$PLYBOX" version | grep -q '(embedded)'
export XDG_STATE_HOME="$RUN/state"
RUNSC="$LAB/tools/runsc"
"$PLYBOX" pull "$IMAGE" >/dev/null 2>&1 || "$PLYBOX" images | grep -q "^$IMAGE " || { echo "cannot pull $IMAGE" >&2; exit 1; }

LO_PORT=47891; LAN_PORT=47892
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
  cp "$PROBE" "$WORK/probe"; cp "$LAB/image/inside.py" "$WORK/inside.py"
}
hostcheck() {
  for pair in "f.inject.githook:.git/hooks/pre-commit" "f.inject.agentcfg:.claude/settings.json"; do
    id="${pair%%:*}"; rel="${pair#*:}"
    if [ -e "$WORK/$rel" ]; then printf '%s\tALLOWED\t%s exists in the real workspace\n' "$id" "$rel"
    else printf '%s\tBLOCKED\t%s never reached the real workspace\n' "$id" "$rel"; fi
  done > "$OUT/$1.host.tsv"
}

COMMON=(--quiet --image "$IMAGE" --mem 512M --pids 512 --allow pypi.org
        --env PROBE_HOST_LO --env PROBE_HOST_LAN --env PROBE_HOST_HOME --env PROBE_HOST_UID
        --env PROBE_SSH_AUTH_SOCK --env PROBE_OUTSIDE)

# Probe last: under gVisor the memory probe's OOM kill takes the sandbox.
BOXCMD='python3 /work/inside.py; /work/probe | sed "s/^/probe\t/"'

echo "running image.ns ($IMAGE)" >&2
prepare image.ns
"$PLYBOX" run "${COMMON[@]}" --isolation ns --session "$RUN/s-ns" --work "$WORK" -- sh -c "$BOXCMD" \
  >"$OUT/image.ns.tsv" 2>"$OUT/image.ns.err" || echo "  image.ns exited nonzero — see $OUT/image.ns.err" >&2
hostcheck image.ns

if [ -x "$RUNSC" ]; then
  echo "running image.gvisor ($IMAGE)" >&2
  prepare image.gvisor
  "$PLYBOX" run "${COMMON[@]}" --isolation gvisor --session "$RUN/s-gv" --work "$WORK" -- sh -c "$BOXCMD" \
    >"$OUT/image.gvisor.tsv" 2>"$OUT/image.gvisor.err" || echo "  image.gvisor exited nonzero — see $OUT/image.gvisor.err" >&2
  hostcheck image.gvisor
fi

prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

# A run that fails must not be timed as a fast one: it prints FAIL, and a
# median with any FAIL in it reads "failed".
med() { local v; v=$(cat); if grep -q FAIL <<<"$v"; then echo failed; else sort -n <<<"$v" | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; fi; }
t() { local s; s=$(date +%s%N); if "$@" >/dev/null 2>&1; then echo $(( ($(date +%s%N) - s) / 1000000 )); else echo FAIL; fi; }
# Sessions must live outside the workspace, so the timed runs get their own.
LATW="$RUN/latwork"; mkdir -p "$LATW"
{
  echo "tier	median_ms"
  echo "plybox run --image (ns)	$(cd "$RUN" && for i in $(seq 10); do t "$PLYBOX" run --quiet --isolation ns --image "$IMAGE" --session "$RUN/lat-$i" --work "$LATW" -- /bin/true; done | med)"
  [ -x "$RUNSC" ] && echo "plybox run --image --isolation gvisor	$(cd "$RUN" && for i in $(seq 10); do t "$PLYBOX" run --quiet --image "$IMAGE" --isolation gvisor --session "$RUN/glat-$i" --work "$LATW" -- /bin/true; done | med)"
} > "$OUT/latency.tsv"
echo "$IMAGE" > "$OUT/image.txt"

python3 -I "$LAB/image/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
