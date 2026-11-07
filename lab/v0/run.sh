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

# --- the secret test: a throwaway value, a lab CA, two TLS upstreams that
# know the value (see lab/full/run.sh for the design) ---
REAL="sk-ant-lab-$(openssl rand -hex 12)"
SECRET_HOST="secret-test.lab"; OTHER_HOST="other.lab"
ECHO_A=47881; ECHO_B=47882
python3 "$LAB/net/proxy.py" mkcert --ca-dir "$RUN/ca" --host "$SECRET_HOST" --host "$OTHER_HOST" >/dev/null
python3 "$LAB/net/echo.py" --port $ECHO_A --cert "$RUN/ca/$SECRET_HOST.pem" --key "$RUN/ca/$SECRET_HOST.key" --expect "$REAL" --name "$SECRET_HOST" & PIDS+=($!)
python3 "$LAB/net/echo.py" --port $ECHO_B --cert "$RUN/ca/$OTHER_HOST.pem" --key "$RUN/ca/$OTHER_HOST.key" --expect "$REAL" --name "$OTHER_HOST" & PIDS+=($!)
sleep 0.3

NODE_DIR="$HOME/.local/share/mise/installs/node"
echo "running plybox ($("$PLYBOX" version))" >&2
prepare plybox
SESSION="$RUN/session"
"$PLYBOX" run --quiet --session "$SESSION" --work "$WORK" \
  --mem 512M --pids 512 \
  --allow api.anthropic.com --allow '*.anthropic.com' --allow registry.npmjs.org \
  --allow "$SECRET_HOST" --allow "$OTHER_HOST" \
  --secret "ANTHROPIC_API_KEY=$REAL@$SECRET_HOST" --trust-ca "$RUN/ca/ca.pem" \
  --map "$SECRET_HOST=127.0.0.1:$ECHO_A" --map "$OTHER_HOST=127.0.0.1:$ECHO_B" \
  --env "SECRET_TEST_HOST=$SECRET_HOST" --env "SECRET_OTHER_HOST=$OTHER_HOST" \
  --ro-bind "$NODE_DIR:/opt/node" --env PATH=/opt/node/latest/bin:/usr/local/bin:/usr/bin:/bin \
  --env PROBE_HOST_LO --env PROBE_HOST_LAN --env PROBE_HOST_HOME --env PROBE_HOST_UID \
  --env PROBE_SSH_AUTH_SOCK --env PROBE_OUTSIDE \
  -- sh /work/inside.sh /work/probe >"$OUT/plybox.tsv" 2>"$OUT/plybox.err" \
  || echo "  plybox exited nonzero — see $OUT/plybox.err" >&2
hostcheck plybox
cp "$SESSION/record.jsonl" "$OUT/record.jsonl" 2>/dev/null || true
# What the box changed, as the operator would review it before `apply`.
"$PLYBOX" diff "$SESSION" > "$OUT/diff.txt" 2>&1 || true

# Host-side secret checks: the real value must appear nowhere the box could
# write, and the box's copy of the variable must be the placeholder.
if grep -qF -- "$REAL" "$OUT/plybox.tsv" "$OUT/plybox.err" 2>/dev/null; then
  printf 's.leak\tALLOWED\tthe real secret appeared in the box'"'"'s output\n'
else
  printf 's.leak\tBLOCKED\tthe real secret never appeared in the box'"'"'s output or stderr\n'
fi >> "$OUT/plybox.host.tsv"
held="$(awk -F'\t' '$1=="secretenv"{print $2}' "$OUT/plybox.tsv")"
if [ "$held" = "$REAL" ]; then printf 's.env\tALLOWED\tANTHROPIC_API_KEY inside is the real value\n'
else printf 's.env\tBLOCKED\tANTHROPIC_API_KEY inside is a placeholder (%s)\n' "${held:0:28}…"; fi >> "$OUT/plybox.host.tsv"

# --- the gVisor tier, same probes, when runsc is available ---
RUNSC="$LAB/tools/runsc"
if [ -x "$RUNSC" ]; then
  echo "running plybox --isolation gvisor" >&2
  prepare plybox.gvisor
  GSESSION="$RUN/session-gvisor"
  "$PLYBOX" run --quiet --isolation gvisor --runsc "$RUNSC" --session "$GSESSION" --work "$WORK" \
    --mem 512M --pids 512 \
    --allow api.anthropic.com --allow '*.anthropic.com' --allow registry.npmjs.org \
    --allow "$SECRET_HOST" --allow "$OTHER_HOST" \
    --secret "ANTHROPIC_API_KEY=$REAL@$SECRET_HOST" --trust-ca "$RUN/ca/ca.pem" \
    --map "$SECRET_HOST=127.0.0.1:$ECHO_A" --map "$OTHER_HOST=127.0.0.1:$ECHO_B" \
    --env "SECRET_TEST_HOST=$SECRET_HOST" --env "SECRET_OTHER_HOST=$OTHER_HOST" --env PROBE_LAST=1 \
    --ro-bind "$NODE_DIR:/opt/node" --env PATH=/opt/node/latest/bin:/usr/local/bin:/usr/bin:/bin \
    --env PROBE_HOST_LO --env PROBE_HOST_LAN --env PROBE_HOST_HOME --env PROBE_HOST_UID \
    --env PROBE_SSH_AUTH_SOCK --env PROBE_OUTSIDE \
    -- sh /work/inside.sh /work/probe >"$OUT/plybox.gvisor.tsv" 2>"$OUT/plybox.gvisor.err" \
    || echo "  plybox.gvisor exited nonzero — see $OUT/plybox.gvisor.err" >&2
  hostcheck plybox.gvisor
  if grep -qF -- "$REAL" "$OUT/plybox.gvisor.tsv" "$OUT/plybox.gvisor.err" 2>/dev/null; then
    printf 's.leak\tALLOWED\tthe real secret appeared in the box'"'"'s output\n'
  else
    printf 's.leak\tBLOCKED\tthe real secret never appeared in the box'"'"'s output or stderr\n'
  fi >> "$OUT/plybox.gvisor.host.tsv"
  gheld="$(awk -F'\t' '$1=="secretenv"{print $2}' "$OUT/plybox.gvisor.tsv")"
  if [ "$gheld" = "$REAL" ]; then printf 's.env\tALLOWED\tANTHROPIC_API_KEY inside is the real value\n'
  else printf 's.env\tBLOCKED\tANTHROPIC_API_KEY inside is a placeholder (%s)\n' "${gheld:0:28}…"; fi >> "$OUT/plybox.gvisor.host.tsv"
fi

prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

med() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
t() { local s; s=$(date +%s%N); "$@" >/dev/null 2>&1 || true; echo $(( ($(date +%s%N) - s) / 1000000 )); }
{
  echo "tier	median_ms"
  echo "host	$(for i in $(seq 10); do t /bin/true; done | med)"
  echo "plybox run	$(cd "$RUN" && for i in $(seq 10); do t "$PLYBOX" run --quiet --session "$RUN/lat-$i" --work "$RUN" -- /bin/true; done | med)"
  if [ -x "$RUNSC" ]; then
    echo "plybox run --isolation gvisor	$(cd "$RUN" && for i in $(seq 10); do t "$PLYBOX" run --quiet --isolation gvisor --runsc "$RUNSC" --session "$RUN/glat-$i" --work "$RUN" -- /bin/true; done | med)"
  fi
} > "$OUT/latency.tsv"

python3 "$LAB/v0/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
