#!/usr/bin/env bash
# plybox lab, step 4 driver: the whole box.
#
#   full/run.sh
#
# Three columns, all 41 probes:
#   host       — no sandbox (the control)
#   box.boxer  — step 3: namespaces + loopback-only + proxy + boxer
#   box.full   — step 4: box.boxer + workspace overlay + secrets kept outside
#                + cgroup limits (systemd-run --user, no root)
#
# Two things are measured from the HOST after a box exits, because that is
# where the threat is: did a planted file land in the real workspace, and
# did the real secret ever appear inside the box?
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/full-$STAMP"
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

# --- host services the box must not reach ---
LO_PORT=47831; LAN_PORT=47832
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
socat -u TCP-LISTEN:$LO_PORT,bind=127.0.0.1,fork,reuseaddr OPEN:/dev/null & PIDS+=($!)
[ -n "$LAN_IP" ] && { socat -u TCP-LISTEN:$LAN_PORT,bind="$LAN_IP",fork,reuseaddr OPEN:/dev/null & PIDS+=($!); }
export PROBE_HOST_LO="127.0.0.1:$LO_PORT"
export PROBE_HOST_LAN="${LAN_IP:+$LAN_IP:$LAN_PORT}"
export PROBE_HOST_HOME="$HOME"
export PROBE_HOST_UID="$(id -u)"
export PROBE_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

# --- the secret, the lab CA, and two TLS upstreams that know the secret ---
# REAL is a throwaway value in the shape of a key; it is never a real key.
REAL="sk-ant-lab-$(openssl rand -hex 12)"
SECRET_HOST="secret-test.lab"; OTHER_HOST="other.lab"
ECHO_A=47841; ECHO_B=47842
python3 "$LAB/net/proxy.py" mkcert --ca-dir "$RUN/ca" --host "$SECRET_HOST" --host "$OTHER_HOST" >/dev/null
cat /etc/ssl/certs/ca-certificates.crt "$RUN/ca/ca.pem" > "$RUN/ca/bundle.pem"
python3 "$LAB/net/echo.py" --port $ECHO_A --cert "$RUN/ca/$SECRET_HOST.pem" --key "$RUN/ca/$SECRET_HOST.key" --expect "$REAL" --name "$SECRET_HOST" & PIDS+=($!)
python3 "$LAB/net/echo.py" --port $ECHO_B --cert "$RUN/ca/$OTHER_HOST.pem" --key "$RUN/ca/$OTHER_HOST.key" --expect "$REAL" --name "$OTHER_HOST" & PIDS+=($!)

# --- the proxy ---
ALLOW="api.anthropic.com,registry.npmjs.org,*.anthropic.com,$SECRET_HOST,$OTHER_HOST"
mkdir -p "$RUN/sock"
python3 "$LAB/net/proxy.py" --socket "$RUN/sock/sock" --allow "$ALLOW" --log "$OUT/proxy.jsonl" \
  --secret "ANTHROPIC_API_KEY=$REAL@$SECRET_HOST" --ca-dir "$RUN/ca" \
  --map "$SECRET_HOST=127.0.0.1:$ECHO_A" --map "$OTHER_HOST=127.0.0.1:$ECHO_B" \
  --placeholders "$RUN/secrets.env" & PIDS+=($!)
for i in $(seq 1 50); do [ -S "$RUN/sock/sock" ] && [ -s "$RUN/secrets.env" ] && break; sleep 0.1; done
[ -S "$RUN/sock/sock" ] || { echo "proxy socket never appeared" >&2; exit 1; }

prepare() {
  WORK="$RUN/work-$1"; export PROBE_OUTSIDE="$RUN/outside-$1"
  mkdir -p "$WORK" "$PROBE_OUTSIDE"; git -C "$WORK" init -q
}

run_box() { # column, extra env...
  local col="$1"; shift
  prepare "$col"
  cp "$PROBE" "$WORK/probe"; cp "$LAB/net/inside.sh" "$WORK/inside.sh"
  env "$@" bash "$LAB/net/box.sh" "$RUN/sock" "$WORK" -- sh /work/inside.sh /work/probe \
    >"$OUT/$col.tsv" 2>"$OUT/$col.err" || echo "  $col exited nonzero — see $OUT/$col.err" >&2
  # Host-side truth for the two injection probes: did the file land in the
  # REAL workspace?
  {
    for pair in "f.inject.githook:.git/hooks/pre-commit" "f.inject.agentcfg:.claude/settings.json"; do
      id="${pair%%:*}"; rel="${pair#*:}"
      if [ -e "$WORK/$rel" ]; then printf '%s\tALLOWED\t%s exists in the real workspace\n' "$id" "$rel"
      else printf '%s\tBLOCKED\t%s never reached the real workspace\n' "$id" "$rel"; fi
    done
  } > "$OUT/$col.host.tsv"
}

echo "running box.boxer (step 3)" >&2
run_box box.boxer BOXER_BIN="$BOXER"

echo "running box.full (overlay + secrets + limits)" >&2
UPPER="$RUN/upper-box.full"
# The cgroup limits wrap the whole box: bwrap, forwarder and workload alike.
# systemd-run --scope runs the command in this shell's context, so the
# functions and variables are passed along and output lands in $OUT.
# OOMPolicy=continue: when the kernel OOM-kills one process for exceeding
# MemoryMax, the box carries on (systemd's default would stop the whole
# scope — first run proved it, and took the workloads down with it).
timeout 150 systemd-run --user --scope -q \
  -p TasksMax=512 -p MemoryMax=512M -p MemorySwapMax=0 -p OOMPolicy=continue -- \
  bash -c "$(declare -f prepare run_box)
    LAB='$LAB' RUN='$RUN' OUT='$OUT' PROBE='$PROBE'
    run_box box.full BOXER_BIN='$BOXER' BOX_OVERLAY=1 BOX_UPPER='$UPPER' BOX_CA_DIR='$RUN/ca' \
      BOX_SECRETS_FILE='$RUN/secrets.env' SECRET_TEST_HOST='$SECRET_HOST' SECRET_OTHER_HOST='$OTHER_HOST'"

# What the operator would review before `apply`: everything the box wrote.
( cd "$UPPER/upper" 2>/dev/null && find . -type f -o -type c | sort ) > "$OUT/box.full.upper.txt" || true

# Did the real secret ever appear inside? Search everything that came out
# of the box: its output, its stderr, its written files.
if grep -rqF -- "$REAL" "$OUT/box.full.tsv" "$OUT/box.full.err" "$UPPER/upper" 2>/dev/null; then
  printf 's.leak\tALLOWED\tthe real secret appeared inside the box\n'
else
  printf 's.leak\tBLOCKED\tthe real secret never appeared in the box'"'"'s output, stderr or written files\n'
fi >> "$OUT/box.full.host.tsv"
held="$(awk -F'\t' '$1=="secretenv"{print $2}' "$OUT/box.full.tsv")"
if [ "$held" = "$REAL" ]; then printf 's.env\tALLOWED\tANTHROPIC_API_KEY inside is the real value\n'
else printf 's.env\tBLOCKED\tANTHROPIC_API_KEY inside is a placeholder (%s)\n' "${held:0:28}…"; fi >> "$OUT/box.full.host.tsv"

# The control.
prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

python3 "$LAB/full/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
