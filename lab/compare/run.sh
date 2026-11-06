#!/usr/bin/env bash
# plybox lab, comparison: the same 41 probes and the same workloads against
# other agent sandboxes, on this machine, today.
#
#   compare/run.sh
#
# Columns produced here: host (control), srt (Anthropic sandbox-runtime),
# greywall (Greywall + greyproxy). The report adds our box.full and gv.box
# from their latest results. Every tool gets ITS OWN DEFAULTS plus the same
# allow list our box uses — what a user gets after reading the quickstart.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/compare-$STAMP"
RUN="$(mktemp -d "$LAB/.run.XXXXXX")"
mkdir -p "$OUT"
TOOLS="$LAB/tools"
SRT="$TOOLS/srt/node_modules/.bin/srt"
GW="$TOOLS/greywall"; GP="$TOOLS/greyproxy"
for t in "$SRT" "$GW" "$GP"; do [ -x "$t" ] || { echo "missing $t — run tools/fetch.sh" >&2; exit 1; }; done
GP_DATA="$HOME/.local/share/greyproxy"
HAD_GP_DATA=$([ -e "$GP_DATA" ] && echo 1 || echo 0)
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  # greyproxy writes its CA and session key to a fixed directory; leave the
  # user's home as we found it.
  [ "$HAD_GP_DATA" = 0 ] && rm -rf "$GP_DATA"
  rm -rf "$RUN"
}
trap cleanup EXIT

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
( cd "$LAB/probe" && RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --quiet --target "$TARGET" )
( cd "$LAB/boxer" && cargo build --release --quiet )
PROBE="$LAB/probe/target/$TARGET/release/probe"
BOXER="$LAB/boxer/target/release/boxer"

LO_PORT=47861; LAN_PORT=47862
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
# The probe's inputs, placed on the command line so a tool that sanitizes
# the environment cannot strip them (both tools do some sanitizing).
envline() {
  printf 'export PROBE_HOST_LO=%q PROBE_HOST_LAN=%q PROBE_HOST_HOME=%q PROBE_HOST_UID=%q PROBE_SSH_AUTH_SOCK=%q PROBE_OUTSIDE=%q;' \
    "$PROBE_HOST_LO" "$PROBE_HOST_LAN" "$PROBE_HOST_HOME" "$PROBE_HOST_UID" "$PROBE_SSH_AUTH_SOCK" "$PROBE_OUTSIDE"
}

# ---------------------------------------------------------------- srt ---
cat > "$RUN/srt.json" <<'EOF'
{
  "network": {
    "allowedDomains": ["api.anthropic.com", "*.anthropic.com", "registry.npmjs.org"],
    "deniedDomains": []
  },
  "filesystem": { "denyRead": [], "allowWrite": ["."], "denyWrite": [] }
}
EOF
echo "running srt (Anthropic sandbox-runtime $("$SRT" --version 2>/dev/null))" >&2
prepare srt
( cd "$WORK" && timeout 240 "$SRT" -s "$RUN/srt.json" sh -c "$(envline) exec sh ./inside.sh ./probe" ) \
  >"$OUT/srt.tsv" 2>"$OUT/srt.err" || echo "  srt exited nonzero — see $OUT/srt.err" >&2
hostcheck srt

# ----------------------------------------------------------- greywall ---
echo "starting greyproxy ($("$GP" --version 2>/dev/null | head -1))" >&2
# Defaults, deliberately: a `-C` file REPLACES the default service list, so a
# config with only settings in it starts a proxy that listens on nothing.
# greyproxy also exits if its fixed data directory (MITM CA) is missing.
# Notifications are switched off over the API right after start.
mkdir -p "$GP_DATA"
"$GP" serve >"$OUT/greyproxy.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 100); do curl -fsS -o /dev/null http://127.0.0.1:43080/api/settings 2>/dev/null && break; sleep 0.1; done
curl -fsS -o /dev/null http://127.0.0.1:43080/api/settings 2>/dev/null \
  || echo "  greyproxy dashboard never answered — see $OUT/greyproxy.log" >&2
curl -fsS -o /dev/null -X PUT http://127.0.0.1:43080/api/settings -H 'Content-Type: application/json' \
  -d '{"notificationsEnabled": false}' 2>/dev/null || true
rule() { # destination, port, action — a global rule, deny-by-default first
  curl -fsS -o /dev/null -X POST http://127.0.0.1:43080/api/rules -H 'Content-Type: application/json' \
    -d "{\"container_pattern\":\"*\",\"destination_pattern\":\"$1\",\"port_pattern\":\"$2\",\"action\":\"$3\",\"notes\":\"plybox lab\"}" \
    2>/dev/null || echo "  rule $1:$2 $3 not accepted" >&2
}
rule '*' '*' deny
rule api.anthropic.com 443 allow
rule '*.anthropic.com' 443 allow
rule registry.npmjs.org 443 allow
cat > "$RUN/greywall.json" <<'EOF'
{
  "network": {
    "proxyUrl": "socks5://localhost:43052",
    "dnsAddr": "localhost:43053",
    "httpProxyUrl": "http://localhost:43051"
  },
  "filesystem": { "allowWrite": ["."] }
}
EOF
echo "running greywall ($("$GW" check 2>/dev/null | sed -n 's/^Version: *//p' | head -1))" >&2
prepare greywall
( cd "$WORK" && PATH="$TOOLS:$PATH" timeout 240 "$GW" --settings "$RUN/greywall.json" -- sh -c "$(envline) exec sh ./inside.sh ./probe" ) \
  >"$OUT/greywall.tsv" 2>"$OUT/greywall.err" || echo "  greywall exited nonzero — see $OUT/greywall.err" >&2
hostcheck greywall
curl -fsS "http://127.0.0.1:43080/api/logs?limit=300" >"$OUT/greyproxy.logs.json" 2>/dev/null || true

# ------------------------------------------------------------ control ---
prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

# ----------------------------------------------------------- latency ---
med() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
t() { local s; s=$(date +%s%N); "$@" >/dev/null 2>&1 || true; echo $(( ($(date +%s%N) - s) / 1000000 )); }
BW=(bwrap --unshare-all --unshare-user --ro-bind /usr /usr --symlink usr/lib /lib64 --symlink usr/lib /lib
    --symlink usr/bin /bin --proc /proc --dev /dev --tmpfs /tmp --cap-drop ALL --disable-userns)
{
  echo "tier	median_ms"
  echo "host	$(for i in $(seq 10); do t /bin/true; done | med)"
  echo "ours: namespaces + boxer	$(for i in $(seq 10); do t "${BW[@]}" --ro-bind "$BOXER" /boxer /boxer --no-landlock -- /bin/true; done | med)"
  echo "srt	$(for i in $(seq 10); do t "$SRT" -s "$RUN/srt.json" /bin/true; done | med)"
  echo "greywall	$(cd "$RUN" && for i in $(seq 10); do t env PATH="$TOOLS:$PATH" "$GW" --settings "$RUN/greywall.json" -- /bin/true; done | med)"
} > "$OUT/latency.tsv"

python3 "$LAB/compare/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
