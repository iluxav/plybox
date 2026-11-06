#!/usr/bin/env bash
# plybox lab, step 5 (gVisor half): the probe and workloads under gVisor.
#
#   gv/run.sh
#
# gVisor (runsc) puts a user-space kernel between the program and the real
# one: the program's syscalls land in the "sentry", which reimplements Linux
# and talks to the host kernel through a small, filtered surface. No root:
# `--rootless`. No network device: `--network=none` leaves gVisor's own
# loopback. The host's filesystem is visible through an in-memory overlay,
# so writes never reach the host.
#
# Columns:
#   gv      — gVisor alone, probes only (nothing to reach without a proxy)
#   gv.box  — gVisor + our proxy (over a host unix socket, --host-uds=all)
#             + boxer (seccomp applies inside gVisor; Landlock does not exist
#             there and boxer says so) + cgroup limits via systemd-run
# The report adds `host` and the latest step-4 `box.full` for comparison,
# and start-latency medians for every tier incl. the Firecracker run.
set -euo pipefail
LAB="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$LAB/results/gv-$STAMP"
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
RUNSC="$LAB/tools/runsc"
[ -x "$RUNSC" ] || { echo "no $RUNSC — run tools/fetch.sh" >&2; exit 1; }

LO_PORT=47851; LAN_PORT=47852
LAN_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
socat -u TCP-LISTEN:$LO_PORT,bind=127.0.0.1,fork,reuseaddr OPEN:/dev/null & PIDS+=($!)
[ -n "$LAN_IP" ] && { socat -u TCP-LISTEN:$LAN_PORT,bind="$LAN_IP",fork,reuseaddr OPEN:/dev/null & PIDS+=($!); }
export PROBE_HOST_LO="127.0.0.1:$LO_PORT"
export PROBE_HOST_LAN="${LAN_IP:+$LAN_IP:$LAN_PORT}"
export PROBE_HOST_HOME="$HOME"
export PROBE_HOST_UID="$(id -u)"
export PROBE_SSH_AUTH_SOCK="${SSH_AUTH_SOCK:-}"

ALLOW="api.anthropic.com,registry.npmjs.org,*.anthropic.com"
mkdir -p "$RUN/sock"
python3 "$LAB/net/proxy.py" --socket "$RUN/sock/sock" --allow "$ALLOW" --log "$OUT/proxy.jsonl" & PIDS+=($!)
for i in $(seq 1 50); do [ -S "$RUN/sock/sock" ] && break; sleep 0.1; done

prepare() {
  WORK="$RUN/work-$1"; export PROBE_OUTSIDE="$RUN/outside-$1"
  mkdir -p "$WORK" "$PROBE_OUTSIDE"; git -C "$WORK" init -q
  cp "$PROBE" "$WORK/probe"; cp "$LAB/net/inside.sh" "$WORK/inside.sh"
}

# Did a planted file reach the REAL workspace? (gVisor's overlay says no.)
hostcheck() {
  for pair in "f.inject.githook:.git/hooks/pre-commit" "f.inject.agentcfg:.claude/settings.json"; do
    id="${pair%%:*}"; rel="${pair#*:}"
    if [ -e "$WORK/$rel" ]; then printf '%s\tALLOWED\t%s exists in the real workspace\n' "$id" "$rel"
    else printf '%s\tBLOCKED\t%s never reached the real workspace\n' "$id" "$rel"; fi
  done > "$OUT/$1.host.tsv"
}

GV=(--rootless --network=none --host-uds=all)
# `runsc do` does not forward our environment, so hand it over explicitly.
ENVV=(PROBE_HOST_LO="$PROBE_HOST_LO" PROBE_HOST_LAN="$PROBE_HOST_LAN" PROBE_HOST_HOME="$PROBE_HOST_HOME"
      PROBE_HOST_UID="$PROBE_HOST_UID" PROBE_SSH_AUTH_SOCK="$PROBE_SSH_AUTH_SOCK")

echo "running gv (gVisor alone, probes only)" >&2
prepare gv
"$RUNSC" "${GV[@]}" do -cwd "$WORK" /usr/bin/env "${ENVV[@]}" PROBE_OUTSIDE="$PROBE_OUTSIDE" \
  "$WORK/probe" 2>"$OUT/gv.err" | sed 's/^/probe\t/' > "$OUT/gv.tsv" || echo "  gv exited nonzero — see $OUT/gv.err" >&2
hostcheck gv

echo "running gv.box (gVisor + proxy + boxer + limits)" >&2
prepare gv.box
PROXY_ENV=(HTTPS_PROXY=http://127.0.0.1:3128 HTTP_PROXY=http://127.0.0.1:3128
           https_proxy=http://127.0.0.1:3128 http_proxy=http://127.0.0.1:3128
           NO_PROXY=localhost,127.0.0.1 no_proxy=localhost,127.0.0.1 NODE_USE_ENV_PROXY=1
           HOME=/tmp/lab TERM=dumb PROBE_LAST=1
           PATH="$HOME/.local/share/mise/installs/node/latest/bin:/usr/local/bin:/usr/bin:/bin")
timeout 180 systemd-run --user --scope -q \
  -p TasksMax=512 -p MemoryMax=512M -p MemorySwapMax=0 -p OOMPolicy=continue -- \
  "$RUNSC" "${GV[@]}" do -cwd "$WORK" /usr/bin/env "${ENVV[@]}" "${PROXY_ENV[@]}" PROBE_OUTSIDE="$PROBE_OUTSIDE" \
    /bin/sh -c 'mkdir -p /tmp/lab
      socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:'"$RUN/sock/sock"' &
      for i in 1 2 3 4 5 6 7 8 9 10; do socat -u OPEN:/dev/null TCP:127.0.0.1:3128 2>/dev/null && break; sleep 0.1; done
      exec '"$BOXER"' -- /bin/sh '"$WORK/inside.sh"' '"$WORK/probe"'' \
  >"$OUT/gv.box.tsv" 2>"$OUT/gv.box.err" || echo "  gv.box exited nonzero — see $OUT/gv.box.err" >&2
hostcheck gv.box

# The control.
prepare host
( cd "$WORK" && "$PROBE" ) >"$OUT/host.tsv" 2>/dev/null || true
"$PROBE" --list >"$OUT/probes.tsv"

# Start latency, median of 10 (ms from spawn to /bin/true exiting).
med() { sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}'; }
t() { local s; s=$(date +%s%N); "$@" >/dev/null 2>&1; echo $(( ($(date +%s%N) - s) / 1000000 )); }
BW=(bwrap --unshare-all --unshare-user --ro-bind /usr /usr --symlink usr/lib /lib64 --symlink usr/lib /lib
    --symlink usr/bin /bin --proc /proc --dev /dev --tmpfs /tmp --cap-drop ALL --disable-userns)
{
  echo "tier	median_ms"
  echo "host	$(for i in $(seq 10); do t /bin/true; done | med)"
  echo "namespaces (bwrap)	$(for i in $(seq 10); do t "${BW[@]}" /bin/true; done | med)"
  echo "namespaces + boxer	$(for i in $(seq 10); do t "${BW[@]}" --ro-bind "$BOXER" /boxer /boxer --no-landlock -- /bin/true; done | med)"
  echo "gVisor (runsc do)	$(for i in $(seq 10); do t "$RUNSC" --rootless --network=none do /bin/true; done | med)"
  VM=$(ls -d "$LAB"/results/vm-* 2>/dev/null | tail -1)
  if [ -n "$VM" ]; then
    up=$(awk -F'|' 'NR>4 && $2+0>0 {print $3+0}' "$VM/timing.md" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
    ex=$(awk -F'|' 'NR>4 && $2+0>0 {print $5+0}' "$VM/timing.md" | sort -n | awk '{a[NR]=$1} END{print a[int((NR+1)/2)]}')
    echo "Firecracker microVM: kernel→init	$up"
    echo "Firecracker microVM: boot+probe+exit	$ex"
  fi
} > "$OUT/latency.tsv"

python3 "$LAB/gv/report.py" "$OUT" | tee "$OUT/report.md"
echo "results: $OUT" >&2
