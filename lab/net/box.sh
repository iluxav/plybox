#!/usr/bin/env bash
# plybox lab, step 2: start a box whose only way out is the proxy socket.
#
#   box.sh <proxy-socket-dir> <workdir> -- <command...>
#
# No root. bubblewrap gives the box its own user, pid, mount, ipc, uts and
# NETWORK namespaces; the network one has loopback and nothing else. The
# directory holding the proxy's unix socket is bound in at /proxy, and a
# tiny forwarder turns it into 127.0.0.1:3128 so ordinary HTTPS_PROXY
# settings reach it. Tools that honour proxy variables work; nothing else
# can leave.
set -euo pipefail
SOCKDIR="$1"; WORK="$2"; shift 2; [ "${1:-}" = "--" ] && shift

NODE_DIR="$HOME/.local/share/mise/installs/node"
CLAUDE_DIR="$HOME/.local/share/mise/installs/claude"
BINDS=()
[ -d "$NODE_DIR" ] && BINDS+=(--ro-bind "$NODE_DIR" /opt/node)
[ -d "$CLAUDE_DIR" ] && BINDS+=(--ro-bind "$CLAUDE_DIR" /opt/claude)

# Addresses of host services to probe for reachability (set by the driver),
# forwarded in so the box can try — and fail — to reach the host.
PASS=()
[ -n "${PROBE_HOST_LO:-}" ] && PASS+=(--setenv PROBE_HOST_LO "$PROBE_HOST_LO")
[ -n "${PROBE_HOST_LAN:-}" ] && PASS+=(--setenv PROBE_HOST_LAN "$PROBE_HOST_LAN")

# Step 3: if BOXER_BIN points at the boxer binary, bind it in and wrap the
# workload with it, so seccomp + Landlock apply to the command (and the
# probe) but not to the socat forwarder that must keep running.
WRAP=""
if [ -n "${BOXER_BIN:-}" ]; then
  BINDS+=(--ro-bind "$BOXER_BIN" /boxer)
  WRAP="/boxer ${BOXER_ARGS:-} --"
fi
PASS+=(--setenv BOX_WRAP "$WRAP")

exec bwrap \
  --unshare-all --unshare-user --die-with-parent --new-session \
  --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib /lib64 \
  --symlink usr/bin /bin --symlink usr/bin /sbin \
  --ro-bind /etc/ssl /etc/ssl --ro-bind /etc/ca-certificates /etc/ca-certificates \
  --ro-bind /etc/passwd /etc/passwd --ro-bind /etc/group /etc/group \
  --ro-bind /etc/hosts /etc/hosts \
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /home --dir /home/lab \
  --bind "$WORK" /work --bind "$SOCKDIR" /proxy "${BINDS[@]}" \
  --chdir /work --cap-drop ALL --disable-userns \
  --clearenv "${PASS[@]}" \
  --setenv HOME /home/lab --setenv USER lab --setenv TERM dumb \
  --setenv PATH "/opt/node/latest/bin:/opt/claude/latest:/usr/local/bin:/usr/bin:/bin" \
  --setenv HTTPS_PROXY http://127.0.0.1:3128 --setenv HTTP_PROXY http://127.0.0.1:3128 \
  --setenv https_proxy http://127.0.0.1:3128 --setenv http_proxy http://127.0.0.1:3128 \
  --setenv NO_PROXY "localhost,127.0.0.1" --setenv no_proxy "localhost,127.0.0.1" \
  --setenv NODE_USE_ENV_PROXY 1 \
  -- sh -c '
    socat TCP-LISTEN:3128,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/proxy/sock &
    for i in 1 2 3 4 5 6 7 8 9 10; do
      socat -u OPEN:/dev/null TCP:127.0.0.1:3128 2>/dev/null && break; sleep 0.1
    done
    exec $BOX_WRAP "$@"' -- "$@"
