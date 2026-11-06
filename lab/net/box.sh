#!/usr/bin/env bash
# plybox lab: start a box whose only way out is the proxy socket.
#
#   box.sh <proxy-socket-dir> <workdir> -- <command...>
#
# No root. bubblewrap gives the box its own user, pid, mount, ipc, uts and
# NETWORK namespaces; the network one has loopback and nothing else. The
# directory holding the proxy's unix socket is bound in at /proxy, and a
# tiny forwarder turns it into 127.0.0.1:3128 so ordinary HTTPS_PROXY
# settings reach it. Tools that honour proxy variables work; nothing else
# can leave.
#
# Options, all by environment variable (empty = off):
#   BOXER_BIN=/path/to/boxer   step 3: wrap the workload in seccomp + Landlock
#   BOXER_ARGS="..."            extra boxer flags
#   BOX_OVERLAY=1 BOX_UPPER=DIR step 4: /work is an overlay over <workdir>;
#                               the box's changes land in DIR/upper only
#   BOX_CA_DIR=DIR              step 4: trust DIR/ca.pem (+ DIR/bundle.pem) so
#                               the proxy can terminate TLS for secret hosts
#   BOX_SECRETS_FILE=FILE       step 4: NAME=PLACEHOLDER lines → environment
set -euo pipefail
SOCKDIR="$1"; WORK="$2"; shift 2; [ "${1:-}" = "--" ] && shift

NODE_DIR="$HOME/.local/share/mise/installs/node"
CLAUDE_DIR="$HOME/.local/share/mise/installs/claude"
BINDS=()
[ -d "$NODE_DIR" ] && BINDS+=(--ro-bind "$NODE_DIR" /opt/node)
[ -d "$CLAUDE_DIR" ] && BINDS+=(--ro-bind "$CLAUDE_DIR" /opt/claude)

# The workspace: a plain bind, or (step 4) an overlay whose upper layer is
# the only place the box's writes go. The real directory never changes.
if [ "${BOX_OVERLAY:-}" = 1 ]; then
  : "${BOX_UPPER:?BOX_OVERLAY=1 needs BOX_UPPER=dir}"
  mkdir -p "$BOX_UPPER/upper" "$BOX_UPPER/work"
  WORKMOUNT=(--overlay-src "$WORK" --overlay "$BOX_UPPER/upper" "$BOX_UPPER/work" /work)
else
  WORKMOUNT=(--bind "$WORK" /work)
fi

# Variables the probe and the test script read; forwarded verbatim.
PASS=()
for var in PROBE_HOST_LO PROBE_HOST_LAN PROBE_HOST_HOME PROBE_HOST_UID PROBE_OUTSIDE \
           PROBE_SSH_AUTH_SOCK PROBE_FORK_CAP PROBE_MEM_MB SECRET_TEST_HOST SECRET_OTHER_HOST; do
  [ -n "${!var:-}" ] && PASS+=(--setenv "$var" "${!var}")
done

# Step 3: wrap the workload (not the socat forwarder) in boxer.
WRAP=""
if [ -n "${BOXER_BIN:-}" ]; then
  BINDS+=(--ro-bind "$BOXER_BIN" /boxer)
  WRAP="/boxer ${BOXER_ARGS:-} --"
fi
PASS+=(--setenv BOX_WRAP "$WRAP")

# Step 4: the lab CA, so TLS terminated by the proxy is trusted inside.
if [ -n "${BOX_CA_DIR:-}" ]; then
  BINDS+=(--ro-bind "$BOX_CA_DIR" /etc/plybox)
  for var in SSL_CERT_FILE CURL_CA_BUNDLE REQUESTS_CA_BUNDLE GIT_SSL_CAINFO; do
    PASS+=(--setenv "$var" /etc/plybox/bundle.pem)
  done
  PASS+=(--setenv NODE_EXTRA_CA_CERTS /etc/plybox/ca.pem)
fi

# Step 4: secrets enter the box as placeholders only.
if [ -n "${BOX_SECRETS_FILE:-}" ]; then
  while IFS='=' read -r name value; do
    [ -n "$name" ] && PASS+=(--setenv "$name" "$value")
  done < "$BOX_SECRETS_FILE"
fi

exec bwrap \
  --unshare-all --unshare-user --die-with-parent --new-session \
  --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib /lib64 \
  --symlink usr/bin /bin --symlink usr/bin /sbin \
  --ro-bind /etc/ssl /etc/ssl --ro-bind /etc/ca-certificates /etc/ca-certificates \
  --ro-bind /etc/passwd /etc/passwd --ro-bind /etc/group /etc/group \
  --ro-bind /etc/hosts /etc/hosts \
  --proc /proc --dev /dev --tmpfs /tmp --tmpfs /home --dir /home/lab \
  "${WORKMOUNT[@]}" --bind "$SOCKDIR" /proxy "${BINDS[@]}" \
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
