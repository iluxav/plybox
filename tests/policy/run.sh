#!/usr/bin/env bash
# plybox lab: a hostile POLICY (not a hostile workload) must not weaken the box.
#
#   tests/policy/run.sh [path/to/plybox]
#
# The probe suite assumes plybox's own policy and attacks from inside. Here
# the attacker writes the policy or the flags — a shared repo's policy file,
# or a hosted service's user — and the checks measure what the box ends up
# with. One `check <TAB> name <TAB> pass|FAIL <TAB> detail` line per check;
# exits non-zero if any fails.
set -uo pipefail
PLYBOX="${1:-plybox}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUNSC="$ROOT/tests/tools/runsc"
T="$(mktemp -d /tmp/plybox-policy-lab.XXXXXX)"
export XDG_STATE_HOME="$T/state"
FAILS=0
check() { # name, condition-exit-code, detail
  if [ "$2" -eq 0 ]; then printf 'check\t%-52s\tpass\t%s\n' "$1" "$3"
  else printf 'check\t%-52s\tFAIL\t%s\n' "$1" "$3"; FAILS=$((FAILS+1)); fi
}
tiers=(ns); [ -x "$RUNSC" ] && tiers+=(gvisor)
tier_args() { [ "$1" = gvisor ] && echo "--isolation gvisor --runsc $RUNSC"; }

# A stand-in for plybox's in-box helper that skips everything it installs
# (seccomp, Landlock, the forwarder) and runs the command bare.
mkdir -p "$T/fake"
printf '#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n' > "$T/fake/plybox"
chmod +x "$T/fake/plybox"

# --- 1. ro_bind cannot replace /plybox ---------------------------------------
W="$T/ws"; mkdir -p "$W"
msg="$("$PLYBOX" run --quiet --work "$W" --ro-bind "$T/fake/plybox:/plybox" -- true 2>&1)"; code=$?
[ $code -ne 0 ] && echo "$msg" | grep -q "plybox's own"
check "ro_bind onto /plybox refused" $? "$(echo "$msg" | head -1 | cut -c1-80)"
msg="$("$PLYBOX" run --quiet --work "$W" --ro-bind "$T/fake:/run" -- true 2>&1)"; code=$?
[ $code -ne 0 ] && echo "$msg" | grep -q "plybox's own"
check "ro_bind over /run (covers /run/plybox) refused" $? "$(echo "$msg" | head -1 | cut -c1-80)"

# A symlink in the workspace steers a bind onto /plybox: the box must still
# end up with plybox's own helper on top (seccomp on), in every tier.
WS="$T/ws-link"; mkdir -p "$WS"; ln -s / "$WS/l"
for tier in "${tiers[@]}"; do
  # shellcheck disable=SC2046
  out="$("$PLYBOX" run --quiet $(tier_args "$tier") --work "$WS" --ro-bind "$T/fake/plybox:/work/l/plybox" -- grep Seccomp: /proc/self/status 2>&1)"
  echo "$out" | grep -q 'Seccomp:[[:space:]]*2'
  check "symlink-steered bind onto /plybox: seccomp stays ($tier)" $? "$(echo "$out" | grep Seccomp | tr "\t" " " | cut -c1-80)"
done

# --- 2. ro_bind destinations stay inside the box ------------------------------
# The gVisor tier creates each destination as a mount point in its bundle on
# the host; `..` must not let it create directories elsewhere on the host.
ESC="$T/escaped-$$"
for tier in "${tiers[@]}"; do
  # shellcheck disable=SC2046
  msg="$("$PLYBOX" run --quiet $(tier_args "$tier") --work "$W" --ro-bind "$T/fake:/../../../../../../../../..$ESC" -- true 2>&1)"; code=$?
  [ $code -ne 0 ] && [ ! -e "$ESC" ]
  check "ro_bind destination with .. refused, nothing made ($tier)" $? "$(echo "$msg" | head -1 | cut -c1-80)"
  rm -rf "$ESC"
done

# --- 3. operator rules: the owner's ceiling over policy and flags -------------
OPD="$T/op"; OKW="$OPD/work/ok"
mkdir -p "$OKW" "$OPD/outside" "$OPD/sessions"
echo "private-$$" > "$OPD/outside/key"; chmod 600 "$OPD/outside/key"
echo "opkey-$$" > "$OPD/opkey"; chmod 600 "$OPD/opkey"
ln -s "$OPD/outside" "$OKW/sneaky"            # inside the allowed root, pointing out
ln -s "$OPD/outside" "$OPD/sessions/link"
cat > "$OPD/operator.toml" <<EOF
host_rootfs = true
paths = ["$OPD/work"]
hosts = ["*.example.com", "api.example.org"]
sessions = "$OPD/sessions"
[secrets]
OPKEY = { only = "api.example.org", file = "$OPD/opkey" }
[max]
file_size = "64M"
bytes_in = "10M"
EOF
# The same rules plus cgroup limits, for the checks that need them.
{ cat "$OPD/operator.toml"; printf 'mem = "1G"\npids = 256\n'; } > "$OPD/limits.toml"
opr() { PLYBOX_OPERATOR="${OPF:-$OPD/operator.toml}" "$PLYBOX" run --quiet "$@"; }
refused() { # name, expected-message-fragment, run args...
  local name="$1" want="$2"; shift 2
  msg="$(opr "$@" -- true 2>&1)"; code=$?
  [ $code -ne 0 ] && echo "$msg" | grep -q "operator rules" && echo "$msg" | grep -qF -- "$want"
  check "$name" $? "$(echo "$msg" | head -1 | sed 's/^plybox: //' | cut -c1-90)"
}
start_of() { grep '"event":"start"' "$1/record.jsonl"; }

S="$OPD/sessions/ok"
opr --work "$OKW" --session "$S" --allow api.example.com --secret-file "OPKEY=$OPD/outside/key@evil.com" -- true >/dev/null 2>&1; code=$?
st="$(start_of "$S")"
[ $code -eq 0 ] && echo "$st" | grep -q '"file_size":67108864' && echo "$st" | grep -q '"bytes_in":10485760' && echo "$st" | grep -qF "\"operator\":\"$OPD/operator.toml\""
check "allowed run gets the max limits, records the rules" $? "exit $code"
echo "$st" | grep -qF '"secrets":["OPKEY@api.example.org"]' && echo "$st" | grep -qF "\"host\":\"$OPD/opkey\"" && ! echo "$st" | grep -qF "$OPD/outside/key"
check "operator's secret: its own file and host, not the policy's" $? "$(echo "$st" | grep -o '"secrets":\[[^]]*\]')"

refused "workspace outside the allowed paths"        "outside the allowed paths" --work "$OPD/outside"
refused "workspace via a symlink that leaves them"   "outside the allowed paths" --work "$OKW/sneaky"
refused "ro_bind source outside the allowed paths"   "outside the allowed paths" --work "$OKW" --ro-bind "$OPD/outside:/opt/x"
refused "ro_bind source via a symlink out"           "outside the allowed paths" --work "$OKW" --ro-bind "$OKW/sneaky:/opt/x"
refused "net.allow outside the operator's hosts"     "outside the operator's hosts" --work "$OKW" --allow evil.com
refused "wildcard does not cover its apex"           "outside the operator's hosts" --work "$OKW" --allow example.com
refused "secret file the operator did not declare"   "only the operator's secrets" --work "$OKW" --secret-file "K=$OPD/outside/key@api.example.org"
refused "secret from plybox's env, undeclared"       "only the operator's secrets" --work "$OKW" --secret "HOME@api.example.org"
refused "typed secret to a host outside the list"    "outside the operator's hosts" --work "$OKW" --secret "MINE=v@evil.com"
refused "a limit over the maximum"                   "over the maximum" --work "$OKW" --file-size 128M
OPF="$OPD/limits.toml" refused "memory over the maximum" "over the maximum" --work "$OKW" --mem 2G
refused "map refused"                                "net.map is not allowed" --work "$OKW" --map api.example.com=127.0.0.1:443
refused "trust_ca refused"                           "net.trust_ca is not allowed" --work "$OKW" --trust-ca "$OPD/opkey"
refused "--learn refused"                            "--learn is not allowed" --work "$OKW" --learn
refused "a policy's own runsc refused"               "may not choose its runsc" --work "$OKW" --runsc /bin/true
refused "--session outside the sessions root"        "is outside" --work "$OKW" --session "$T/elsewhere"
refused "--session via a symlink out of the root"    "is outside" --work "$OKW" --session "$OPD/sessions/link/s"
[ ! -e "$OPD/outside/s" ]; check "…and nothing was created outside" $? "$(ls "$OPD/outside" | tr '\n' ' ')"
opr --work "$OKW" -- true >/dev/null 2>&1; RN="$(XDG_STATE_HOME="$XDG_STATE_HOME" "$PLYBOX" diff --last 2>&1 >/dev/null | sed -n 's/^plybox: session //p')"
refused "--resume refused unless allowed"            "--resume is not allowed" --resume "$RN"
refused "image not on the approved list"             "is not approved" --work "$OKW" --image python:3.13-slim

printf 'paths = ["%s"]\n' "$OPD/work" > "$OPD/no-host.toml"
OPF="$OPD/no-host.toml" refused "host /usr refused unless host_rootfs"  "host's /usr" --work "$OKW"
OPF="$T/missing.toml" refused "missing operator file: refused, not ignored" "missing.toml" --work "$OKW"
printf 'host_rootfs = true\npaths = ["/"]\nhostz = ["*"]\n' > "$OPD/typo.toml"
OPF="$OPD/typo.toml" refused "unknown key in the operator file refused" "unknown field" --work "$OKW"

# Limits the operator requires but this machine cannot enforce: no
# systemd-run on PATH, and on a desktop no cgroup of our own either.
mkdir -p "$T/bin"; ln -sf "$(command -v bwrap)" "$T/bin/bwrap"
msg="$(PATH="$T/bin" OPF="$OPD/limits.toml" opr --work "$OKW" -- /usr/bin/true 2>&1)"; code=$?
if [ $code -eq 0 ]; then  # a container's init: the direct cgroup worked
  start_of "$(ls -td "$XDG_STATE_HOME"/plybox/sessions/*/ | head -1)" | grep -q '"via":"cgroup '
else echo "$msg" | grep -q "cannot be enforced"; fi
check "required limits unenforceable: refused" $? "$(echo "$msg" | head -1 | sed 's/^plybox: //' | cut -c1-90)"

# Where this machine can enforce cgroup limits, [max] fills them in too.
S="$OPD/sessions/lim"
if OPF="$OPD/limits.toml" opr --work "$OKW" --session "$S" -- true >/dev/null 2>&1; then
  start_of "$S" | grep -q '"mem":"1G"' && start_of "$S" | grep -q '"pids":256'
  check "max mem/pids fill in when the policy is silent" $? "$(start_of "$S" | grep -o '"via":"[^"]*"')"
else
  printf 'check\t%-52s\tskip\t%s\n' "max mem/pids fill in when the policy is silent" "no cgroup limits on this machine"
fi

if [ -x "$RUNSC" ]; then
  sed "1i isolation = \"gvisor\"\nrunsc = \"$RUNSC\"" "$OPD/operator.toml" > "$OPD/gvisor.toml"
  S="$OPD/sessions/gv"
  msg="$(OPF="$OPD/gvisor.toml" opr --work "$OKW" --session "$S" --isolation ns -- true 2>&1)"; code=$?
  [ $code -eq 0 ] && start_of "$S" | grep -q '"isolation":"gvisor"'
  check "operator forces the gVisor tier over the policy's ns" $? "exit $code $(echo "$msg" | head -1 | cut -c1-60)"
fi

echo "scratch dir: $T"
exit $((FAILS > 0))
