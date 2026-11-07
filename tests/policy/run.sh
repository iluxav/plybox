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

echo "scratch dir: $T"
exit $((FAILS > 0))
