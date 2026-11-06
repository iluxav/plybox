#!/bin/sh
# plybox lab, step 2: runs INSIDE the box. Prints TSV on stdout.
#
#   inside.sh <probe-binary-path>
#
# Two series:
#   probe    <id> <verdict> <detail>    the attack probes (reused from step 1)
#   workload <name> <ok|fail> <detail>  real tools, to prove the box is usable
#
# The point of step 2: the `n.*` probes should read BLOCKED while the
# workloads to allowed hosts still read ok.
set -u
PROBE="$1"

# --- attack probes (same binary as step 1) ---
# PROBE_LAST=1 runs them after the workloads: under gVisor a memory-limit
# kill takes the whole sandbox down, so the probe must go last there.
run_probe() { "$PROBE" | sed 's/^/probe\t/'; }
[ "${PROBE_LAST:-}" = 1 ] || run_probe

# --- workloads: does a normal tool reach an allowed host through the proxy? ---
# want = the outcome that means the box behaves correctly: "ok" (command
# should succeed) or "blocked" (command should fail — a door that must stay
# shut). The row is a pass only when the outcome matches `want`.
wl() { # name, want, command...
  name="$1"; want="$2"; shift 2
  start=$(date +%s%N 2>/dev/null || echo 0)
  out=$("$@" 2>&1); rc=$?
  end=$(date +%s%N 2>/dev/null || echo 0)
  ms=$(( (end - start) / 1000000 ))
  [ $rc -eq 0 ] && got=ok || got=blocked
  [ "$got" = "$want" ] && verdict=pass || verdict=FAIL
  printf 'workload\t%s\t%s\t%s\t%sms rc=%s %s\n' \
    "$name" "$want" "$verdict" "$ms" "$rc" \
    "$(printf '%s' "$out" | tr '\n\t' '  ' | cut -c1-80)"
}

# allowed host over HTTPS: any HTTP status (even 401) means the tunnel worked.
wl "https allowed host" ok sh -c '
  c=$(curl -sS --max-time 15 -o /dev/null -w "%{http_code}" https://api.anthropic.com/v1/models)
  echo "status $c"; [ "$c" != 000 ]'

# a host NOT in the allow list: the proxy must refuse it, so curl must fail.
wl "https denied host" blocked sh -c '
  curl -sS --max-time 15 -o /dev/null https://example.com'

# npm talking to its registry (allowed), the common agent dependency step.
wl "npm ping registry" ok sh -c '
  npm ping --registry=https://registry.npmjs.org 2>&1 | tail -1'

# direct TCP to the internet, skipping the proxy entirely: must be unreachable.
wl "direct tcp (no proxy)" blocked sh -c '
  curl -sS --noproxy "*" --max-time 8 -o /dev/null https://1.1.1.1'

# --- secrets (step 4; only when the driver attached one) ----------------------
# What the box holds as ANTHROPIC_API_KEY; the driver checks it is the
# placeholder, and that the real value appears nowhere in this output.
if [ -n "${SECRET_TEST_HOST:-}" ]; then
  printf 'secretenv\t%s\n' "${ANTHROPIC_API_KEY:-<unset>}"

  # To the host the secret belongs to: the proxy swaps in the real value.
  wl "secret reaches its own host (substituted)" ok sh -c '
    b=$(curl -sS --max-time 15 -H "x-api-key: $ANTHROPIC_API_KEY" "https://$SECRET_TEST_HOST/")
    echo "$b"; echo "$b" | grep -q "key=ok"'

  # To any other host: the placeholder goes out as-is, worthless.
  wl "secret NOT sent to another host" ok sh -c '
    b=$(curl -sS --max-time 15 -H "x-api-key: $ANTHROPIC_API_KEY" "https://$SECRET_OTHER_HOST/")
    echo "$b"; echo "$b" | grep -q "key=placeholder"'

  # The same through node (Claude Code'"'"'s runtime): env proxy + extra CA.
  wl "node fetch with the secret (substituted)" ok node -e '
    fetch("https://" + process.env.SECRET_TEST_HOST + "/",
          { headers: { "x-api-key": process.env.ANTHROPIC_API_KEY } })
      .then(r => r.text())
      .then(t => { process.stdout.write(t); process.exit(t.includes("key=ok") ? 0 : 1); })
      .catch(e => { console.error(String(e)); process.exit(1); });'
fi

# Under gVisor the probe runs last (see PROBE_LAST above).
[ "${PROBE_LAST:-}" = 1 ] && run_probe
exit 0
