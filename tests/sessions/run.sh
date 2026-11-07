#!/usr/bin/env bash
# plybox lab: session lifecycle and apply safety.
#
#   tests/sessions/run.sh [path/to/plybox]
#
# Uses a throwaway XDG_STATE_HOME, so the caller's real sessions are never
# listed, pruned or discarded. Prints one `check <TAB> pass|FAIL <TAB> detail`
# line per check and exits non-zero if any check fails.
set -uo pipefail
PLYBOX="${1:-plybox}"
T="$(mktemp -d /tmp/plybox-sessions-lab.XXXXXX)"
export XDG_STATE_HOME="$T/state"
FAILS=0
check() { # name, condition-exit-code, detail
  if [ "$2" -eq 0 ]; then printf 'check\t%-46s\tpass\t%s\n' "$1" "$3"
  else printf 'check\t%-46s\tFAIL\t%s\n' "$1" "$3"; FAILS=$((FAILS+1)); fi
}
run() { "$PLYBOX" run --quiet --work "$1" -- sh -c "$2" >/dev/null 2>&1; }
# The newest session, as plybox itself resolves `--last` (it names the
# session it picked on stderr).
last() { "$PLYBOX" diff --last 2>&1 >/dev/null | sed -n 's/^plybox: session //p'; }

# --- 1. apply carries a deletion, an edit and a new file -------------------
W1="$T/ws1"; mkdir -p "$W1"; echo keep > "$W1/keep.txt"; echo doomed > "$W1/doomed.txt"
run "$W1" 'unlink doomed.txt; echo edited > keep.txt; echo new > added.txt'
S1="$(last)"
[ -e "$W1/doomed.txt" ] && [ "$(cat "$W1/keep.txt")" = keep ]; check "box changes held, workspace untouched" $? "before apply"
"$PLYBOX" diff "$S1" > "$T/diff1.txt" 2>&1
grep -q '^D  doomed.txt' "$T/diff1.txt" && grep -q '^M  keep.txt' "$T/diff1.txt" && grep -q '^A  added.txt' "$T/diff1.txt"
check "diff lists D/M/A" $? "$(tr '\n' ' ' < "$T/diff1.txt")"
"$PLYBOX" sessions | grep -q "$S1.*PENDING 3"; check "sessions shows PENDING 3" $? "$("$PLYBOX" sessions | grep "$S1" | cut -c1-60)"
"$PLYBOX" apply "$S1" >/dev/null 2>&1
[ ! -e "$W1/doomed.txt" ]; check "apply deletes the deleted file" $? "doomed.txt gone"
[ "$(cat "$W1/keep.txt")" = edited ] && [ "$(cat "$W1/added.txt")" = new ]; check "apply carries edit + new file" $? "keep.txt=edited added.txt=new"
"$PLYBOX" sessions | grep -q "$S1.*applied"; check "sessions shows applied" $? "after apply"

# --- 1b. housekeeping: apply keeps only the record; runs leave no run files --
D1="$XDG_STATE_HOME/plybox/sessions/$S1"
left="$(ls -A "$D1" | sort | tr '\n' ' ')"
[ ! -e "$D1/upper" ] && [ ! -e "$D1/work" ] && [ -f "$D1/meta.json" ] && [ -f "$D1/record.jsonl" ]
check "apply trims the session to meta + record" $? "left: $left"
echo tampered > "$W1/keep.txt"
msg="$("$PLYBOX" apply "$S1" 2>&1)"; code=$?
[ $code -ne 0 ] && echo "$msg" | grep -q 'already applied' && [ "$(cat "$W1/keep.txt")" = tampered ]
check "second apply refused, workspace untouched" $? "$(echo "$msg" | head -1 | cut -c1-80)"
out="$("$PLYBOX" diff "$S1" 2>&1)"; code=$?
[ $code -eq 0 ] && echo "$out" | grep -q 'was applied'
check "diff of an applied session explains itself" $? "$(echo "$out" | head -1 | cut -c1-80)"
WC="$T/wsc"; mkdir -p "$WC"
# A secret makes plybox create a session CA and trust bundle for the run.
"$PLYBOX" run --quiet --work "$WC" --secret 'TOK=lab-fake-value@example.com' -- sh -c 'echo c > c.txt; test -s /run/plybox/ca.pem && echo yes > had-ca.txt' >/dev/null 2>&1
SC="$(last)"; DC="$XDG_STATE_HOME/plybox/sessions/$SC"
[ "$("$PLYBOX" diff "$SC" 2>/dev/null | grep -c had-ca.txt)" = 1 ]; check "a run with a secret had its CA while running" $? "$SC"
[ ! -e "$DC/ca.pem" ] && [ ! -e "$DC/bundle.pem" ] && [ ! -e "$DC/sock/proxy.sock" ] && [ -d "$DC/upper" ]
check "run end removes CA, bundle, socket; keeps the copy" $? "left: $(ls -A "$DC" | sort | tr '\n' ' ')"
"$PLYBOX" discard "$SC" >/dev/null 2>&1

# --- 1c. diff --patch: the lines, and never the target of a symlink ----------
WP="$T/wsp"; mkdir -p "$WP"; printf 'one\ntwo\n' > "$WP/f.txt"; printf 'gone line\n' > "$WP/del.txt"
CANARY="$T/canary.txt"; echo "CANARY-$$-not-for-the-box" > "$CANARY"
"$PLYBOX" run --quiet --work "$WP" -- sh -c "printf 'one\nTWO\n' > f.txt; echo hello > new.txt; unlink del.txt; ln -s '$CANARY' peek" >/dev/null 2>&1
SP="$(last)"; "$PLYBOX" diff "$SP" --patch > "$T/patch.txt" 2>&1; code=$?
[ $code -eq 0 ] && grep -qx -- '-two' "$T/patch.txt" && grep -qx -- '+TWO' "$T/patch.txt" && grep -qx -- '+hello' "$T/patch.txt" && grep -qx -- '-gone line' "$T/patch.txt" && grep -q -- '--- a/f.txt' "$T/patch.txt"
check "diff --patch shows edited, added and deleted lines" $? "$(grep -c '^[-+][^-+]' "$T/patch.txt") changed lines"
grep -q 'symlink → ' "$T/patch.txt" && ! grep -q 'CANARY' "$T/patch.txt"
check "diff --patch names a symlink, never reads its target" $? "$(grep 'symlink' "$T/patch.txt" | head -1 | cut -c1-60)"
"$PLYBOX" discard "$SP" >/dev/null 2>&1

# --- 1d. session paths longer than a unix socket address (107 bytes) --------
# A bounded --disk volume or a CI checkout easily nests that deep; the proxy
# socket inside the session must still bind, serve and shut down promptly.
WL="$T/wsl"; mkdir -p "$WL"
SL="$T/$(printf 'v%.0s' $(seq 1 90))/long-session"; mkdir -p "$(dirname "$SL")"
s=$(date +%s%N)
"$PLYBOX" run --quiet --session "$SL" --work "$WL" -- sh -c 'echo long > long.txt' >"$T/long.out" 2>&1; code=$?
ms=$(( ($(date +%s%N) - s) / 1000000 ))
[ $code -eq 0 ] && [ -f "$SL/upper/long.txt" ] && [ $ms -lt 1500 ]
check "session path over the socket limit still runs" $? "socket path $(( ${#SL} + 16 )) bytes, ${ms} ms, exit $code $(head -c 80 "$T/long.out")"
"$PLYBOX" discard "$SL" >/dev/null 2>&1

# --- 1e. exposure: every host reach shown at start and recorded, no values ---
WE="$T/wse"; mkdir -p "$WE"; TOKF="$T/tok"; echo "lab-token-$$" > "$TOKF"; chmod 600 "$TOKF"
"$PLYBOX" run --work "$WE" --ro-bind "$W1:/opt/peek" --secret-file "TOK=$TOKF@example.com" -- true >"$T/exp.out" 2>&1
SE="$(last)"; RE="$XDG_STATE_HOME/plybox/sessions/$SE/record.jsonl"
grep -qF "reads   $W1 at /opt/peek (read-only)" "$T/exp.out" && grep -qF "secret  TOK from file $TOKF" "$T/exp.out" \
  && grep '"start"' "$RE" | grep -q '"kind":"ro_bind"' && grep '"start"' "$RE" | grep -q '"kind":"secret_file"' \
  && ! grep -q "lab-token-$$" "$RE" "$T/exp.out"
check "start shows + records host exposure, no values" $? "$(grep -c '^plybox:   ' "$T/exp.out") exposure lines"
"$PLYBOX" discard "$SE" >/dev/null 2>&1

# --- 2. apply never writes through a symlink that leaves the workspace ------
W2="$T/ws2"; OUT="$T/outside"; mkdir -p "$W2" "$OUT"; echo original > "$OUT/target.txt"
ln -s "$OUT/target.txt" "$W2/cfg"
run "$W2" 'unlink cfg; echo replaced > cfg'
S2="$(last)"; "$PLYBOX" apply "$S2" >/dev/null 2>&1
[ "$(cat "$OUT/target.txt")" = original ] && [ ! -L "$W2/cfg" ] && [ "$(cat "$W2/cfg")" = replaced ]
check "symlink destination replaced, not written through" $? "outside target.txt=$(cat "$OUT/target.txt"); cfg is now a plain file"

# A tampered upper layer that writes under a directory symlink pointing out.
W3="$T/ws3"; mkdir -p "$W3"; ln -s "$OUT" "$W3/link"
run "$W3" 'echo x > note.txt'
S3="$(last)"; mkdir -p "$XDG_STATE_HOME/plybox/sessions/$S3/upper/link"; echo planted > "$XDG_STATE_HOME/plybox/sessions/$S3/upper/link/planted.txt"
msg="$("$PLYBOX" apply "$S3" 2>&1)"; code=$?
[ $code -ne 0 ] && [ ! -e "$OUT/planted.txt" ] && [ ! -e "$W3/note.txt" ]
check "write through a dir symlink out: refused, nothing applied" $? "$(echo "$msg" | head -1 | cut -c1-90)"

# --- 3. names: readable, prefix-selectable, never ambiguous -----------------
echo "$S1" | grep -Eq '^[a-z]+-[a-z]+(-[0-9]+)?$'; check "new session gets a two-word name" $? "$S1"
SB="$XDG_STATE_HOME/plybox/sessions"
WN="$T/wsn"; mkdir -p "$WN"
"$PLYBOX" run --quiet --session "$SB/alpha-one" --work "$WN" -- sh -c 'echo 1 > one.txt' >/dev/null 2>&1
"$PLYBOX" run --quiet --session "$SB/alpha-two" --work "$WN" -- sh -c 'echo 2 > two.txt' >/dev/null 2>&1
out="$("$PLYBOX" diff alpha-o 2>&1)"; echo "$out" | grep -q 'one.txt' && ! echo "$out" | grep -q 'two.txt'
check "unique prefix selects one session" $? "alpha-o → $(echo "$out" | head -1)"
out="$("$PLYBOX" diff alp 2>&1)"; code=$?; [ $code -ne 0 ] && echo "$out" | grep -q 'alpha-one' && echo "$out" | grep -q 'alpha-two'
check "ambiguous prefix refused, candidates named" $? "$(echo "$out" | head -1 | cut -c1-80)"
"$PLYBOX" discard al >/dev/null 2>&1; [ $? -ne 0 ] && [ -d "$SB/alpha-one" ] && [ -d "$SB/alpha-two" ]
check "2-character prefix refused (discard)" $? "both alpha sessions still there"
[ "$(last)" = alpha-two ]; check "--last is the most recently started" $? "$(last)"
"$PLYBOX" discard alpha-one >/dev/null 2>&1; "$PLYBOX" discard alpha-two >/dev/null 2>&1

# --- 4. discard and prune -----------------------------------------------------
W4="$T/ws4"; mkdir -p "$W4"; run "$W4" 'true'; S4="$(last)"          # empty session
W5="$T/ws5"; mkdir -p "$W5"; run "$W5" 'echo p > pending.txt'; S5="$(last)"  # pending session
"$PLYBOX" sessions --prune > "$T/prune.txt" 2>&1
grep -q "$S1" "$T/prune.txt" && grep -q "$S4" "$T/prune.txt" && ! grep -q "$S5" "$T/prune.txt"
check "prune removes applied + empty, keeps pending" $? "$(grep -c '^removed' "$T/prune.txt") removed"
[ -d "$XDG_STATE_HOME/plybox/sessions/$S5" ]; check "pending session still on disk" $? "$S5"
"$PLYBOX" discard "$S5" >/dev/null 2>&1 && [ ! -e "$XDG_STATE_HOME/plybox/sessions/$S5" ]
check "discard removes a session (incl. overlay scratch dir)" $? "$S5"
"$PLYBOX" discard "$T" >/dev/null 2>&1; [ $? -ne 0 ] && [ -d "$T" ]
check "discard refuses a directory that is not a session" $? "$T still there"

echo "scratch dir: $T"
exit $((FAILS > 0))
