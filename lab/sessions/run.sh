#!/usr/bin/env bash
# plybox lab: session lifecycle and apply safety.
#
#   lab/sessions/run.sh [path/to/plybox]
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
last() { ls -1 "$XDG_STATE_HOME/plybox/sessions" | sort | tail -1; }

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

# --- 3. discard and prune -----------------------------------------------------
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

echo "lab dir: $T"
exit $((FAILS > 0))
