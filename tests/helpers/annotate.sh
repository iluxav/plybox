#!/usr/bin/env bash
# Turn a suite's FAIL lines into GitHub Actions annotations, so a failure
# can be read from the run page (and the public API) without the raw log.
#
#   tests/helpers/annotate.sh SUITE LOGFILE EXIT_CODE
#
# Exits with EXIT_CODE. If the suite failed without any FAIL line (it
# crashed), the last lines of its output become the annotation instead.
suite="$1" log="$2" code="${3:-0}"
esc() { sed -e 's/%/%25/g' -e 's/\r/%0D/g' | sed -e ':a;N;$!ba;s/\n/%0A/g'; }
fails="$(grep -P '\tFAIL\t' "$log" || true)"
if [ -n "$fails" ]; then
  while IFS=$'\t' read -r _ name _ detail; do
    name="$(echo "$name" | sed 's/[[:space:]]*$//')"
    echo "::error title=$suite: $name::$(printf '%s' "${detail:-no detail}" | esc)"
  done <<< "$fails"
elif [ "$code" -ne 0 ]; then
  echo "::error title=$suite exited $code::$(tail -15 "$log" | esc)"
fi
exit "$code"
