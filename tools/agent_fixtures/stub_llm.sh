#!/bin/sh
COUNT_FILE="${AIFUZZ_AGENT_STATE:-/tmp/aifuzz_agent_stub_count}"
DIR="$(cd "$(dirname "$0")" && pwd)"
n=0
if [ -f "$COUNT_FILE" ]; then
  n="$(cat "$COUNT_FILE")"
fi
n=$((n + 1))
echo "$n" > "$COUNT_FILE"
cat > /dev/null
if [ "$n" = "1" ]; then
  cat "$DIR/bad_harness.c"
else
  cat "$DIR/good_harness.c"
fi
