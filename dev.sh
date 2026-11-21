#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Start forgec on a free port, run the make.fun conformance suite against it, print a summary.
#   usage: dev.sh [--perf] [--json]
set -u
ROOT="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-9099}"
TOKEN="${TOKEN:-tok123}"
NODE="${NODE:-/home/ubuntu/.hermes/tools/node-26.12.1-linux-x64/bin/node}"

stop() {
  if [ -f "$ROOT/.forge.pid" ]; then
    kill -9 "$(cat "$ROOT/.forge.pid")" 2>/dev/null || true
    rm -f "$ROOT/.forge.pid"
  fi
  # fall back: free the port no matter who holds it
  local pid
  pid="$(ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p {print $NF}' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1)"
  [ -n "${pid:-}" ] && kill -9 "$pid" 2>/dev/null || true
}

stop
( cd "$ROOT" && MAKEFUN_SHOP_TOKEN="$TOKEN" ./forge --port "$PORT" >"$ROOT/.forge.log" 2>&1 & echo $! > "$ROOT/.forge.pid" )
sleep 0.6
if ! curl -s -m 3 "http://127.0.0.1:$PORT/healthz" >/dev/null; then
  echo "server did not come up"; cat "$ROOT/.forge.log"; exit 1
fi

"$NODE" --experimental-strip-types "$ROOT/suite/run.ts" --url "http://127.0.0.1:$PORT" --token "$TOKEN" --json "$@" \
  > "$ROOT/.run.json" 2>"$ROOT/.run.err"
rc=$?

python3 "$ROOT/summarize.py" "$ROOT/.run.json"
stop
exit $rc
