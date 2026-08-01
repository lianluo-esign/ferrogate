#!/usr/bin/env bash
# Wave-24 boot proof: five Workers, real `wrangler dev --local`, distinct ports.
#
# Same three claims as wave 20 (workerd accepts the COMMITTED wrangler.toml,
# /healthz answers 200 from the deployed entry module, and the five health
# documents share ONE shape), plus the one this wave introduced:
#
#   4. `/readyz` on the gateway is now ASYNC and reads the durable
#      `runtime-state/drain` document (FLEET-CONSISTENCY FC-1, third leg). A
#      boot that hangs, 500s or reports an unhandled rejection there would be
#      invisible to vitest, which never runs wrangler's own bundle.
#
# LOCAL ONLY. No `wrangler deploy`, no remote binding, no real upstream.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT=/tmp/wave24-boot
rm -rf "$OUT"; mkdir -p "$OUT"

APPS=(gateway:8821 control-plane:8822 mcp:8823 agent-runtime:8824 telemetry:8825)
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
  sleep 2
  for pid in "${PIDS[@]:-}"; do kill -9 "$pid" 2>/dev/null; done
  pkill -f "wrangler dev" 2>/dev/null
  pkill -f workerd 2>/dev/null
}
trap cleanup EXIT

for entry in "${APPS[@]}"; do
  app="${entry%%:*}"; port="${entry##*:}"
  ( cd "$ROOT/apps/$app" && exec bunx wrangler dev --local --port "$port" \
      --inspector-port "$((port + 100))" ) > "$OUT/$app.log" 2>&1 &
  PIDS+=($!)
done

echo "waiting for boot (up to 180s)..."
for i in $(seq 1 90); do
  ready=0
  for entry in "${APPS[@]}"; do
    app="${entry%%:*}"
    grep -qiE "Ready on" "$OUT/$app.log" 2>/dev/null && ready=$((ready + 1))
  done
  [ "$ready" -eq 5 ] && break
  sleep 2
done

echo
echo "=== BOOT + /healthz ==="
for entry in "${APPS[@]}"; do
  app="${entry%%:*}"; port="${entry##*:}"
  readyline="$(grep -iE "Ready on" "$OUT/$app.log" 2>/dev/null | head -1 | tr -d '\r')"
  code="$(curl -s -o "$OUT/$app.healthz.json" -w '%{http_code}' \
          --max-time 20 "http://127.0.0.1:$port/healthz" 2>/dev/null)"
  echo "--- $app (port $port)"
  echo "    ready: ${readyline:-<NO 'Ready on' LINE>}"
  echo "    /healthz HTTP $code"
  echo "    body: $(cat "$OUT/$app.healthz.json" 2>/dev/null)"
done

echo
echo "=== /readyz (wave 22: the gateway's is now an async durable read) ==="
for entry in "${APPS[@]}"; do
  app="${entry%%:*}"; port="${entry##*:}"
  code="$(curl -s -o "$OUT/$app.readyz.json" -w '%{http_code}' \
          --max-time 20 "http://127.0.0.1:$port/readyz" 2>/dev/null)"
  echo "--- $app  /readyz HTTP $code"
  echo "    body: $(head -c 400 "$OUT/$app.readyz.json" 2>/dev/null)"
done

echo
echo "=== FLEET HEALTH-DOCUMENT SHAPE ==="
python3 - "$OUT" <<'PY'
import json, os, sys
out = sys.argv[1]
shapes = {}
for app in ("gateway", "control-plane", "mcp", "agent-runtime", "telemetry"):
    p = os.path.join(out, f"{app}.healthz.json")
    try:
        doc = json.load(open(p))
        shapes[app] = sorted(doc.keys())
        print(f"{app:15} keys={sorted(doc.keys())}  version={doc.get('version')!r}")
    except Exception as exc:
        shapes[app] = f"UNPARSEABLE: {exc}"
        print(f"{app:15} {shapes[app]}")
distinct = {tuple(v) if isinstance(v, list) else v for v in shapes.values()}
print()
print(f"distinct shapes: {len(distinct)}  -> {'IDENTICAL' if len(distinct) == 1 else 'DIVERGENT'}")
print("every document carries `version`:",
      all(isinstance(v, list) and "version" in v for v in shapes.values()))
PY
