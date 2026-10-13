#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
TMP="$(mktemp -d)"
GATEWAY_PID=""
cleanup() {
  if [[ -n "$GATEWAY_PID" ]]; then kill "$GATEWAY_PID" 2>/dev/null || true; wait "$GATEWAY_PID" 2>/dev/null || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT
command -v openssl >/dev/null || { echo "OpenSSL is needed for this local TLS-only smoke test." >&2; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$TMP/lab.key" -out "$TMP/lab.crt" -subj "/CN=localreach-lab" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
go build -o "$TMP/localreach-lab" ./cmd/localreach-lab
"$TMP/localreach-lab" -mode gateway -data "$TMP/data" -cert "$TMP/lab.crt" -key "$TMP/lab.key" >"$TMP/gateway.out" 2>&1 &
GATEWAY_PID=$!
READY=false
for _ in $(seq 1 100); do
  if [[ -f "$TMP/data/agent.json" ]]; then
    if curl --silent --fail --cacert "$TMP/lab.crt" https://127.0.0.1:18787/v1/agent/heartbeat -o /dev/null 2>/dev/null; then
      READY=true; break
    fi
    # A 405 or 403 indicates the TLS server is listening.
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' --cacert "$TMP/lab.crt" https://127.0.0.1:18787/v1/agent/heartbeat || true)"
    if [[ "$status" == "405" || "$status" == "403" ]]; then READY=true; break; fi
  fi
  if ! kill -0 "$GATEWAY_PID" 2>/dev/null; then cat "$TMP/gateway.out"; exit 1; fi
  sleep 0.1
done
if [[ "$READY" != true ]]; then cat "$TMP/gateway.out"; echo "Gateway startup timed out" >&2; exit 1; fi
"$TMP/localreach-lab" -mode agent -data "$TMP/data" >"$TMP/agent.out" 2>&1
grep -q 'mock command handled: true' "$TMP/agent.out" || { cat "$TMP/agent.out"; exit 1; }
echo "PASS: separate gateway and agent processes exchanged a mock command over verified loopback TLS."
