# R1K.2 — Separate-process TLS mock laboratory

Two executable modes: gateway binds **only 127.0.0.1:18787** and creates an ephemeral in-memory agent identity; agent runs in another terminal, reads local test-only identity data, verifies the gateway TLS certificate and issues outbound HTTPS claim/received/complete requests.

This is not the production installer, and it DOES NOT verify remote internet connectivity.

## TLS prerequisite
Create a localhost TLS certificate and key for the lab using a trusted development tool (e.g., mkcert or OpenSSL) with **127.0.0.1 as a certificate SAN**. Do not copy production private keys into this lab. Both the certificate and private key remain local. Example with OpenSSL:

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout .localreach-lab/lab.key -out .localreach-lab/lab.crt -subj "/CN=localreach-lab" -addext "subjectAltName=IP:127.0.0.1"
```

Create the directory beforehand. If OpenSSL is unavailable, skip the manual harness for now; unit/integration tests use Go's httptest TLS server automatically.

## Gateway terminal
```powershell
go run ./cmd/localreach-lab -mode gateway -data .localreach-lab -cert .localreach-lab/lab.crt -key .localreach-lab/lab.key
```
Gateway issues a single `lab-mock-001` command and writes `agent.json` with a **test private key**. Do not commit `.localreach-lab` or expose its contents.

## Agent terminal
```powershell
go run ./cmd/localreach-lab -mode agent -data .localreach-lab
```
Expected console output: `mock command handled: true`. The broker and edge logs persist results across processes. Stop the gateway before restarting it; it creates ephemeral identity and submits one fixed ID, so repeated gateway launches with the same data directory are not currently supported without safe reset.

## Limitations
- A local test harness only, with one enrolled agent, one mock.ping job, and separate processes on the same machine.
- In-memory registry is regenerated each server start.
- No UI, signed installer, device discovery, authorization-grant API, managed certificates, automatic renewal, real WAN access, or hardware.
- The entire gateway is a development prototype. **Never bind to 0.0.0.0 or expose via public tunnel.**
- Command journal ownership sentinels can remain after unclean termination; don't automatically delete without confirming no writer exists.

## Consolidated verification (not run by the GitHub connector)
```powershell
go test ./...
go vet ./...
```
Then run the two-process harness separately. Hardware, CGNAT and WAN tests remain blocked behind security hardening.
