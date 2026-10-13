# R1A: local mock command lifecycle (not remote connectivity)

This first implementation slice tests the control API -> agent poll -> mock execution -> result round-trip. It is intentionally **loopback-only** and **not** the cross-network proof, not an installer, not durable, and not production authentication.

## Requirements
Go 1.22 or newer. Run in PowerShell on Windows, from repository root. Use two terminal windows. Do not commit any tokens.

```powershell
git switch feat/r1a-command-prototype
$env:LOCALREACH_DEV_TOKEN = [guid]::NewGuid().ToString('N')
go test ./...
go run ./cmd/localreach -mode server
```

In a second terminal, set the **same** token value from the first terminal (copy its value privately, not to GitHub):

```powershell
$env:LOCALREACH_DEV_TOKEN = "<same dev token>"
go run ./cmd/localreach -mode agent
```

In a third terminal, set the same token and submit / inspect the mock operation:

```powershell
$env:LOCALREACH_DEV_TOKEN = "<same dev token>"
$headers = @{Authorization="Bearer $env:LOCALREACH_DEV_TOKEN"}
$job = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8787/v1/mock/jobs -Headers $headers -ContentType application/json -Body '{"operation":"mock.ping"}'
$job
Start-Sleep -Seconds 2
Invoke-RestMethod -Uri "http://127.0.0.1:8787/v1/mock/jobs/$($job.id)" -Headers $headers
```

Expected result: queued job progresses to SUCCEEDED with result `pong`. Unauthorized request returns 401. Unknown operation returns 400. Duplicate completion returns 409. Server and agent run until Ctrl+C.

## Known limitations / release blocks
- HTTP over localhost only; hard-coded loopback checks intentionally prohibit WAN/network exposure.
- Development shared bearer token is not agent identity, pairing or key rotation. It must not be deployed.
- In-memory relay loses jobs on restart; no dispatch leases or crash-safe acknowledgments.
- Polling is a temporary spike; RFC targets authenticated outbound TLS transport.
- No discovery, printer adapter, AMS adapter, GUI, signed installer, multi-tenancy or logging privacy audit.
- Local test builds have not been executed by the GitHub connector.

## R1B next gate
Design enrollment and identity before any cross-network deployment; add secure channel, bounded queue/journal and a failure-injection test. Do not extend this proof to bind publicly with a shared token.
