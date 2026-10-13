# R1I — Mock reconciliation and outbound polling supervisor

## Delivered
- Repeat broker claims now inspect the durable edge journal instead of blindly rerunning an operation.
- A previous SUCCEEDED / FAILED / INDETERMINATE edge result can be reported back using the new broker lease, without repeating mock execution.
- An existing QUEUED or EXECUTING local intent is marked INDETERMINATE in the broker when re-claimed; it is never automatically executed.
- New cancellable outbound `Runner` with idle interval, bounded exponential reconnect backoff and jitter. It does not bypass the journal.
- Tests added/updated for completed-result reconciliation, prior unexecuted/uncertain intent, and runner cancellation.

## Important fault semantics
The broker can be LEASED and the agent can have recorded its ID while the Receive HTTP acknowledgment is lost. After lease expiration, the broker can offer the job again. The edge journal prevents duplicate execution; an earlier recorded final result is reported, otherwise the broker records INDETERMINATE and requires explicit review.

A previously RECEIVED broker job is **not re-leased**; after the deadline its broker state is INDETERMINATE. That case still needs an authenticated, auditable reconciliation protocol for a known completed edge result. Do not auto-promote a cloud INDETERMINATE status to SUCCEEDED without verifying the original scoped job and edge evidence.

## Limitations and release blockers
- HTTP transport still uses test TLS servers; the runner is a reusable library, not an installable Windows service or a real WAN deployment.
- **No production-grade cloud/edge reconciliation**; no reconciliation endpoint for a previously terminal broker job, and no proof that a mock result maps to an irreversible device effect.
- Credentials remain unbound bearer sessions; registry is in-memory, admin-authorized enrollment and secure agent key storage absent.
- Single-process append-only storage has no locks, compaction, crash fault injection, repair/recovery tools or transactional coordination.
- No rate limits, audit trail, public-facing policy boundary, operational metrics, persistent connection, CGNAT experiments, signed installer, real-device adapters or one-click UX.
- Polling backoff handles transient errors but does not implement session reuse, liveness visibility, nor automatic device discovery.

## Batched acceptance instructions (deferred)
```powershell
git fetch origin
git switch --track origin/feat/r1i-reconciliation-runner
go test ./...
go vet ./...
```
Expected: tests pass with no vet diagnostics. This is unverified until run. Follow with race and failure-injection tests on a suitable environment at the integration gate.

## Next
R1J should prioritize release-blocking invariants: serialized storage ownership, safe replay/reconciliation when broker is terminal, authenticated admin grants, durable identity/key management, and a real two-process test harness. Validate this before public WAN testing or real hardware.
