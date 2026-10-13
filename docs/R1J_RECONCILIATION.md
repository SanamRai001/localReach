# R1J — late-result reconciliation hardening

## Implemented
- Fixed TLS handler JSON decoder to reject malformed or trailing content rather than silently accepting a second invalid value; the previously unused io import now has a purpose.
- Introduced broker.ReconcileObservedResult for an already INDETERMINATE command whose original RECEIVED lease expired. The state change requires the exact original tenant, agent and lease, and only accepts SUCCEEDED or FAILED as final observed outcomes.
- Tests prevent cross-tenant/agent reconciliation, wrong-lease updates, rewriting completed results and claiming success for never-received commands.

## What this deliberately does NOT do
There is **no public reconciliation HTTP endpoint**: an original lease token is insufficient evidence by itself that real hardware executed an operation. A production endpoint must require authenticated, independently verifiable, durable edge evidence bound to job ID, tenant, agent, operation, result and original lease, plus replay and timestamp validation. Current broker file storage remains a single-process prototype.

The existing outbound poller does not yet invoke late-result reconciliation. A timed-out RECEIVED command stays INDETERMINATE unless a trusted internal caller explicitly reconciles it. No real devices may be enabled.

## Unresolved release blockers
OS-level single-writer file locking; partial-write recovery; journal compaction/retention; session binding, rate limits and durable enrollment; signed reconciliation evidence; a two-process gateway/agent harness; independent security review; actual separate-network connectivity; installer and UX.

## Verification
No Go test suite was executed in this GitHub editing environment. At the consolidated acceptance gate run `go test ./...` and `go vet ./...`. The user has deferred time-consuming local verification.
