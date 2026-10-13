# R1D — Crash-aware command journal spike

## Delivered
A standalone Go append-only edge journal that fsyncs an event before making the new command state visible. Operations: Submit -> Begin -> Finish. Distinct states: QUEUED, EXECUTING, SUCCEEDED, FAILED, INDETERMINATE. On restart, unfinished EXECUTING commands become INDETERMINATE and cannot silently execute again. QUEUED commands remain queued. Invalid or truncated records make startup fail closed. Journal size is bounded.

## Why it matters
A printer may accept a print command before the network drops. Sending it again might print twice. **Claiming a job means we may have started irreversible IO**. Thus an interrupted EXECUTING command is uncertain rather than automatically retried.

## Limitations
- Library is intentionally isolated from R1A relay and TLS gateway. No device side effects yet.
- The append log uses a single-process writer assumption; **no OS file lock**, compaction, transactional cross-process delivery, encryption at rest, or safe cross-machine coordination.
- File and directory creation permissions vary by OS; run with isolated working directory and restricted user account.
- The disk-full/partial-write scenario may corrupt the journal. It deliberately fails to start rather than ignoring bytes; operational recovery tooling is required.
- No durable event acknowledgements across cloud/gateway, idempotency-key policy, quotas per tenant, delivery expiration or command reconciliation yet.
- `FAILED` and `INDETERMINATE` are terminal. Reconciliation requires an explicit audited separate operation in a later phase.

## Deferred verification
Run `go test ./...` and `go vet ./...` in the eventual acceptance batch. Never test with real hardware until safety boundaries are confirmed.

## Next design gate
Add a versioned operation manifest with policy-based retry classes; ensure server+agent have distinct acknowledgments and stable job IDs, and design durable cloud claim leasing. Introduce fsync fault injection and journal repair guidance before field deployment.
