# R2F — Approved invitation handoff (isolated primitive)

After a tenant-scoped administrator **independently authorized** the pending request, the enrolled-key candidate can sign the random pairing request ID under the `localreach/pairing/handoff/v1:` domain. The pairing manager verifies the signature against the originally proposed Ed25519 public key and returns the short-lived, one-time invitation. The agent then signs the invitation using the existing identity enrollment proof and the manager atomically enrolls it through the registry.

This closes the **in-process proof-of-possession handoff** for test purposes. It does **not** add public pairing HTTP routes or a working consumer onboarding flow.

Security limitations: the manager is in-memory, `Decide` takes an authorization boolean provided by an assumed-trusted caller, no administrator identity integration exists, and the invitation must travel via a confidential authenticated transport. Repeated valid handoff calls may access the token until the request expires/enrolls. No rate limits, auditing, transactionally persistent approvals, OS key storage, channel binding or permission grants exist. Pairing alone must never grant printing or attendance capability.

Acceptance: `go test ./...`, `go vet ./...`, and `go test -race ./...` in GitHub CI. Tests added cover unauthorized and wrong-key retrieval, wrong-key enrollment, successful approval-to-enrollment, replay denial and expiry.
