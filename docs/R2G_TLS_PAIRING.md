# R2G — TLS-only pairing transport experiment

## What was implemented
- Fixed malformed literal escaped newline text introduced in R2F pairing handoff code. Its prior GitHub Actions test job failed; R2G must establish a green gate before any claim of successful verification.
- An independent `internal/pairtransport` **HTTP handler**; it never starts a public listener.
- HTTPS is mandatory and browser-origin requests are denied; request bodies are bounded and decoded strictly.
- Administrator decisions are Ed25519-signed with a domain-separated canonical payload including tenant, request ID, approval decision and a 32-byte random nonce.
- Authorized administrator public keys are **provisioned into the handler by trusted server setup**, never accepted from an HTTP request. Each signed decision nonce can be used once.
- A separately generated 30-second single-use challenge is required before the approved agent can retrieve an invitation. The candidate signs `request ID + fresh nonce` using the public key originally bound to the request.
- The invitation is delivered in the TLS response, and one-time enrollment consumes it after another Ed25519 proof of possession. No device permissions are granted.
- Tests cover TLS-only behavior, wrong admin identity, cross-tenant decisions, signed decision replay, wrong agent key, single-use handoff challenge, wrong enrollment key, enrollment replay and expiry.

## Scope that remains intentionally excluded
The request proposal is still created through the in-process pairing manager, not a network API. The administrator keys are preinstalled in a test fixture; no user login, SSO, admin sessions, automated key rotation or audit trail exists. Identity, approval, invitation and replay state are in-memory and single-process. No real pairing UI, signed installer, secure OS key storage, durable cross-process persistence or public deployable gateway exists.

The earlier `InvitationForAgent` helper signs a static request ID and must **not** be used as a network authorization protocol; use the new fresh-challenge route. The transport has no abuse-rate controls beyond map size limits, no TLS client/channel binding, no revocation fanout and no transactional shared storage. Approval does not grant any device capability.

## Verification
R2F predecessor CI failed during Go tests. R2G must pass the branch GitHub Actions workflow (`go test ./...`, `go vet ./...`, race tests, mock two-process loopback check) before being considered validated. No WAN, printer, attendance device or signed installer use is authorized.

## Next
Fix CI until green; then R2H: durable admin and agent identity with audit, isolated role authorization and protected key storage. Integrate pairing only after real tenant admin auth and request-side throttling, keeping the local setup UI honest about status.
