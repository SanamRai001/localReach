# R2E — Explicit pairing approval policy

Implemented an in-memory, fail-closed request state machine:
PENDING_APPROVAL -> APPROVED / REJECTED / EXPIRED -> ENROLLED (on authenticated proof).

A tenant administrator must be independently authenticated and authorized before `Decide` can be called. The policy primitive checks matching tenant scope and authorization flag but is **not an auth provider**. A pairing proposal cannot enroll by itself. On approval, a private one-time enrollment invitation is created. The registered agent key must prove ownership before enrollment.

## Integration blockers
- No HTTP pairing endpoints are introduced, particularly none on the read-only local setup server.
- No safe method yet to deliver the one-time invitation to the local agent; it remains hidden in memory. End-to-end enrollment with this manager is therefore incomplete.
- No durable transactional approval/audit table, org admin login/session verification, secure OS private-key storage, public transport, approved capability grants or revocation UI.
- Browser-visible pairing stays NOT_PAIRED: do not simulate success from policy state.
- In-memory approvals are lost on restart; an approved token is not an actual durable authorization.
- Physical-device access is not enabled.

This isolated policy slice must not be wired to an untrusted caller until robust admin identity, authenticated agent communication, audit and transactional persistence exist.
