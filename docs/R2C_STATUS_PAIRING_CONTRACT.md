# R2C — Local agent status and pairing trust boundary

R2C introduces a read-only local setup status contract. It does **not** enroll or pair the user yet.

GET /v1/local/status:
```json
{"agent":"RUNNING","pairing":"NOT_PAIRED","connection":"OFFLINE","devices":"NOT_DISCOVERED"}
```

The dedicated handler accepts only loopback peers, read-only GET, and a restricted local setup origin when an Origin header is provided. This is an internal API for a future local desktop agent; no background listener or service is started. Do not reverse-proxy it into a public host.

## Pairing security specification (not implemented)
1. A logged-in tenant admin creates a short-lived, single-use scoped invitation through authenticated control plane.
2. The **local agent** generates its private Ed25519 key in OS-protected storage, with user-approved connection.
3. Agent proves possession of its key, the invitation is redeemed atomically, and admin receives a confirmation.
4. Capability grants are separate and explicit; pairing alone does not enable printing or attendance reads.
5. The UI displays PAIRED/ONLINE only after receiving verified local status grounded in an authenticated session to the control plane.

## Important limitations
- There is no real agent service serving this status endpoint.
- Read-only status is not cryptographically authenticated; unrestricted local processes may read it. No identifying secrets are returned.
- A browser page served from a different origin will not get CORS permission. A production setup UI should be served from the same trusted loopback origin or use a native desktop shell.
- No automatic discovery, OS installer, app admin auth, real pairing, or device access.
