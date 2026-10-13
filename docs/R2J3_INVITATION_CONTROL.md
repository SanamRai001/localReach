# R2J.3 — Authenticated invitation intake and loopback TLS control plane

## Scope

This is an **isolated, operator-run prototype**, not a public cloud service or a released Connect button. No new device permission, discovery, printer, attendance or shell command is enabled.

The workflow is now:

1. An organization administrator already provisioned with an Ed25519 key performs a **signed** login challenge. The backend issues a five-minute, hashed, revocable session.
2. The authenticated OWNER/ADMIN uses `POST /v1/control/invite` with organization and site. The backend verifies the live role again, writes a short-lived, cryptographically random **256-bit one-use invitation** (hash only in PostgreSQL) and an audit row. It returns the secret once, and only through the authenticated TLS response.
3. The prospective agent explicitly creates its signing key in the OS vault, runs `localreach-agent request`, and pastes the short-lived invitation **via standard input**, not an argument or environment variable. `/v1/agent/request-invite` checks the token and inviter's continuing authorization, then creates a **PENDING** proposal and consumes the invitation in one serializable PostgreSQL transaction with audit.
4. The administrator uses authenticated `POST /v1/control/review` to inspect the proposed public-key SHA-256 **fingerprint**, site, status, and expiry. The administrator must compare that fingerprint out-of-band with the agent owner before signing a separate decision through the existing protected `/v1/control/decide` route. A stolen invitation **must never** result in automatic approval.
5. Only after approval can the agent run `localreach-agent enroll`, prove possession of the same key via one-use Ed25519 enrollment challenge, and later use `serve` to check signed identity status. A successful proof still means `OFFLINE` cloud command connection, zero device grants.

### HTTP API added

- `POST /v1/control/login-challenge` — native admin-client key login challenge
- `POST /v1/control/login` — 64-byte Ed25519 proof yields five-minute hashed session
- `POST /v1/control/invite` — preauthorized OWNER/ADMIN bearer, creates one-use invitation
- `POST /v1/control/review` — preauthorized OWNER/ADMIN bearer, read-only candidate fingerprint and pending status
- `POST /v1/agent/request-invite` — token plus agent **public** key creates pending proposal

Existing `propose`, signed `decide`, `enrollment-challenge`, `enroll`, `resume-challenge` and `resume-verify` routes remain unchanged. All network handlers reject plaintext, browser Origin/Cookie, unrecognized methods and oversized input. The new login/invitation routes **fail closed** without an explicitly constructed `pairapi.Guard`: a bounded, single-process limiter allowing up to five admissions/minute per directly observed peer IP. It deliberately ignores spoofable `X-Forwarded-For`. **This is not sufficient for public ingress**, multi-replica gateways, proxy-aware per-user throttling, denial-of-service defense or application-layer abuse.

### Database

Migration `063_pairing_invitations.sql` adds organization-and-site-scoped invitations, unique hashed secrets, a consumed request reference and invitation issue/redeem audit. One secret can be redeemed only once, by exactly one agent. The issuer must remain ACTIVE with OWNER/ADMIN role. Token expiry: 10 minutes; the new pending request expiry: 5 minutes. `RedeemInvitation` and invitation issuance are PostgreSQL SERIALIZABLE transactions; failed inserts or audit operations roll back the entire operation.

### Operator-only local TLS executable

`cmd/localreach-control` is a **manually runnable** HTTPS server which binds **only to `127.0.0.1:19443`** and has no configurable external listen address. It will not run without an operator-supplied TLS certificate and private key, PostgreSQL DSN, and existing database migrations/admin key provisioning. It does not log bearer tokens, passwords, invitation codes or database DSNs.

Example for an already configured *local test* environment:

```sh
# Store a disposable localreach_test DB DSN in LOCALREACH_CONTROL_DSN
# (never commit credentials). Provision the schema & trusted owner separately.
go run ./cmd/localreach-control \
  -tls-cert ./local-cert.pem -tls-key ./local-key.pem \
  -allow-disposable-loopback-db
```

For non-test databases, PostgreSQL must use `sslmode=verify-full`, and TLS certificates must be verifiably trusted. The opt-in plain PostgreSQL option works **only for `localreach_test` on loopback**. The example command does not generate certificates, create users or configure a domain. On the native agent, use a gateway URL that its **ordinary TLS trust store validates**. Never disable TLS verification or forward this loopback prototype to the public Internet.

```sh
go run ./cmd/localreach-agent init
go run ./cmd/localreach-agent request -organization ORG_ID -gateway https://TRUSTED_HOST
# Paste the invitation at the terminal prompt. Result: PENDING_APPROVAL.
# Administrator must independently inspect fingerprint and sign approval.
go run ./cmd/localreach-agent enroll -organization ORG_ID -gateway https://TRUSTED_HOST -request APPROVED_REQUEST_ID
```

The administrator key must still be securely provisioned out of band. There is **no human-facing administrator account portal or operating-system-protected admin signer CLI**, and no public deployment. An installation on a remote Wi-Fi network cannot connect to an address bound to loopback on another machine.

### Verification

Go/PostgreSQL tests include:
- Invite issuance only by live active OWNER/ADMIN; blocked organization, revoked administrator, viewer, invalid/expired code, cross-tenant redemption and replay all denied
- Competing invitation redemptions: **exactly one pending proposal**
- Full HTTPS signed admin login → one-time invitation → pending proposal → **authenticated public-key fingerprint review** → separate signed approval → Ed25519 native enrollment and recovery
- Wrong/bad token denial; per-peer admission guard cannot be bypassed with an attacker-controlled forwarded-for header
- Operator control-plane rejects remote plaintext database connections, absent TLS identity, unexpected command-line parameters and non-loopback listeners
- Linux/Windows/macOS compilation, PostgreSQL, native vault and prior local mock TLS checks preserved in CI

### Release blockers

No true Internet-facing hosted control plane, distributed abuse limiter, proxy configuration, cloud session manager, online-state signal, native background installer/service, admin portal + secure admin key custody, authenticated recovery/rotation UI, monitored relay or WAN/CGNAT acceptance. User consent, tenant billing policy and **separate per-device/per-capability grants** remain mandatory before any printer or attendance command. Only a local prototype with remote-client-capable code is implemented; nothing has been deployed.

## Next

R2J.4 should implement a hardened operator-managed gateway and human administrator consent flow, with production TLS/DB secret storage, user/key provisioning, multi-tenant request throttling and trusted bootstrap. Then R2K will introduce safe capability-grant contracts and device discovery, followed by hardware tests. None of these steps should expose arbitrary tunneling, device-write actions or private keys to a browser.
