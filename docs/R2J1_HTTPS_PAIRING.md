# R2J.1 — HTTPS pairing control plane (no public deployment)

## Delivered

An independent `internal/pairapi.Handler` exposes a narrow HTTP+JSON **testable HTTPS pairing protocol**. It does **not** bind a port, run a gateway, grant device capabilities, or make the local setup browser an administrator.

The caller must install a properly authenticated TLS server. The handler rejects plaintext, browser `Origin`/Cookie, unrecognized routes and methods, unknown JSON fields, oversized request bodies and unrestricted redirects. Response caching is disabled.

| Native-only route | Authorization | Effect |
|---|---|---|
| `POST /v1/control/propose` | Existing unexpired `pgauth` bearer token, live OWNER/ADMIN | Records scoped agent public key as PENDING; never approves |
| `POST /v1/control/decide` | Same bearer, exact same administrator ID, **independent** Ed25519-signed decision | PostgreSQL serializable approval/rejection/revocation with unique nonce and audit |
| `POST /v1/agent/enrollment-challenge` | Unapproved or unknown requests denied; short-lived challenge only for APPROVED | Sends one-use challenge for native private-key proof |
| `POST /v1/agent/enroll` | Signed one-use Ed25519 proof bound to original proposal key | Atomically records enrolled identity, no device grants |
| `POST /v1/agent/resume-challenge` | Existing unrevoked public key; challenge rate controls still needed | Sends challenge bound to agent ID and organization |
| `POST /v1/agent/resume-verify` | Private-key Ed25519 proof of fresh challenge | `IDENTITY_VERIFIED` with explicit `OFFLINE` and `NONE` capabilities |

`internal/agentremote.Client` uses a **caller-supplied trusted TLS HTTP client** to perform enrollment/resume from a native signer. The client requires `https://`, denies URL-embedded credentials, follows no redirects, uses bounded JSON responses, and never accepts a database URL or private key over the network. Caller must validate actual hostname/cert chain (no `InsecureSkipVerify` outside test-only clients).

Server-side `pgauth` still requires **provisioned** administrator Ed25519 keys and a separately authenticated key-login challenge to issue its five-minute tokens. There is no password/SSO/UI sign-in route; only server-side verification of externally supplied token. The initial public key must be delivered to an authorized admin out-of-band, not submitted by arbitrary Internet agents. All admin actions are tied to organization and signing admin ID.

## Test acceptance

The PostgreSQL GitHub Actions job now tests `internal/pairapi`, serially with other destructive database test packages. The test fixture:
1. Provisions a trusted organization, site and owner signing key, authenticates using `pgauth`, and starts an `httptest.NewTLSServer` (trusted by its test client only).
2. Denies unauthorized key proposals and enrollment before approval.
3. Confirms tenant OWNER bearer **plus signed** decision and short-lived replay nonce are required.
4. Enrolls the original agent through native HTTPS client key proof, verifies identity through fresh challenge.
5. Reopens a new database connection and new TLS handler; the same native key recovers its identity.
6. Revokes the identity via a freshly signed admin decision and verifies subsequent resume fails.
7. Refuses plaintext and browser-origin attempts. Native client tests reject plaintext URLs and redirect downgrade.

## Critical release blockers

This is a **controlled integration slice**, not an Internet-ready service:
- There is no listener, gateway deployment, TLS certificate management, hardened per-IP/tenant rate limiter, monitored abuse defense, audited challenge throttling, DDoS resilience or an authenticated user-facing admin login.
- Admin public-key provisioning and signed approval occur outside this handler; human approval UX not integrated. An installed agent has no administrator bearer and cannot self-propose over the Internet.
- Tests do not involve actual Windows/macOS/Linux agent installations, an unlocked native user credential vault, a real remote machine, CGNAT, WAN relay, or device adapters.
- The local setup web page remains a **preview**. Its status GET is read-only. The preview's Connect step cannot claim paired/online because a status check succeeded. No scripts call the new admin endpoints from the browser.
- Even verified pairing returns `OFFLINE` / `NONE` capabilities. No printer command, attendance event, generic shell, proxy or port-forwarding is permitted.
- No automatic native key recovery, rotation or forced reset. A stolen/revoked old identity must be separately audited and revoked before re-pairing; a new native key needs fresh explicit administrator consent.

## Next

R2J.2: isolated installed-agent workflow and authenticated cloud control-plane deployment (tenant-aware rate limits, pinned/validated TLS, operator secret provisioning, trusted invite intake), then connect real agent status to local setup UI. Separately grant minimum device capabilities only after explicit policy review. Production deployment is forbidden until those gates pass.
