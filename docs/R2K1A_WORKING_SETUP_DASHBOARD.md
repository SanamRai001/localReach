# Working localhost setup dashboard — R2K.1A

## What changed

`go run ./cmd/localreach-setup` now hosts a **functional single-page dashboard** on `http://127.0.0.1:18788`. The previous three-step looping tour and fake connection button have been removed.

The dashboard has three separately truthful surfaces:

1. **This Computer** — shows whether this Windows/macOS/Linux user's OS-protected Ed25519 identity already exists, has been corrupted/unavailable, or needs explicit creation. `Create identity` is a real user-initiated operation using the existing `agentkeys.Store.Create`. It never replaces an existing identity, stores no private keys in browser JS, and never automatically pairs.
2. **Find Devices** — a real click starts a bounded **8-second passive UDP 5353 mDNS observation**. The existing strict DNS-SD parser displays potential printer advertisements with an `UNTRUSTED_MDNS` marker. It does not send discovery probes, open printer connections, reveal local IPs to a server, or upload results. On Windows, UDP multicast port permissions, firewall behavior and already-running mDNS listeners may produce zero results or an error; the dashboard reports this accurately. Zero candidates is not proof no printers exist.
3. **Connect to your organization** — when a trusted HTTPS gateway/organization are **explicitly configured at launch**, a user can paste a one-use invitation, create a `PENDING_APPROVAL` request, then after a distinct signed administrator approval click `Finish approved pairing`. Existing enrolled identities can click Reconnect. A server-verified enrollment starts the real outbound `agentservice.LiveMonitor` with fresh signed challenge/stream heartbeats. The cloud status becomes ONLINE **only** after authenticated stream frames arrive. Offline, no gateway, expired invitation, missing identity, unsuccessful approval and OS-vault failures are surfaced as errors; no page-only action is presented as a successful cloud connection.

### Run locally (Windows PowerShell)

```powershell
cd C:\Users\DELL\localReach
git switch feat/r2k1a-working-local-setup-dashboard
git pull --ff-only
go run ./cmd/localreach-setup
```

Open `http://127.0.0.1:18788` and select **Find devices**. Go must already be installed, and any prior LocalReach process bound to port 18788 must be stopped with Ctrl+C. The default standalone dashboard requires **no PostgreSQL**, no agent signing key, and no cloud service just to view local status and use discovery.

Optional real organization pairing (only when a separately **operator-authorized and deployed** control plane exists):

```powershell
go run ./cmd/localreach-setup -gateway https://TRUSTED_GATEWAY -organization ORG_ID
```

Both startup flags must be present. Gateway URLs must be HTTPS with ordinary, valid TLS certificate trust; the backend fixes them at launch so the browser cannot direct the agent to arbitrary hosts. Do **not** disable certificate checking to make a staging server work. The admin independently provisions the organization, creates the invitation, reviews the proposed key fingerprint and approves using signed native administrator tooling. There is **no public LocalReach cloud gateway currently deployed**, so cloud pairing is correctly disabled for ordinary local users.

## Local browser security

All localhost APIs enforce the fixed `127.0.0.1:18788` Host and directly connected loopback peer. The static page and GET status use a strict same-origin CSP with no remote scripts or fonts.

State changes require `POST`, `Content-Type: application/json`, a strict same-origin `Origin` header, no cookies, a random process-local 256-bit CSRF token obtained by a same-origin GET bootstrap and returned in a custom header, an at-most-1KB body with unknown JSON fields rejected, and an explicit click. Missing/wrong Origin, wrong Host, remote peers and missing/wrong CSRF token fail before any operation. There is no CORS wildcard or unauthenticated remote listener. Long-running discovery has a per-operation duration limit and a one-operation-at-a-time guard; key generation and remote pairing are never triggered by a GET/status poll.

Browser JavaScript never obtains the agent signing key, system credential-store reference or a cloud database password. The one-use invitation is submitted over localhost once, used immediately over authenticated HTTPS and cleared from the input. No browser session persists keys or invitation codes. The private signing process operates only within Go.

The local dashboard service does not expose generic device operations, port forwarding, shell, raw TCP, attendance readers or printer writes. Existing R2K.1 discovery-read grants remain independent from an agent pairing; **no grant is silently applied by finding a device**.

## Tests and verification scope

`internal/localdashboard` unit tests verify mandatory loopback+Origin+CSRF checks, same-origin bootstrap, no unauthorized discovery, bounded real backend invocation and untrusted results, no fake cloud configuration, pending request isolation, explicit post-approval enrollment and ONLINE only after a real stream callback; status becomes OFFLINE when it stops. Cross-platform Go and full PostgreSQL/TLS suites remain CI gates.

**This phase does not install an OS background service, ship a signed installer, deploy a cloud gateway, complete a two-network WAN pilot, securely attest mDNS device identities, or allow physical-device commands.** The standalone dashboard is a real local setup surface, not a promise of working remote access before the cloud exists.

## Next

R2K.1B can improve local discovery usability (bounded service query and vetted read-only printer verification, after user consent) and a trusted administrator acceptance UI. Then implement a signed installer and deploy the actual authorized staging gateway for a two-network pilot before calling LocalReach ready for nontechnical users.
