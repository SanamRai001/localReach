# R2K.1 — discovery-read policy and passive LAN observation

## What this phase actually makes possible

**The native agent can listen for existing mDNS/DNS-SD printer announcements and show unverified candidates locally.** It does not send discovery queries, connect to their hostnames/IPs, scan ports, submit candidates to the cloud, print, access an attendance device, or open a generic tunnel.

```sh
# On the prospective device owner's own computer, explicitly choose a 1–30s observation:
go run ./cmd/localreach-agent discover -duration 5s
```

The command reports potential printer service names and their SHA-256 discovery hint (a deterministic hash of the advertised mDNS service name, target host and port), with `UNTRUSTED_MDNS` and `Verified=false`. This fingerprint **is not a hardware key, proof of device identity or an authenticated device claim**: another LAN participant can forge DNS-SD packets. It is useful as a provisional name for reviewing inventory, not a secure physical-device authorization target. The tool collects up to 20 records and keeps them on the local screen only. Passive discovery often returns **zero** results if no printer happens to announce itself during the listening period, if multicast is disabled or if another local mDNS process owns the socket. Zero is not proof of absence.

The parser only accepts well-formed, bounded mDNS *responses* with DNS-SD SRV services commonly advertised by printers (`_ipp`, `_ipps`, `_printer`, `_pdl-datastream`). It never resolves or connects to an advertised hostname. Arbitrary network hosts are not classified as printers. Attendance readers have no universal trustworthy mDNS service; **no attendance scanner or protocol implementation** is introduced in this phase.

## Separately signed discovery permission records

Migration `066_device_read_grants.sql` and `internal/pgcapability` define a **policy-only** capability ledger with exactly two enumerated permissions:

- `PRINTER_DISCOVERY_READ`
- `ATTENDANCE_DISCOVERY_READ`

These allow *only the future controlled interpretation of passive discovery metadata*, NOT printer status requests, attendance exports, data writes, device actions, raw TCP or shell access. The `ATTENDANCE_DISCOVERY_READ` policy exists in preparation for a future vendor-reviewed, opt-in scanner, **which is not implemented**.

Grant decisions are scoped to the exact **organization + site + enrolled agent + provisional device fingerprint + capability**. Each decision requires a live OWNER/ADMIN token, matching pre-provisioned signing administrator ID, an **independent** domain-separated Ed25519 signature covering every scope and a fresh 256-bit nonce. The PostgreSQL SERIALIZABLE transaction re-checks live organization status, issuer role, agent enrollment and site, consumes a unique hashed nonce, inserts or revokes the expiring policy row, and appends an audit row atomically. **A pairing approval signature cannot be replayed as a device policy signature.**

Every grant expires after **one hour**, can be explicitly revoked, and becomes ineffective immediately if its issuer, agent, organization or pairing is revoked/blocked. Policy evaluation re-checks these constraints and tenant/site/device/capability scope. A re-grant must receive a new signed, audited decision. A discovery policy is **not automatically attached to the long-lived connection**; that connection's frames remain `capabilities=NONE`.

## Operator-only administration

`POST /v1/control/device-read-decision` is accessible only to a trusted native administrative HTTP client with a valid OWNER/ADMIN bearer token and independent signed decision. It does **not** expose any agent-facing device command endpoint.

The `localreach-admin` CLI adds:

```sh
go run ./cmd/localreach-admin grant-read \
  -identity-dir /SEPARATE/OS_PROTECTED_ADMIN_IDENTITY \
  -gateway https://TRUSTED_OPERATOR_GATEWAY \
  -organization ORG -admin ADMIN_ID -site SITE \
  -agent ENROLLED_AGENT_ID \
  -device-fingerprint FULL_64_CHARACTER_DISCOVERY_HINT \
  -capability PRINTER_DISCOVERY_READ

# Exactly the same arguments, but replace 'grant-read' with 'revoke-read'
# to revoke the policy independently.
```

The operator must **retype the full fingerprint through standard input** before the new decision is signed. The CLI explicitly warns that mDNS fingerprints are unauthenticated hints. Keys remain in the existing separate native administrator OS vault. No browser gets an admin private key.

Even after a signed policy is ACTIVE, there is no device interface that uses it yet. Authorizing access to real printers or attendance devices will need a stronger, independently verified device binding; narrow protocol-specific read methods, least-privilege enforcement and additional tests before exposing any actual hardware traffic.

## Verification

- Go unit tests exercise deterministic printer candidate fingerprinting, malformed DNS packet/name rejection, spoofable SRV hints, zero-port and nonlocal-target rejection, unsupported attendance detection, and bounded duration.
- Real PostgreSQL tests verify no grant at pairing time, wrong-key denial, Ed25519 signature binding to tenant/site/agent/device/capability/action, nonce replay denial, expired grants, admin/agent revocation, site/tenant/device/capability isolation and signed grant/revoke audit.
- A native HTTPS integration test verifies that only an authenticated, correctly signing admin can create/revoke discovery policy and that wrong/replayed grants fail; responses explicitly say `deviceOperations=DISABLED`.
- CI includes `internal/pgcapability` in its serial disposable PostgreSQL job alongside existing pairing/auth/TLS, plus Linux race, Windows DPAPI and macOS Keychain suites.

**No physical device, external LAN, network scan, public production deployment or end-to-end printer/attendance operation has been performed.** No branches have been merged to main.

## Next

R2K.2: opt-in authenticated local network discovery with validated device identity and explicit user's consent, per-capability policy delivery to an authenticated agent, and scoped _read-only_ adapter contracts. Prefer printer IPP Get-Printer-Attributes or reviewed vendor APIs only after identity verification, rate-limits and permissions are in place. Then hardware acceptance for printers and attendance readers. Separately, R2J.6B real authorized two-network staging acceptance remains to be done before claiming WAN support.
