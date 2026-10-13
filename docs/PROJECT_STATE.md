# Project state

**Date:** 2026-10-13
**Goal:** Simple outbound-only setup for narrowly authorized LAN devices, without device-side router changes.
**Branch:** `feat/r2j4b-restricted-staging-gateway`
**Phase:** R2J.4B — explicit operator-controlled source-allowlisted HTTPS staging ingress.
**Base:** `feat/r2j4-admin-approval-distributed-admission` (PR #32). PRs #1–#32 remain open and stacked, no main merge/deploy.

## Verified foundation

R2J.4A final CI run `38379094549` succeeded in all four Linux unit/vet/race/mock TLS, PostgreSQL authorization/shared admission, Windows DPAPI, and macOS Keychain jobs. The operator native administrator key remains separate, with invitation issuance, fingerprint review, independently signed approval and PostgreSQL-backed per-route admission.

## R2J.4B implemented

- `internal/staginggate`: an explicitly enabled direct-TLS ingress guard for a **restricted cross-network staging pilot**, accepting only configured IP listener/DNS name and narrow source CIDRs (max 16, IPv4 /24 or narrower, IPv6 /64 or narrower).
- Rejects blocked direct peers at the socket accept stage before TLS handshake, and again per HTTP request; ignores untrusted `X-Forwarded-For`.
- Validates leaf certificate SAN, valid date and server-auth purpose against DNS identity before binding, and enforces TLS 1.3 minimum, exact SNI/Host and max 16 concurrent application requests.
- `cmd/localreach-control` defaults to localhost, but can accept `-enable-restricted-staging` with explicit staging listener, hostname and CIDRs. It rejects missing/unsafe input and rejects the disposable plaintext PostgreSQL option in staging mode. TLS and PostgreSQL verification remain required.
- Tests cover unsafe ranges/config, spoofing, TLS/SNI/Host, certificate mismatch/expiry, concurrency exhaustion and allowed socket peers, plus CLI fail-closed stage flags.
- `docs/R2J4B_RESTRICTED_STAGING.md` documents operator prerequisites, warnings, test plan and why network availability does not mean a cloud command session.

## Verification

R2J.4B code authored, **GitHub CI result not yet confirmed**. Linux Go/race/ctl build, PostgreSQL integration, Windows/macOS native packages and TLS gate tests must pass before accepting the phase. No physical WAN staging session or actual deployment executed.

## Explicit limitations

Source-allowlisted staging is **not** a publicly hardened Internet production deployment. DNS, TLS certificate installation, static ingress peer IP, firewall, host lifecycle, secure environment secrets, SSO/provisioning, monitoring, IP/certificate rotation, retention, rollback and real WAN pilot remain operator tasks. No persistent cloud session or truthful ONLINE signal, signed end-user installers, capability grants, discovery or printer/attendance actions. Identity verification remains `connection=OFFLINE`, `capabilities=NONE`.

## Next

CI and security findings first. Then R2J.4C real authorized two-network acceptance, R2J.5 authenticated outbound long-lived session and revocation, and R2K narrow separately authorized device capabilities. No merges or public deployments unless explicitly approved.
