# Project state

**Date:** 2026-10-13
**Goal:** Install once, connect over outbound TLS and authorize narrowly scoped local devices without router changes.
**Current branch:** `feat/r2j1-https-pairing-control-plane`
**Phase:** R2J.1 HTTPS-native pairing transport and truthful local setup preview.
**Base:** `feat/r2i3-agent-identity-binding` (PR #28). All prior PRs remain open and stacked. No main merge/deploy.

## Verified baseline
R2I.3 latest CI `38367445700` SUCCESS: PostgreSQL pairing, native signer lifecycle and recovery, Windows DPAPI, Linux Go/vet/race/mocked TLS, macOS Keychain CGo and fallback. No real native installed agent or public WAN testing.

## Authored R2J.1
- `internal/pairapi.Handler`: isolated HTTPS-only JSON API, no public listener. Native administrator proposal/approval/revocation requires short-lived scoped `pgauth` OWNER/ADMIN bearer; signed decisions must match the actor and are transactionally validated by PostgreSQL. Enrollment and resume require fresh, bounded one-use Ed25519 proofs; identity verification does not grant device access.
- `internal/agentremote.Client`: native signer uses caller-authenticated HTTPS only, disallows redirects and insecure/credential-bearing URL forms. No database credentials in agent, no arbitrary signing endpoint in browser.
- New test-backed controlled TLS flow exercises authenticated administrator key-login, protected proposal, signed approval, agent enrollment, restart proof with fresh backend, and revocation denial. No public or Internet-facing process.
- `web/setup/setup.js`: removes fake `Your computer is connected` state, labels previews consistently and prevents stale asynchronous status responses from modifying the wrong screen.
- PostgreSQL CI includes `internal/pairapi`; native client has redirect/plaintext denial tests.
- `docs/R2J1_HTTPS_PAIRING.md` details protocol, test acceptance and safety gaps.

## Verification
**R2J.1 CI verified green**: GitHub Actions run `38369546185` concluded SUCCESS for all four jobs: Linux Go unit/vet/race plus separate-process HTTPS smoke, disposable PostgreSQL admin/auth/HTTPS-native pairing integration, Windows DPAPI/full packages, and macOS native Keychain/full packages/disabled-CGo. An earlier run failed from handler method-check ordering (GET returned 503 instead of 405), corrected in commit `daf4aa0647adf0774cf235b01b1179ef1a98d278`. A subsequent documentation-only commit triggers its own CI verification.

## Not production ready
No public HTTPS pairing listener, real administrator login/SSO and user consent UI, production rate limiting and trust-onboarding, signed installer, OS service, actual WAN/CGNAT relay, live agent online status, optional Keychain/Secret Service live acceptance, explicit device capabilities, printer or attendance driver, public deployment or hardware testing.
Even successful signed identity verification returns `OFFLINE` and `NONE` capabilities. Local preview remains status-only; it never performs real pairing. All PRs remain unmerged pending explicit approval.

## Next
R2J.2 secure installed agent and operator-managed pairing API with authenticated invite intake, production rate limiting, revocation fanout and real local status. Then R2K explicit capability grants, device discovery and hardware acceptance.
