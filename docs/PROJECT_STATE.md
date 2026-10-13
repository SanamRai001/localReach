# LocalReach project state

**Date:** 2026-10-13
**Branch:** `feat/r2k1a-working-local-setup-dashboard`
**Phase:** R2K.1A — replace nonfunctional setup tour with real localhost dashboard.
**Base:** `feat/r2k1-device-discovery-read-grants` (PR #36). Previous PRs stacked and unmerged. No public deployment.

## Last verified foundation
R2K.1 final CI `38389796103` SUCCESS: Linux Go/vet/race, PostgreSQL device discovery-read grants and TLS acceptance, Windows DPAPI, macOS Keychain. Physical printer discovery and real WAN were not tested.

## Current implementation
- `cmd/localreach-setup` now hosts a real dashboard on `127.0.0.1:18788` rather than a three-button loop. It optionally takes `-gateway https://TRUSTED_URL -organization ORG` at startup; without those flags, identity creation and passive local discovery still work and cloud pairing is clearly unavailable.
- `internal/localdashboard.Service`: reads existing OS-protected identity without auto-regeneration; explicit `Create identity`; real invitation submission and PENDING_APPROVAL tracking; separately approved enrollment and existing-key reconnect; after verification starts authenticated `agentservice.LiveMonitor`. ONLINE only after actual authenticated stream frames. No arbitrary LAN or printer commands.
- `internal/localdashboard.Handler`: fixed Host, direct loopback peer, strict same-origin POST, no cookie, per-process cryptographically random 256-bit CSRF token, custom header, JSON body limits, unknown-field rejection, one active operation. Status and bootstrap are GET-only. No CORS, remote routes, browser private keys, or browser-specified gateway URLs.
- `web/setup/index.html`, `setup.js`, `style.css`: responsive dashboard with truthful OS identity, cloud session, passive Find Devices, pairing request/approval/finish/reconnect, specific errors and status refresh. No simulation tour.
- `landiscovery.Listen` invoked only when the user clicks Find Devices, bounded to 8 seconds, max 20 local untrusted mDNS printer announcements; no packets sent, no device commands or upload.
- Security and state-flow unit tests with mocked native signer, remote backend and passive discovery. `docs/R2K1A_WORKING_SETUP_DASHBOARD.md` contains runnable commands and clear limitations.

## Verification
New phase source pushed; **GitHub CI not yet verified**. Must pass unit/vet/race, PostgreSQL integration, Windows DPAPI, macOS Keychain, and browser JS syntax. Actual user Windows installation/UI click test remains to be performed; no live cloud gateway configured.

## Critical product limits
Default dashboard runs locally without Postgres/cloud, but **cloud connection is disabled** until the operator deploys a trusted HTTPS service and independently provisions/approves a tenant and agent. No signed installer, automatic OS background service, public gateway, real two-network acceptance, hardware attestation, verified printer integration, attendance reader, printer command, raw TCP or generic tunnel. Browser labels all mDNS discovery fingerprints untrusted. All stacked PRs remain unmerged, no deployment.

## Next
Pass new CI. Provide Windows PowerShell pull/checkout/run instructions with no repeat cloning. Then R2K.1B improve real device discovery/verified read-only printer identification and operator pairing UX, followed by authorized staging/hardware pilot.
