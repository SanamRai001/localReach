# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, authorize scoped LAN-only device access.
**Current branch:** `feat/r2i2-macos-linux-secret-stores`
**Phase:** R2I.2 native OS agent key storage foundation for Linux and macOS.
**Base:** `feat/r2i1-windows-dpapi-agent-identity` (PR #26). All previous PRs #1–#26 remain open and stacked. No merge/deploy.

## Previously verified
R2I.1 latest CI `38363952211` succeeded for Windows DPAPI tests, Linux Go/vet/race and local TLS smoke, and PostgreSQL pairing/admin sessions. Does not verify WAN/hardware or installed service.

## R2I.2 changes
- Refactored `internal/agentkeys` into common native identity/signing API and platform-specific persistence while preserving existing Windows current-user DPAPI.
- Added Linux libsecret Secret Service provider via `/usr/bin/secret-tool` with secrets only on stdin/stdout; no plaintext filesystem or argv fallback, unsupported if desktop session service is absent.
- Added macOS Security.framework Keychain generic-password credential provider via CGo; duplicate item denied and no plaintext CLI arguments. CGo-disabled macOS fails closed.
- Linux/macOS persist only a small public reference marker (random ID, fingerprint, timestamp). A native secret is required for any key load. Creation uses exclusive marker creation; lost/corrupt secrets require explicit recovery.
- Added mock-vault lifecycle tests for key stability, signing, concurrent enrollment, marker tampering, missing native secret and disabled backend; optional interactive real provider roundtrip.
- Added macOS GitHub Actions compilation/testing and disabled-CGo check alongside existing Linux, Windows and PostgreSQL jobs.
- `docs/R2I2_NATIVE_KEY_STORES.md` records platform support and limitations.

## Verification
R2I.2 code pushed. **New CI results not yet verified**. Mock-vault tests do not establish successful real Keychain / Secret Service operations in an installed app.

## Release blockers
No real agent process/enrollment wireup, OS service-account policy, production code signing, key rotation/recovery UI, protected keychain permissions audit, headless Linux secret-store availability, user login/SSO or authorized device grants. No WAN/CGNAT/public relay, printer/attendance integration or signed installers.

## Next
Verify CI, fix platform findings, then R2I.3 agent enrollment/lifecycle/recovery and R2J real pairing UX. Keep PRs unmerged until explicit approval.
