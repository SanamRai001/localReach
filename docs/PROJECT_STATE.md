# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, and authorize strictly scoped LAN device capabilities.
**Active branch:** `feat/r2i1-windows-dpapi-agent-identity`
**Phase:** R2I.1 — Windows current-user DPAPI identity persistence and recovery.
**Base:** `feat/r2h3-postgres-transactional-pairing` (PR #25). All upstream PRs #1–#25 remain open and stacked, no main merge/deploy.

## Verified baseline
R2H.3 latest GitHub Actions run `38360284081` was green: Go test/vet/race and separate-process HTTPS mock smoke, plus transactional PostgreSQL pairing and scoped Ed25519 administrator login/session verification. No real WAN/hardware tests.

## This phase
- `internal/agentkeys` introduces explicit `Create` / `Load` of a per-user Ed25519 signing identity.
- On Windows, secret bytes are encrypted with current-user scoped DPAPI and saved as a versioned, bounded encrypted payload in a local-profile `identity.dpapi` file. No plaintext file fallback, no machine-wide DPAPI scope.
- On unsupported platforms, key creation/decryption fails closed. Linux and macOS native secure key stores are not yet implemented.
- Identity is never returned as JSON or served to a browser; the trusted Go backend can access its public key, fingerprint and restricted native signing function. No automatic key regeneration after loss/corruption, nor automatic overwrites.
- Added Windows runtime tests of DPAPI roundtrip, encryption tampering, restarts, identity stability, concurrent create refusal and corruption recovery. Existing Linux test rejects plaintext fallback.
- Added a real `windows-latest` CI job for Windows DPAPI tests, Windows build and broader package tests.
- `docs/R2I1_WINDOWS_DPAPI.md` details Windows user scope, ACL caveats, recovery limitations and next milestones.

## Verification
R2I.1 new code committed; **R2I CI results not confirmed** at this state entry. Need green Windows CI as well as Linux Go and PostgreSQL CI before claiming native key persistence validated.

## Remaining production gaps
- No installed Windows background agent, actual pairing to the PostgreSQL backend, OS-safe user/key lifecycle or diagnostic UI.
- Windows DPAPI under interactive user is not a machine-service-wide credential store. Windows service account selection, ACL/symlink hardening, signing-key revocation and rotation require design and tests.
- Linux Keyring and macOS Keychain support remain unimplemented and cannot use a plaintext fallback.
- User-supplied protocol messages must be domain-separated before signing; no unrestricted signer RPC or browser access.
- No real login/SSO integration, public-safe gateway, WAN/CGNAT verification, capability grants, printers, attendance device adapters, installers or hardware testing.

## Next
Verify Windows CI and fix any findings. Then R2I.2 native macOS/Linux secure credential backends, and R2I.3 agent enrollment/restore/rotation integration. Keep public listeners and hardware commands disabled.
