# R2J.2 — Manually runnable native agent with verified local status

## Implemented: diagnostics, not an installed service

New `cmd/localreach-agent` supports three **explicit** CLI commands using existing native OS credential storage:

```sh
# 1. Generate this user's private signing identity ONLY by explicit action
go run ./cmd/localreach-agent init

# Give the printed PUBLIC key to a trusted organization administrator.
# Administrator proposal + approval must take place separately.
# These operations are NOT offered by a public website or agent CLI yet.

# 2. Complete an ALREADY approved pairing over a TLS-trusted control plane
go run ./cmd/localreach-agent enroll -organization YOUR_ORG -gateway https://YOUR_TRUSTED_GATEWAY -request APPROVED_REQUEST_ID

# 3. Run read-only localhost diagnostics and periodic HTTPS identity proofs
go run ./cmd/localreach-agent serve -organization YOUR_ORG -gateway https://YOUR_TRUSTED_GATEWAY -web web/setup
# Open http://127.0.0.1:18788
```

These are **workflow examples**, not currently usable with a hosted production gateway: the previous `pairapi.Handler` is intentionally NOT publicly deployed and has no production server/listener or administrator portal. All commands require the correct working directory for the static `-web` assets. There is no signed installer or OS-autostart service.

The native agent refuses to continue when the existing OS credential is missing/damaged. The only key-creating operation is `init`, which never overwrites an existing identity and only outputs the *public* key and fingerprint. Linux needs an unlocked Secret Service user session; macOS uses an accessible Keychain; Windows uses current-user DPAPI. No plaintext fallback exists. `enroll`/ `serve` load the existing key, use the native HTTPS client with validated system certificates (TLS 1.2+), fail closed for non-HTTPS URLs, and never receive database passwords or device command capabilities.

## Status semantics

`internal/agentservice.Monitor` calls the R2J.1 HTTPS native `VerifyIdentity` proof immediately and once per minute (configurable with a 10-second minimum). The verified identity has a freshness period capped at **90 seconds**. A successful proof reports:

- `agent=RUNNING`
- `pairing=PAIRED`
- `verification=VERIFIED_RECENTLY`
- `lastVerifiedAt=<UTC RFC3339>`
- `connection=OFFLINE`
- `devices=NOT_DISCOVERED`

**PAIRING/VERIFIED_RECENTLY means the backend successfully verified the same Ed25519 identity at the recorded time. It is not an established cloud command session, live relay socket, hardware permission, or real-time revocation subscription.** On any failed proof (including internet outage, server rejection, or revocation) the local UI conservatively falls back to `pairing=UNVERIFIED` and `verification=FAILED`. If a previously successful proof becomes older than 90 seconds without a refresh, the GET view becomes `verification=STALE` / `pairing=UNVERIFIED`. Shutdown marks `agent=STOPPED`. A failed proof does **not** claim `REVOKED` because connection failures cannot prove revocation.

The static setup page still has **no state-changing browser endpoints**. The native agent serves it from `127.0.0.1:18788` only, using the existing strict Host / peer loopback / Origin controls and read-only GET handler. The page explicitly distinguishes a recently verified identity from a continuous ONLINE connection and tells the user that no devices are available. A local process reading localhost status is not trusted as a device administrator.

## Tests and safety

- Monitor tests prove initially unverified / freshly verified / stale / failed states, immutable loopback status, and cancellation.
- CLI tests reject missing/invalid commands and absent native keys without generating replacements; TLS config has certificate validation enabled and a minimum TLS version.
- Existing R2J.1 PostgreSQL/TLS pairing end-to-end tests, Windows DPAPI native storage, macOS Keychain compilation and Linux fail-closed Secret Service tests remain in all-platform CI.
- **No actual Windows service, macOS LaunchAgent, Linux systemd unit, reliable WAN relay, command authorization, printer access, attendance device operation or installed-client UI exists.**

## Next

R2J.3: operator-managed authenticated gateway with trusted administrator invitation workflow, durable device status and abuse throttling, plus separately authorized device capability grants. R2K follows with LAN discovery. Before production, add signed installers and native service identity policies (user vs system services), TLS certificate configuration, safe key reset, revocation fanout, CI against real user-vault access, actual WAN/CGNAT acceptance, and an approved hardware pilot.
