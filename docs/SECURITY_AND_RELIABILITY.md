# Security and reliability requirements

**Status:** Mandatory requirements for design review, not implemented controls.

## Assets and actors
User accounts, application API identities, enrollment invitations, agent private keys, device credentials, command data, logs, tenant/device registry. Actors: workspace admin, app integration, local agent, relay operator, malicious LAN participant, compromised account, stolen laptop.

## Threats and baseline mitigations
| Threat | Required control |
| --- | --- |
| Cross-tenant command execution | Tenant-scoped data model + server/edge authorization tests |
| Leaked pairing invite | Single-use, short TTL, workspace binding, replay prevention |
| Malicious device advertisement | Bounded discovery, explicit operator approval, protocol validation |
| SSRF / lateral movement | Adapter allowlists, subnet bounds, no generic TCP proxy |
| Intercepted/replayed commands | TLS, agent identity proof, command ID/expiry, replay journal |
| Credential loss/compromised agent | Secure local storage, rotation, immediate revoke, audit |
| Payload-based DoS | Limits on size/rate/time/queue; per-tenant quotas |
| Supply-chain compromise | Signed releases, reproducible build goal, dependency review |
| Unauthorized operations | Least-privilege capabilities and explicit grants |
| Sensitive logs | Redaction, retention boundaries, no tokens/private keys |

## Delivery contract
- Clearly distinguish command **accepted**, **received by agent**, **attempted on device**, and **outcome observed**.
- At-least-once **delivery may happen**, therefore edge enforces deduplication where possible.
- Exactly-once physical effects are impossible to guarantee without supporting device protocol.
- Retry only when operation class and latest journal state indicate safety.
- Make INDETERMINATE an explicit terminal or reconciled state with operator guidance.
- Cap queued work by bytes, count and age. Expires and cancels are durable.
- Define crash boundaries around journal write and physical IO before rollout.

## Required tests
Isolation, forged device/agent identities, replay, stale grants, expired invites, revoked reconnect, corrupt journal, power loss between send/ack, duplicate job submissions, flaky Wi-Fi, server restart, offline expiry, backpressure and malformed device payloads.

## Unknowns before release
OS secure key storage strategy, credential recovery process, installer signing keys, update compromise recovery, data residency, telemetry privacy, device-specific acknowledgements, independent security audit scope.
