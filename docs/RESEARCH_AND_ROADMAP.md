# Research references and phased roadmap

**Status:** Research plan, not evidence of LocalReach implementation. License and dependency suitability are not yet verified.

## Architecture inspirations
| Project | What to study | What not to copy blindly |
| --- | --- | --- |
| [Tailscale control/data planes](https://tailscale.com/docs/concepts/control-data-planes) and [NAT traversal](https://tailscale.com/blog/how-nat-traversal-works) | Identity, coordination, DERP fallbacks, failure behavior | Building a whole VPN when only typed capabilities are needed |
| [Cloudflare Tunnel routing](https://developers.cloudflare.com/tunnel/concepts/routing/) | Outbound origin connectivity and connector redundancy | Publicly exposing arbitrary private endpoints |
| [OpenZiti policies](https://openziti.io/docs/learn/core-concepts/security/authorization/policies/creating-service-policies/) and [source](https://github.com/openziti/ziti) | Service-scoped identity and grants | Full platform complexity without a demonstrated requirement |
| [ThingsBoard gateway](https://thingsboard.io/docs/iot-gateway/what-is-thingsboard-iot-gateway/) and [connectors](https://thingsboard.io/docs/iot-gateway/connectors/) | Hardware protocol adapters, telemetry and device lifecycle | Universal device compatibility assumptions |
| [Headscale](https://github.com/juanfont/headscale) / [zrok](https://github.com/openziti/zrok) | Self-hosting and access coordination | Unreviewed licensing, dependencies or operational complexity |

Before reusing libraries/code, inspect exact component licenses, trademarks, release cadence, threat models and dependency trees. Conceptual architectural influence is distinct from copying code.

## R0 — Documentation and validation (now)
Complete problem definition, UX flow, proposed architecture, security baseline, research sources, acceptance gates. Interview 2–3 nontechnical operators and identify exact initial hardware.

## R1 — Network and identity prototype
Mock local device, minimal Go agent, authenticated outbound session, control API, secure pairing, command lifecycle. Prove across two different networks including a CGNAT environment; deny other tenants.

## R2 — Installer and discovery usability
Windows signed installer strategy and browser handoff; bounded device discovery; mock onboarding; clear error/recovery states and accessibility checks. Signatures and trusted distribution required before public release.

## R3 — Device adapters
Implement one ESC/POS model and one identified attendance device protocol. Verify physical capabilities and acknowledgement semantics rather than claiming general compatibility.

## R4 — Hardening
Durable journal, crash replay matrix, revocation, key rotation, backlog bounds, offline behavior, authz fuzz tests, load testing and observability. Security review before production use.

## R5 — Open-source beta
Versioned TypeScript SDK and adapter contract, self-host deploy, contributor guide, dependency/license audit, reproducible release pipeline, migration/backward-compatibility policy.

## First proof acceptance criteria
1. Install + pair from GUI, no CLI, no router rules.
2. Secure outbound connection on different networks and under CGNAT.
3. User approves a discovered supported device and a capability.
4. Remote SDK command succeeds on a mock adapter.
5. Revoke, cross-tenant deny, offline/expired and duplicate-delivery tests pass.
6. Automatic reconnect after agent and gateway restart.
7. Clear UI for unknown device and indeterminate operation.
8. Record reproducible logs, environment, hardware and failures.

## Stop/go
Do not move to real hardware until identity, tenant isolation and retry semantics pass. Do not call the platform production-ready until signed distribution, patching, monitoring, recovery and security review are complete.
