# Product vision and scope

## Problem
Legacy LAN-only printers, attendance terminals and IoT devices are difficult to integrate with cloud applications. Developers repeatedly build local bridges, tunnels and polling services. Operators face IP addresses, VPNs, firewall settings and unclear errors.

## Promise
**Install once. Click Connect. Your devices are ready.**

LocalReach is a self-hostable, open-source, capability-first edge gateway. An authorized app calls a well-defined device operation instead of connecting to an arbitrary private IP address.

This is a product goal, not a claim that all hardware can be accessed with one click. When a device cannot originate a connection, a local service or gateway is required.

## Primary users
- Restaurant operator connecting a kitchen/receipt printer.
- Office administrator connecting an existing attendance terminal.
- Application developer integrating supported hardware through an SDK.
- Self-hosting administrator maintaining agents and server.

## User jobs
1. Install one trusted local agent and pair it to the correct workspace.
2. Discover supported devices with bounded, permission-aware discovery.
3. Approve individual devices and permitted operations.
4. Use capabilities from a remote application.
5. Understand and recover from offline, firewall, permission or protocol errors.

## Principles
1. UX first: operator-facing UI shows devices and tasks, not tunnels.
2. Default deny: no generalized LAN access or shell execution.
3. Keep local workflows working through internet failure where feasible.
4. Treat discovery, connectivity, compatibility and action success as different states.
5. Reliable command lifecycle with explicit uncertainty; never advertise exactly-once hardware effects.
6. Open protocols and interchangeable adapters; cloud and edge can be self-hosted.
7. Modular monolith initially; measurable evidence before scaling complexity.

## Initial in-scope
- Windows service agent with signed installer (distribution milestone; security review required).
- Single-site agent enrollment, identity, health, reconnect and revocation.
- Agent-driven mock device adapter, then ESC/POS printer, then one specifically supported attendance model.
- Narrow remote capability execution with job status and audit trail.
- Multi-tenant boundaries in cloud API; minimal browser console and TS SDK.
- Local bounded persistence and recovery behavior.

## Explicit non-goals for first release
- General-purpose VPN, desktop remote control or exposing arbitrary TCP sockets.
- Universal hardware discovery or support for proprietary devices without adapters.
- Cloud-only access to unplugged devices.
- Advanced P2P / custom NAT traversal engine.
- Remote shell, firmware flashing, destructive device admin operations.
- Mobile agents, Kubernetes, Kafka and geographically distributed control planes.
- Claims of zero steps or guaranteed automatic installation without OS approval.

## Success measures to validate
- New operator completes enrollment and supported-device pairing without CLI, port forwarding or manually entering IP.
- Remote mock capability succeeds across different networks including CGNAT scenarios.
- Unauthorized tenant and unauthorized operation are denied.
- Restart/reconnect does not require pairing again.
- User can tell apart agent offline, device offline, unsupported, command timeout and indeterminate outcome.
- Record task-completion rates, time-to-first-operation, reconnection rate, retry duplication and support interventions.

## Open questions
What initial hosting model is sustainable? Which exact AMS device family is available for tests? Does the chosen ESC/POS hardware acknowledge printing? What is the secure installer auto-update and signature distribution model? What discovery methods can be enabled safely per adapter?
