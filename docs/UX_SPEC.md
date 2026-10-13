# UX specification: install once, click Connect

**Status:** Proposal; validate with operators before building.

## Product language
Say **Connect this computer**, **Find devices**, **Use device**, **Reconnect**, **Check device**. Avoid *NAT*, *reverse proxy*, *WebSocket*, *relay* and *VPN* in standard operator screens. Technical diagnostics are in Advanced.

## Golden path
1. An authenticated workspace owner selects **Connect this computer**.
2. Website offers one OS-appropriate signed installer (no terminal); installer prompts for standard OS permissions.
3. Install and pairing invitation complete securely. If browser/installer handoff fails, show a short explicit recovery step.
4. Show **Finding devices** with ability to skip or retry; discovery operates only on permitted local networks.
5. Show recognized supported devices, their type and physical hints; operator selects devices and approves exactly which capabilities to expose.
6. Verify handshake and a harmless test action where supported. Show **Ready** only after verification, not just socket connection.
7. Existing applications can invoke approved operations. Returning user lands directly on device overview.

## States the UI must distinguish
- **Connector not installed** -> Download connector.
- **Permission required** -> Open OS/local-network instructions.
- **Pairing expired or wrong workspace** -> Restart pairing.
- **Computer offline** -> Check power/network; reconnect automatically when possible.
- **Device not found** -> Refresh discovery; advanced manual address only where adapter supports it.
- **Detected but unsupported** -> Explain model/protocol; request adapter support.
- **Device offline** -> Check physical LAN/power.
- **Ready** -> Capability-specific healthy checks passed.
- **Job queued** -> Await delivery; show expiry.
- **Job indeterminate** -> Explain it may already have run; do not present Retry as safe by default.
- **Access denied** -> Contact workspace admin / request approved operation.

## Progressive disclosure
Main page: connector status, discovered devices, the single most likely next action. Device detail: capability list, test, online status. Advanced: IP, ports, protocol, log export, pairing diagnostics, adapter version. Never require advanced configuration for supported happy-path devices.

## Accessibility and safety
Accessible controls, keyboard use, screen-reader states, clear errors, reduced-motion support, contrast-compliant indicators and non-color-only state. Never execute a device operation by auto-detection alone. Prevent duplicate submits; show execution phase and last known timestamp. Confirm impactful/destructive actions separately.

## Example journeys
**Restaurant:** install connector on a computer in the same LAN as ESC/POS printer -> discover -> approve print capability -> test print -> send KOT from cloud. Clarify that print acknowledgement varies by printer.

**Attendance:** install at the office -> discover supported terminal -> approve read-records -> test safe read -> sync attendance to AMS over authenticated channel. Do not imply support for every proprietary model.

## Instrumentation / experiments
Measure first-run completion, device recognition accuracy, number of manual interventions, average setup time, failed setup reasons, recoveries, accessibility review findings and comprehension of offline/indeterminate command states. Run usability tests with non-developer operators.
