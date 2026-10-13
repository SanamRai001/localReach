# R2B — LocalReach onboarding experience preview

A static, accessible, responsive setup walkthrough in `web/setup`, styled with LocalReach's provisional deep-navy and teal design language.

The three user-oriented stages are Install, Connect, Devices. All transitions are **simulated** and explicitly labeled as such in the interface. This design preview does not install an agent, pair a real identity, submit commands, connect to a gateway or discover any physical devices.

Open `web/setup/index.html` in a browser to inspect the design. No build or network access is required.

Future implementation requires a real signed installer, user-authorized enrollment, secure local agent key storage, compatible discovery adapters, approval controls and visible diagnostics. Keep the UI genuinely simple without hiding security consent.

## Integration contracts to build later
- Installer status: NOT_INSTALLED, INSTALLING, RUNNING, NEEDS_PERMISSION, ERROR
- Pairing state: NOT_PAIRED, PENDING_APPROVAL, PAIRED, REVOKED, EXPIRED
- Connection state: CONNECTING, ONLINE, OFFLINE, RECONNECTING, BLOCKED
- Device state: FOUND, UNSUPPORTED, NEEDS_APPROVAL, READY, DISCONNECTED
- Capability grants must be independently authorized and audited, never implied by discovery.

The mock preview must never be presented as real connection status.
