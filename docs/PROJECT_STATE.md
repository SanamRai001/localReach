# Project state

**Date:** 2026-10-13
**Goal:** Install once, click Connect, securely approve LAN-only device capabilities.
**Current branch:** `feat/r2b-setup-experience`
**Phase:** R2B browser setup UX preview authored.
**Base:** `feat/r2a-one-command-local-lab` (PR #16), stacked on PRs #1–#15, all unmerged. No deployment.

## Verified
R1L Go test, vet, race and lab compilation CI runs succeeded. R2A two-process loopback HTTPS mock smoke test CI run `38351933557` concluded SUCCESS. This does not validate public WAN/CGNAT or real hardware.

## This phase
- Static responsive onboarding preview in `web/setup/index.html`, `style.css`, `setup.js`.
- Three-stage Install → Connect → Devices layout, accessible button labels and explicit simulated statuses.
- No real enrollment, installation, scanning, networking or device connection performed in the UI.
- Documented real-state contracts and missing security prerequisites in `docs/R2B_SETUP_PREVIEW.md`.

## Limitations
No signed installer, native agent service, real app pairing, secure OS key storage, approval grants, real device discovery, tenant admin policy or production public endpoint. The workflow is explicitly only a UI prototype. The tested transport remains local mock-only.
No browser UX/a11y tests executed for R2B.

## Next
Build a safe local agent status API and controlled pairing contract, then integrate the page with real states. Require explicit tenant-admin authorization and locally protected signing key for pairing. Do not display simulated success as an actual connection. Keep network exposure and hardware disabled pending security acceptance.
