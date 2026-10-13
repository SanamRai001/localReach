# R2I.1 — Windows DPAPI agent identity foundation

## Purpose

The LocalReach desktop agent needs its own Ed25519 signing identity. Its private key must persist across restarts **without appearing in plaintext on disk or being sent to the browser**. This phase implements a **Windows-only native storage primitive**, not an installer or background agent service.

## Windows implementation

- `internal/agentkeys.Store.Create` explicitly generates an Ed25519 keypair and encrypts a versioned identity payload using the Microsoft Windows Data Protection API (`CryptProtectData`) in the **current user** context.
- The encrypted payload is written once to `%LOCALAPPDATA%\\LocalReach\\Agent\\identity.dpapi` by default, using `O_EXCL`, private file permissions where supported, a bounded format, and an fsync.
- `Load` checks the directory and file type, size and strict JSON envelope, decrypts with `CryptUnprotectData` under the same Windows user, and validates the private-key length and date. It never silently creates a new identity if missing/corrupt or DPAPI fails.
- `Identity.PublicKey()` returns only the public key, `Fingerprint()` its SHA-256 fingerprint, and `SignMessage()` signs a caller-supplied protocol message from the native backend process. There is no JSON serialization of the Identity, public signer endpoint, API route, or device permission grant.
- Windows uses the DPAPI user scope. **CRYPTPROTECT_LOCAL_MACHINE is not used.** Non-Windows builds return `ErrUnsupported` instead of falling back to plaintext, environment-variable keys, or an unencrypted JSON file.
- Creation is intentional and non-destructive: `Create` refuses an existing identity; `Load` recovers only a previously created identity. Interrupted writes remain visibly damaged and require controlled repair, not automatic replacement.

## Verification

GitHub Actions adds a real `windows-latest` job:
- DPAPI roundtrip and tampered-ciphertext rejection;
- persistence across `Create`/`Load`, stable fingerprints and valid Ed25519 signatures;
- duplicate-creator concurrency and no-override policy;
- fail-closed handling of corrupted files and ability to load the original when restored;
- Windows full Go package tests.

Linux CI validates that unsupported operating systems cannot silently create an unencrypted agent identity. Existing Go and PostgreSQL verification remain mandatory. No Windows CI run has yet been confirmed at the time of authoring.

Microsoft's DPAPI defaults usually restrict decryption to the same Windows user and machine. Roaming profiles, admin-initiated password resets, service accounts, machine compromise, privileged malware and backup/restore can affect its security or recoverability. DPAPI encryption does **not** protect keys from code running with the same user's access. Go memory copies cannot guarantee comprehensive private-key zeroization. Folder inheritance and reparse-point attacks need review and installer-controlled ACL hardening.

## Remaining work

1. R2I.2: macOS Keychain, Linux Secret Service or an explicitly supported service-account key store; no insecure fallback. Per-service identity and interactive-user identity require a deliberate trust model.
2. R2I.3: approved identity provision/enroll/restore lifecycle, OS-safe rotation, platform service install/startup, diagnostics, revocation and recovery.
3. R2J: real pairing UI and authenticated gateway/session integration with explicit, independently authorized device capabilities.

The platform is **not** ready for public deployment or physical printer/attendance execution.

## References

- Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
- Microsoft: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
