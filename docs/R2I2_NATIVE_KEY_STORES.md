# R2I.2 — Native Linux and macOS agent key storage

## What this branch delivers

LocalReach agents now have a platform-aware, fail-closed key-storage implementation:
- **Windows:** Existing current-user DPAPI encrypted identity remains unchanged.
- **macOS:** Security.framework Keychain generic-password item (`SecItemAdd` / `SecItemCopyMatching`) holds the signing secret. The private key is never passed as a command-line argument, and duplicate Keychain items are rejected rather than overwritten. This path requires CGo and a usable user Keychain; without CGo it fails closed.
- **Linux desktop:** The session's Secret Service is accessed through `/usr/bin/secret-tool` (libsecret). Store sends the secret over **stdin**; lookup reads from the program's bounded stdout. No secret in command-line arguments, environment variables, local files or application logs. If `DBUS_SESSION_BUS_ADDRESS` or the native tool/service is absent, the backend reports unsupported rather than writing plaintext.
- **Other OS:** unsupported. No plaintext fallback.

For macOS and Linux a small, versioned `identity.ref` in the user's config directory holds **only** a randomly generated reference ID, a public-key SHA-256 fingerprint and creation time. The native credential store holds the full secret JSON. The agent must match both records on Load. The marker is created with exclusive `O_EXCL` semantics **before** storing the secret to prevent concurrent identities. A crash or native-store failure after marker creation can leave an orphan reference; load then fails closed. No silent deletion or automatic key replacement. Missing, symlinked, malformed and corrupted reference files are rejected.

`Store.Create` is an explicit first-enrollment operation; `Store.Load` never generates a key or silently re-enrolls. `Identity` signs only inside native Go process; it is never serialized to browser JSON.

## Tests and limitations

CI runs regular Linux Go suite, Windows DPAPI tests and full packages, and an additional macOS runner which compiles Security.framework CGo, runs signer/reference lifecycle tests and checks CGo-disabled fallback.

The non-Windows mock-vault tests exercise marker integrity, reload, concurrency, lost secret fail-closed behavior and no plaintext file persistence. **They do not prove an unlocked Keychain or Secret Service works** on an end-user machine. A real native-provider roundtrip test can be opted in with `LOCALREACH_TEST_NATIVE_VAULT=1 go test ./internal/agentkeys` on an interactive desktop with a configured unlocked store. This test creates a test-only credential item; cleanup and rotation tools are not implemented yet.

Security caveats:
- `secret-tool` requires a compatible, unlocked desktop Secret Service. This does not cover all headless Linux servers or every distro; no insecure fallback exists.
- macOS Keychain access may require code signing, interactive authorization or entitlements depending on the release environment. CGo-disabled apps fail closed.
- Secret-store security cannot defend against malware running with the same user's credentials. Go cannot guarantee total private-key zeroization. Windows ACLs, macOS app signing / Keychain access rules, Linux user session restrictions, symlink ancestors, and strict service-account isolation need deployment-hardening review.
- Reference marker and OS credential store are not a single transaction. A crash can cause an orphan secret or marker. Recovery must be an explicit, audited operation with administrator authorization; never automatically regenerate the key.
- No installed service, key rotation, revocation fanout, signed installer, real WAN pairing, capability grants, physical device integration or production readiness.

## Next

R2I.3: bind native identity to database-backed enrollment and authorization, add user-guided recovery/rotation and secure installed-agent lifecycle. Then R2J: truly connected Install → Connect → Approve → Ready UX with independently approved device capabilities.

Platform API background:
- Apple generic-password Keychain: https://developer.apple.com/documentation/security/ksecclassgenericpassword
- GNOME libsecret secret-tool: https://github.com/GNOME/libsecret/blob/main/tool/secret-tool.c
