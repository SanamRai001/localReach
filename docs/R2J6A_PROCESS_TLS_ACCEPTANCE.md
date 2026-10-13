# R2J.6A — Process-level TLS, crash/recovery acceptance

## Why this phase exists

The pairing control-plane and native agent tests already exercised HTTPS handlers and PostgreSQL, but did **not** run the actual control-plane executable as an independent OS process through a real listening socket. R2J.6A adds that acceptance boundary and catches the following real defect in `cmd/localreach-control`:

**Fixed:** `http.Server.WriteTimeout = 10s` applied a global HTTP response deadline to an otherwise healthy long-lived authenticated stream. It would disconnect real agents after approximately ten seconds even if heartbeats were working. The server now avoids a global response write timeout, while `pairapi.streamSession` retains its explicit **5-second deadline on each individual frame write**, the server retains read/header deadlines and the native client retains its inactivity watchdog.

## What CI executes

`internal/pilotacceptance/TestSeparateProcessTLSCrashReclaimRevocation` uses the **real** compiled `cmd/localreach-control` executable in a separate OS process and a PostgreSQL-backed enrolled Ed25519 test agent. It runs only when the CI job explicitly supplies `LOCALREACH_CONTROL_BINARY` and the disposable loopback `localreach_test` connection. Otherwise it skips rather than trying to start a service or touch a database.

1. Applies migrations `060`–`065` and truncates **only** the explicitly named disposable test database. The test refuses any DSN except `postgres://...@127.0.0.1/.../localreach_test?sslmode=disable`. It creates a random agent key for the test **client process only**, provisions a test owner, and independently signs approval/enrollment.
2. Generates a temporary, short-lived self-signed TLS certificate with an IP SAN for `127.0.0.1`, backed by an isolated test-only client trust pool. The real server process receives only server TLS private key and database credentials. The client has **no** PostgreSQL credentials and does not use `InsecureSkipVerify`.
3. Starts `localreach-control` with loopback-only `-allow-disposable-loopback-db` and reaches it through an actual TLS TCP connection, not an in-memory handler. Tests that an empty/untrusted certificate pool cannot authenticate to the gateway.
4. Starts `agentremote.Client.StreamSession` with one-use Ed25519 resume challenge. Confirms the connection is ONLINE in PostgreSQL and continues receiving at least three heartbeats **beyond twelve seconds**. This prevents the previous server-global 10s write-timeout regression.
5. Kills the server process to simulate an abrupt crash. Confirms the client exits its streaming read. Waits for the 15-second database lease to expire and checks backend liveness becomes OFFLINE (no immediate false promises of crash detection on the server).
6. Starts a new server process on the same loopback address. Confirms the same test agent authenticates and reclaims a live session without key regeneration.
7. Independently signs tenant-owner revocation in PostgreSQL. Confirms the next server heartbeat closes the live TLS stream, the backend marks the agent OFFLINE, and the revoked key cannot resume.

The workflow runs the test with the Go race detector after the other destructive PostgreSQL tests finish. No physical printers, IoT attendance devices, arbitrary proxies, LAN discovery or device permissions are created.

## Important limitations

**This is a separate-process loopback acceptance harness, NOT two real networks.** Both processes run on the same GitHub Actions VM and share disposable PostgreSQL service. It tests actual server lifecycle, HTTPS certificate validation, socket reads/writes, authenticated streams and crash recovery, but cannot reproduce a customer's ISP, CGNAT, public DNS, WAN path, TLS certificate renewal, router, proxy or external firewall. The `-enable-restricted-staging` listener from R2J.4B is not deployed or exercised in this test because staging correctly **requires PostgreSQL sslmode=verify-full and an operator-managed certificate**. Existing direct-TLS staging gate unit tests still test Host/SNI/source allowlists.

Production blockers remain: real tenant-user SSO, native signed installer/background service, explicitly authorized external pilot with staging DNS/certs/network firewall and remote client source ranges, distributed gateway hardening, metrics/alerting, retention and rotation, and independently approved device-specific capabilities. At most 16 long-lived streams are permitted by the current staging gate, so it is not designed for scale yet.

## Human-run R2J.6B acceptance gate (requires explicit authorization)

An operator with a **permitted remote staging environment** must provide:

- A controlled server with DNS, valid certificate and key, PostgreSQL with `sslmode=verify-full`, migrations, a minimally privileged application database role and operator-managed secrets.
- A client on **another actual network** with a known source public IP/CIDR included in the server firewall and application source allowlist. No router changes should be necessary on the client network.
- An already provisioned organization/administrator and a separately approved agent signing identity, installed user-native credential store and a deliberately authorized test period.
- An explicit rollback plan, certificate trust test, session >30 seconds, controlled network interruption/reconnect, signed revocation, denied reconnect, and confirmation that **device capabilities remain NONE**.

No staging service has been deployed and no physical WAN pilot has been performed. Do **not** expose this prototype broadly or assume an invitation code alone grants access.

## Next

R2J.6B is the controlled real two-network acceptance gate. Code development can then proceed with **R2K.1: audited, organization/site/agent-scoped device permission grants and read-only discovery**, without opening any printer/attendance write routes until approvals and tests pass.
