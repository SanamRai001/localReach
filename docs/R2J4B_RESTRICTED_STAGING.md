# R2J.4B — restricted direct-TLS cross-network staging ingress

## Purpose

This branch adds **an opt-in, tightly source-allowlisted direct HTTPS listener** to the existing LocalReach control-plane prototype. It can accept a native client from another network when the operator controls a reachable server, DNS, an appropriate TLS certificate and firewall rules.

**It is not automatically deployed, not an unrestricted Internet gateway, and not a persistent device relay.** LocalReach's agent still initiates every HTTPS request outbound. The agent-side router needs **no inbound port forwarding**. The *server* hosting the control plane necessarily needs an intentionally reachable HTTPS endpoint for a cross-network pilot.

The original default is unchanged: `localreach-control` binds `127.0.0.1:19443` only. Providing staging arguments without the explicit opt-in flag is rejected.

## Operator-controlled restricted pilot

Preconditions: a disposable staging environment under operator control; a PostgreSQL server provisioned with migrations 060–064, a least-privileged application role, `sslmode=verify-full`, trusted CA certificates and secure backups; separately provisioned administrator keys; a signed and time-valid server certificate matching the chosen DNS hostname; firewall rules allowing **only** the pilot client IPs; and logging/incident response on a host you administer.

After preconditions, a *possible* developer staging invocation is:

```sh
# Supply LOCALREACH_CONTROL_DSN as an environment secret on the host.
# No credentials, private keys, invitations, or tokens in the command string.
go run ./cmd/localreach-control \
  -tls-cert /path/to/server-chain.pem \
  -tls-key /path/to/server-key.pem \
  -enable-restricted-staging \
  -staging-listen 0.0.0.0:19443 \
  -staging-dns pilot.example.test \
  -staging-peer-cidrs 203.0.113.4/32
```

The domain and address above are **illustrative only** and do not establish a working deployment. An actual DNS name and certificate, public or privately routed network path, firewall and accurate source IP must be supplied by the operator. The source allowlist refers to the **direct TCP peer** seen by the Go process. Reverse proxies, tunnels, load balancers and NAT that change that peer are not configured or trusted by this phase; **never** relax the source allowlist or use untrusted forwarded headers to get around it.

When enabled, `internal/staginggate` enforces:

- Exact operator-configured IP-address listener, DNS hostname and a required nonempty comma-separated list of up to 16 narrow CIDR ranges (IPv4 /24 or narrower, IPv6 /64 or narrower). Wildcard client ranges such as `0.0.0.0/0` or `::/0` are rejected.
- A server X.509 leaf certificate whose SAN matches the configured DNS name, within its validity period and usable for TLS server authentication, verified **before** binding the network listener.
- Direct TLS **1.3 minimum**. Both the TLS SNI name and HTTP Host must match the configured hostname and port. Redirects to plaintext remain forbidden in native clients.
- Rejection of nonallowlisted peers **before** TLS handshake; a second check at HTTP request handling; max **16 concurrent routed requests** with immediate overload rejection.
- Existing no-browser/Origin/Cookie restriction, body limits and per-route **shared PostgreSQL five-per-minute per-direct-IP admission**, fail closed on database errors.
- An explicit rejection of the disposable plaintext PostgreSQL option in staging mode. Remote production/staging DB must use `sslmode=verify-full`. Server listens on nothing if required configuration/certificates/DB validation fails.

The operator must still restrict socket access using the host/cloud firewall and network rate limits. TLS endpoint identity, basic CIDRs and app-layer concurrency do not prevent volumetric denial of service, malicious allowed clients, or exploitation of application-level mistakes.

## What an agent can and cannot do

An operator-provisioned agent can call a DNS-resolvable, certificate-validated `https://...` address to request a single-use invitation, wait for separately signed administrator approval, enroll with Ed25519 proof and periodically verify its identity. A native OS-protected key and exact request fingerprint remain mandatory.

A successful `resume-verify` is still **IDENTITY_VERIFIED**, with `connection=OFFLINE`, `capabilities=NONE`. This mode has **no command queue, persistent authenticated outbound session, printer driver, attendance adapter, active online heartbeat, or generic tunneling**. The user experience is not yet “one-click connected.” The server's network exposure is a **restricted pilot**, not permission to deploy publicly.

## Tests

Automated checks cover invalid DNS names, malformed/oversized/overbroad CIDRs, non-IP bind, privileged port denial, allowlisted vs blocked direct peers, spoofed forwarded-for headers, TLS version, SNI/Host mismatch, concurrency exhaustion, socket pre-TLS filter acceptance, certificate SAN mismatch and certificate validity. The existing PostgreSQL pairing/auth/invitation tests and Windows/macOS/Linux builds remain required CI gates.

**Not covered:** real DNS/certificate issuance or renewal, actual source-NAT and firewall acceptance, external TLS scanner results, staging rollback, multi-host disaster recovery, secured tenant SSO, rate-limit retention, real native installer or Internet-scale adversarial testing. No operator secrets or public endpoints are committed.

## Next

1. R2J.4C: stage an operator-controlled **end-to-end network pilot** only after deployment approval, with a second machine/network, valid TLS, source IP rules, negative tests and recovery/rollback procedures.
2. R2J.5: design the real authenticated outbound persistent **agent-to-cloud session** with heartbeat/revocation, where ONLINE actually means connected. Never use identity verification alone as an online signal.
3. R2K: explicit, separately approved device grants, read-only LAN discovery, controlled printer/attendance adapters and actual hardware acceptance.

All stacked PRs stay open pending explicit merge approval. No deployment has been performed in this phase.
