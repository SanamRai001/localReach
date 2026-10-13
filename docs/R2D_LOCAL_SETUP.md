# R2D — Trusted-origin local setup preview

Run `go run ./cmd/localreach-setup` from the repo root and open `http://127.0.0.1:18788`. The loopback service serves the static setup preview and a read-only status response on the **same origin**. It does not initiate pairing, install software, scan hardware or provide LAN command access.

The handler checks the exact Host header, peer loopback IP, optional Origin, method allowlist and static-file allowlist; supplies CSP, no-store and nosniff headers. It never binds a publicly accessible address. This is a preview process, **not** the real installed agent; status is a default local state with NOT_PAIRED and OFFLINE, not proof of connection.

Security boundary: local browsers and other local programs may read the non-secret status. There is no mutating endpoint. Browser origin and host checks do not authenticate local malicious processes; when pairing is implemented it must use explicit approval, CSRF resistance and independent user authorization. No public exposure, reverse proxy or DNS rebinding allowance.

Verification: `go test ./...`, `go vet ./...`, and optional manual `go run ./cmd/localreach-setup`. The branch's GitHub Actions gate must be checked before calling tests passed.
