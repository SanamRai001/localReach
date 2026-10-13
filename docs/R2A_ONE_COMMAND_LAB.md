# R2A — One-command developer smoke test

Run `bash scripts/verify-two-process.sh` on Linux/macOS/WSL with Go, OpenSSL and curl installed. The script creates disposable test certificates, compiles the lab, starts a **loopback-only** HTTPS gateway in a separate process, waits for readiness, runs a separate agent process, checks successful mock delivery and cleans up artifacts.

GitHub Actions runs the script on Linux as an additional acceptance gate.

This is not a consumer installer or secure internet pairing yet. It uses a temporary lab private key; the real device/OS installation and admin-authorized enrollment UX remain future work. The gateway refuses public listening; no real devices are contacted.

A busy port 18787 will fail closed. The agent/server identity and broker are disposable for each run.
