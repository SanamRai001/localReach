# R1K — Single-writer ownership gate

## Implemented
A fail-closed, O_EXCL ownership sentinel beside each broker and edge journal. A second process attempting the same path is denied while the sentinel exists. A clean Close first closes the underlying journal and then removes its ownership sentinel. Added tests for both journals, double-open rejection and clean reopen.

## Critical limitations
- This is a **sentinel**, not an OS advisory lock. Crashes leave stale sentinels. Never automatically delete a stale sentinel based only on PID/time: first establish that no process can still write.
- The sentinel alone does not provide transaction guarantees across broker and edge, protect against manually deleted live locks, enforce secure symlink resolution, recover partial writes, or coordinate distributed deployments.
- A failed Open after acquiring the sentinel removes it. Directory permissions and journal ownership must be restricted at deployment.
- There is no cross-process integration harness yet, and the runtime remains test-harness only, not a deployable gateway.
- Before real-world use, choose robust OS locks or transactional database storage, repair/backup tooling, and an audited stale-recovery procedure.

## Acceptance still pending
```powershell
go test ./...
go vet ./...
```
Verify running tests before making any claims about storage reliability.

## Next
R1K.2: independently runnable gateway and agent mock processes in a secure loopback test harness, TLS certificate trust pinning for test only, then consolidated acceptance. Maintain separate unsafe/public deployment boundary.
