# Security audits

Each report identifies the source revision it examined. The [fix history](HISTORY.md) tracks the status of each finding and its verification.

| Report | Source reviewed | What the review found or verified |
| --- | --- | --- |
| [AUD-001](AUD-001-2026-11-15.md) · [JSON](AUD-001-2026-11-15.json) | `8081d01` | Linux could pass an open secret-memory descriptor across a concurrent fork. A Unix worker could accept requests after incomplete descriptor cleanup. |
| [AUD-002](AUD-002-2026-11-15.md) · [JSON](AUD-002-2026-11-15.json) | `8081d01` | Network isolation could leave IPC shared with the parent. Rejecting an oversized reply could leave the parent and worker waiting on each other. |
| [AUD-003](AUD-003-2026-11-15.md) · [JSON](AUD-003-2026-11-15.json) | `960647c` | A host policy could make a socket probe pass without the crate’s filter. A PID namespace could hide an attached debugger. |
| [AUD-004](AUD-004-2026-11-15.md) · [JSON](AUD-004-2026-11-15.json) | `960647c` | Concurrent macOS calls could lose evidence of sandbox entry. Windows could report a child-process ban even with an exception enabled. |
| [AUD-005](AUD-005-2026-11-15.md) · [JSON](AUD-005-2026-11-15.json) | `960647c` | An existing Windows job could pass the desktop check without limiting the job to one process. The Linux signal regression still reproduced. |
| [AUD-006](AUD-006-2026-11-15.md) · [JSON](AUD-006-2026-11-15.json) | `c57018a` | Worker shutdown could run twice. Unix startup could close descriptors owned by application code. Terminal echo remained the caller’s responsibility. |
| [AUD-007](AUD-007-2026-11-15.md) · [JSON](AUD-007-2026-11-15.json) | `c57018a` | Retested the Linux fixes, including failed signal-filter installation. The Windows pipe inheritance window remained open at this revision. |
| [AUD-008](AUD-008-2026-11-15.md) · [JSON](AUD-008-2026-11-15.json) | `2f28cb3` | The named pipe removed the Windows handle inheritance window. Its access list still admitted other processes of the same user, and malformed settings could activate worker mode. |
| [AUD-009](AUD-009-2026-11-15.md) · [JSON](AUD-009-2026-11-15.json) | Source matched to `0b0aa7f`; the reviewer recorded no commit | A worker could report a clean start without inspecting its open descriptors. A competing client could prevent the Windows worker from starting. |
| [AUD-010](AUD-010-2026-11-15.md) · [JSON](AUD-010-2026-11-15.json) | `39e462e` | A continuing Unix child could still use Rust owners for pages the OS had removed or unlocked. Some fork tests could pass without observing a successful child exit. |
| [AUD-011](AUD-011-2026-11-15.md) · [JSON](AUD-011-2026-11-15.json) | `2747028` | An inherited `ClosedSecret` could report closed pages after fork. The coverage report also named the wrong source revision. |
| [AUD-012](AUD-012-2026-11-15.md) · [JSON](AUD-012-2026-11-15.json) | `2747028` | Worker cleanup before main could close a descriptor that a linked library had already reused for another file. |
| [AUD-013](AUD-013-2026-11-15.md) · [JSON](AUD-013-2026-11-15.json) | `2747028` | Independently confirmed the descriptor-reuse bug and the stale `ClosedSecret` status in a forked child. |
| [AUD-014](AUD-014-2026-11-15.md) · [JSON](AUD-014-2026-11-15.json) | `fb2a6d3` | Five release blockers: a forked callback could change permissions on a reused address, Unix startup could leak descriptors, shutdown could signal a reused PID, admission could accept thread-only isolation, and Windows could miss a higher-privilege thread token. |
| [AUD-015](AUD-015-2026-11-15.md) · [JSON](AUD-015-2026-11-15.json) | Working tree on `fb2a6d3`; native follow-up at `3d914c8` and `e7b0d38` | Verified the fixes with a fork inside a callback, descriptor and worker-admission tests, and native Windows token checks. Unix shutdown now signals only through a stable handle. On macOS, `end()` can return false while a worker is alive; CI verified that the library collected it after exit. |

The [fix history](HISTORY.md) gives finding IDs, fix commits and corrections to older reports. The [final native CI run](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745920704) covers Linux x86-64, Linux ARM64, macOS and Windows.
