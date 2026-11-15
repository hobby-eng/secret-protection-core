# Audits

| Audit | Completed (UTC) | Reviewed commit | Scope | Findings at the reviewed commit |
| --- | --- | --- | --- | --- |
| [AUD-001](AUD-001-2026-11-15.md) · [JSON](AUD-001-2026-11-15.json) | 2026-11-15 | `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca` | Secret memory, process isolation and worker IPC | 22: 5 high, 11 medium, 6 low |
| [AUD-002](AUD-002-2026-11-15.md) · [JSON](AUD-002-2026-11-15.json) | 2026-11-15 | `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca` | Full crate security review with Linux runtime probes and six-target compilation | 6: 1 high, 3 medium, 2 low |

Both reviews read the same commit at the same time, and both were first written as AUD-001, the second over the first. The first report is restored byte for byte: its SHA-256 is the one its own validation recorded. Its JSON companion was found afterwards and is the original too, with the SHA-256 that validation recorded; commit 370c651 holds a copy rebuilt from the report in its place. The second report became AUD-002 before publication: its identifiers and paths changed, nothing else.

The reports record the findings as they stood at the reviewed commit. The fixes follow in later commits; the tables below say where each finding stands.

Audit evidence folders are machine-local and ignored by Git. The harnesses are kept beside the reports so that each check can be run again.

## Verification of the fixes in 6aa7e56

| Audit | Completed (UTC) | Scope | Disposition |
| --- | --- | --- | --- |
| [AUD-003](AUD-003-2026-11-15.md) · [JSON](AUD-003-2026-11-15.json) | 2026-11-15 | Linux and Android isolation, worker admission and shutdown | 14 historical records assessed, 7 new findings |
| [AUD-004](AUD-004-2026-11-15.md) · [JSON](AUD-004-2026-11-15.json) | 2026-11-15 | Protected memory, Windows and Apple isolation, platform contracts | 14 historical records assessed, 4 new findings |
| [AUD-005](AUD-005-2026-11-15.md) · [JSON](AUD-005-2026-11-15.json) | 2026-11-15 | Independent remediation review with targeted Linux probes | 1 new Low; AUD-003-SEC003 reproduced end to end |

## Verification at f3c2401

| Audit | Date (UTC) | Reviewed commit | Result |
| --- | --- | --- | --- |
| [AUD-006](AUD-006-2026-11-15.md) and [JSON](AUD-006-2026-11-15.json) | 2026-11-15 | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | 40 historical records assessed, four open. Six newly numbered findings. Linux tests and coverage, six-target Clippy and WebAssembly runtime checks. |
| [AUD-007](AUD-007-2026-11-15.md) · [JSON](AUD-007-2026-11-15.json) | 2026-11-15 | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | Independent remediation review: no new findings; 57 Linux checks and the prior signal regression passed; AUD-001-SEC004 remained open at this snapshot. |

## Windows worker review at 4c3de34

| Audit | Date (UTC) | Reviewed commit | Result |
| --- | --- | --- | --- |
| [AUD-008](AUD-008-2026-11-15.md) and [JSON](AUD-008-2026-11-15.json) | 2026-11-15 | `4c3de34eed462c7a85f875467a7bfcdb421e082b` | The original handle inheritance window is fixed in source. Native Windows execution is pending. Three new findings. Of 15 fixes in the earlier register, seven verified in scope, six pending verification, two partly open. |

## Where the findings stand

AUD-008 gives the state of every finding at `4c3de34`: 24 verified, 13 fixed with their verification outstanding, 9 open, and 3 new. The table has the 25 that are not verified, as they stand at `cb63252`. `fixed` means a fix exists at the commit named and no later review has verified it yet; none is open. A review of `6aa7e56` kept outside the numbered reports found four more points, fixed in `f3c2401`.

| Finding ID | Status | Fix commit | Verification commit | Evidence |
| --- | --- | --- | --- | --- |
| AUD-001-API001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | A lock taken where no mark can be made reads as unknown in later calls. Unit test of the answers. |
| AUD-001-API003 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | Each measure carries the words of its own outcome. The Windows read-backs were not run. |
| AUD-001-FUN002 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The worker is started from a thread with an ordinary stack. `worker`: a worker starts from a protected stack. The `fork` path of an old C library was not run. |
| AUD-001-FUN004 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | The lock flag comes from the C library's own definition. No architecture with another value was run. |
| AUD-001-FUN005 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | A work area is locked whenever Windows takes the lock. Not run on Windows. |
| AUD-001-FUN006 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | The attribute list is deleted only when it was initialized. Not run on Windows. |
| AUD-001-SEC004 | fixed | `4c3de34eed462c7a85f875467a7bfcdb421e082b` | none | The worker inherits no handle: a named pipe it opens itself, and the parent takes only the process it started. Not run on Windows. |
| AUD-001-SEC005 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | A refused probe counts only with this crate's sandbox profile in place. Not run on macOS. |
| AUD-001-SEC011 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | The dynamic-code policy holds only without a way out for a thread or another process. Not run on Windows. |
| AUD-002-SEC003 | fixed | `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | none | The Windows measures are read back and have fields of their own. Not run on Windows. |
| AUD-003-FUN001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | A kill that fails is not waited for, and both waits are bounded. `worker`: the program that may not signal others. The Windows code was not run. |
| AUD-003-SEC003 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The filter itself tells the thread that asks whom its signal rule names. `isolation`: the forked child, its second thread, and the update that failed. |
| AUD-004-API001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | One sandbox call at a time, and a success never goes back to false. Not run on macOS. |
| AUD-004-API002 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The exception for secure processes counts as a way out of the child-process policy. Not run on Windows. |
| AUD-004-SEC001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The field and the documents promise the default search only, and say what a call with a path or flags of its own still does. Not run on Windows. |
| AUD-005-DOC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The job's limits of the desktop and its one process are read back together. Not run on Windows. |
| AUD-006-BLD001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The test takes a grandchild that was not made or not waited for as a failure. |
| AUD-006-DOC001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The documents say that the crate reads no password and changes no terminal setting. |
| AUD-006-DOC002 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The documents give the outcome of file changes apart from that of sockets. |
| AUD-006-FUN001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | A worker is ended once: `end`, a failed call and the drop share one wait. `worker`: one second, not two, where the worker cannot be killed. |
| AUD-006-FUN002 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | No secret memory where signals cannot be blocked. `isolation`: a secret made where the mask is refused. |
| AUD-006-SEC001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | What a worker inherited is closed before its `main`; `serve` closes nothing and runs once. `worker`: the program with a file of its own, the second call of `serve`. |
| AUD-008-API001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | A setting is taken only as a parent writes it, and the pipe is opened before the isolation. Unit test of the setting. |
| AUD-008-FUN001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The worker's streams have one owner and end when `serve` returns. `worker`: a request left unread by a worker that lives on. The Windows code was not run. |
| AUD-008-SEC001 | fixed | `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | none | The documents describe the access list as it is and what another process of the user can do: take the place first, get nothing, and make the start fail. The list itself is unchanged. |
