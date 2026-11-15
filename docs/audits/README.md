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

## After these reviews

What was open or new at `6aa7e56`, and where it stands. `fixed` means a fix exists at the commit named and no later review has verified it yet.

| Finding ID | Status | Fix commit | Verification commit | Evidence |
| --- | --- | --- | --- | --- |
| AUD-001-SEC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | A process takes secret memory only if it had one thread when the gate was registered, and a secret does not wait for a `fork` for ever. `secret_memory`: the first secret among threads, the secret under a fork handler's lock, the 2,000 forks. |
| AUD-001-SEC004 | open | none | none | Unchanged. The worker's pipe ends can be inherited during its own start; docs/TECHNICAL.md says so. A start without inheritance is planned and needs a run on Windows. |
| AUD-001-FUN002 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The worker is started from a thread with an ordinary stack. `worker`: a worker starts from a protected stack. The `fork` path of an old C library was not run. |
| AUD-003-SEC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | A refused probe confirms only with this crate's filter and its rule. `isolation`: a refusal by someone else's policy. |
| AUD-003-SEC002 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | In a PID namespace of its own the reading of memory is unknown. `isolation`: a PID namespace of its own. |
| AUD-003-SEC003 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The signal rule's owner is recorded once the filter went in. `isolation`: the forked child after a filter update that failed. |
| AUD-003-FUN001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | A kill that fails is not waited for, both waits are bounded, a failed call ends the worker, and `Worker::end` says whether it ended. `worker`: the program that may not signal others. The Windows code was not run. |
| AUD-003-API001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | A refused Landlock layer is tried again and recorded by one more filter. `isolation`: a layer refused once. |
| AUD-003-DOC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | docs/TECHNICAL.md gives the mark as 0xE00 with its bits. |
| AUD-003-BLD001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The test programs turn the leak check off themselves, so a worker without an environment has it off too; the logs of the four sanitizer runs hold no report. |
| AUD-004-SEC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The protection is named `no_planted_libraries` and documented as the limit of the search by name, not a list of folders. Not run on Windows. |
| AUD-004-API001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | One sandbox call at a time, and a success never goes back to false. Not run on macOS. |
| AUD-004-API002 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The exception for secure processes counts as a way out of the child-process policy. Not run on Windows. |
| AUD-004-DOC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | README.md, docs/TECHNICAL.md and the type's note say that the system may refuse to close the pages, and point to `is_closed`. |
| AUD-005-DOC001 | fixed | `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | none | The job's limits of the desktop and its one process are read back together. Not run on Windows. |

A further review of the same snapshot, kept outside the numbered reports, found four more points, fixed in the same commit: a program that reached `Worker::start` before `serve` started itself without end; a secret could wait for ever for a `fork` whose handler waited for a lock of the caller's; a child with its parent's number in another PID namespace read the parent's lock of memory as its own; and a terminal opened after the isolation takes no settings, which the documents now say.
