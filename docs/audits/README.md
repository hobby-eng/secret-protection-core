# Audits

| Audit | Completed (UTC) | Reviewed commit | Scope | Findings at the reviewed commit |
| --- | --- | --- | --- | --- |
| [AUD-001](AUD-001-2026-11-15.md) · [JSON](AUD-001-2026-11-15.json) | 2026-11-15 | `8081d010b8040483d3ede458f522fad0fa81c571` | Secret memory, process isolation and worker IPC | 22: 5 high, 11 medium, 6 low |
| [AUD-002](AUD-002-2026-11-15.md) · [JSON](AUD-002-2026-11-15.json) | 2026-11-15 | `8081d010b8040483d3ede458f522fad0fa81c571` | Full crate security review with Linux runtime probes and six-target compilation | 6: 1 high, 3 medium, 2 low |

Both reviews read the same commit at the same time, and both were first written as AUD-001, the second over the first. The first report is restored byte for byte: its SHA-256 is the one its own validation recorded. Its JSON companion was found afterwards and is the original too, with the SHA-256 that validation recorded; commit 22855bf holds a copy rebuilt from the report in its place. The second report became AUD-002 before publication: its identifiers and paths changed, nothing else.

The reports record the findings as they stood at the reviewed commit. The fixes follow in later commits; the tables below say where each finding stands.

Audit evidence folders are machine-local and ignored by Git. The harnesses are kept beside the reports so that each check can be run again.

## Commit names

The reports AUD-001 to AUD-008 name commits by the hashes these had in the draft history, before it was published. The published commits hold the same trees; their dates are written in UTC, and their messages name the published commits. This index names the published ones, and so does AUD-009.

| In the reports | Published | Tree |
| --- | --- | --- |
| `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca` | `8081d010b8040483d3ede458f522fad0fa81c571` | `54ef11f2815cf7909823d03282e41dfbb730cae5` |
| `6aa7e56fb39dc21c09ac939020423ec13896b2eb` | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | `076dc8c85dcf180a60ca639d7fbc491dc5e46d06` |
| `370c651b6ef03a8f15ed17330b1e86e9e817a804` | `22855bfae09b4c57c782cf518c45c15618018eb6` | `bd84ee74f227f4457cd67c241caf8c8a90cc25f1` |
| `f3c2401d1b5b2ee5dfd98eaec298d74da53b765f` | `c57018a9888fb84335332ed49580e59724217e5c` | `ae2d7bc2dd286b29db4cb99f3c7c003b4b4a3d91` |
| `bd7506328244970891fc230a4abca03824a1bd94` | `7d356f69d5fb79fb72fc4be7380f632a3fddf57d` | `6de6e523f717f0be1e05f943911db32244abd98f` |
| `4c3de34eed462c7a85f875467a7bfcdb421e082b` | `2f28cb3e2cc317c339f0c7ddbdfcf8a1e89c980b` | `6a50c52d7a2b9d90a9a2b89bd8cf09128117c48f` |
| `f855148fadb9e0aa80b0ff7bc88fb923f0cc9ac0` | `d418974b238e17c9a4f70290da95bf83b14db85c` | `d65c521931b9ad5fad473c8b38a1ba5832b20391` |
| `cb63252fb3fa4bf15b682a10f6eb202d47b00a54` | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | `b19e768f11410e7ba325f1d79a70e0295d345b20` |
| `c60d17e3bd03bff03529987352867654059887e3` | `709a5a21dca4c57a7f05943d34f4f52786317765` | `c7d428ad7b60693f628831175dc6921f01f162d7` |

## Verification of the fixes in 960647c

| Audit | Completed (UTC) | Scope | Disposition |
| --- | --- | --- | --- |
| [AUD-003](AUD-003-2026-11-15.md) · [JSON](AUD-003-2026-11-15.json) | 2026-11-15 | Linux and Android isolation, worker admission and shutdown | 14 historical records assessed, 7 new findings |
| [AUD-004](AUD-004-2026-11-15.md) · [JSON](AUD-004-2026-11-15.json) | 2026-11-15 | Protected memory, Windows and Apple isolation, platform contracts | 14 historical records assessed, 4 new findings |
| [AUD-005](AUD-005-2026-11-15.md) · [JSON](AUD-005-2026-11-15.json) | 2026-11-15 | Independent remediation review with targeted Linux probes | 1 new Low; AUD-003-SEC003 reproduced end to end |

## Verification at c57018a

| Audit | Date (UTC) | Reviewed commit | Result |
| --- | --- | --- | --- |
| [AUD-006](AUD-006-2026-11-15.md) and [JSON](AUD-006-2026-11-15.json) | 2026-11-15 | `c57018a9888fb84335332ed49580e59724217e5c` | 40 historical records assessed, four open. Six newly numbered findings. Linux tests and coverage, six-target Clippy and WebAssembly runtime checks. |
| [AUD-007](AUD-007-2026-11-15.md) · [JSON](AUD-007-2026-11-15.json) | 2026-11-15 | `c57018a9888fb84335332ed49580e59724217e5c` | Independent remediation review: no new findings; 57 Linux checks and the prior signal regression passed; AUD-001-SEC004 remained open at this snapshot. |

## Windows worker review at 2f28cb3

| Audit | Date (UTC) | Reviewed commit | Result |
| --- | --- | --- | --- |
| [AUD-008](AUD-008-2026-11-15.md) and [JSON](AUD-008-2026-11-15.json) | 2026-11-15 | `2f28cb3e2cc317c339f0c7ddbdfcf8a1e89c980b` | The original handle inheritance window is fixed in source. Native Windows execution is pending. Three new findings. Of 15 fixes in the earlier register, seven verified in scope, six pending verification, two partly open. |

## External review of the source of 0b0aa7f

| Audit | Date (UTC) | Reviewed source | Result |
| --- | --- | --- | --- |
| [AUD-009](AUD-009-2026-11-15.md) and [JSON](AUD-009-2026-11-15.json) | 2026-11-15 | that of `0b0aa7fd417e0d0c5d126c831bdffaebaa955977`; the review recorded no commit | A reading of the source, filed from a free-form report. Six findings: one high, three medium, two low. Two observations. |

## Where the findings stand

AUD-008 gives the state of every finding at `2f28cb3`: 24 verified, 13 fixed with their verification outstanding, 9 open, and 3 new. The table has the 25 that are not verified, as they stand at `0b0aa7f`. `fixed` means a fix exists at the commit named and no later review has verified it yet; none is open. A review of `960647c` kept outside the numbered reports found four more points, fixed in `c57018a`. The six findings of AUD-009 follow them, as they stand at `bebf3ff`: five fixed, and one mitigated with its rest accepted.

Where a row says that the fix was not run on Windows or macOS, that was so when it was written. Since `f89d0bf` the crate's tests run on Linux for AArch64, macOS and Windows at every push, first in GitHub's run 43694705738: the code of those fixes runs there and its tests pass. That is not the verification of a review, and the statuses stand.

| Finding ID | Status | Fix commit | Verification commit | Evidence |
| --- | --- | --- | --- | --- |
| AUD-001-API001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | A lock taken where no mark can be made reads as unknown in later calls. Unit test of the answers. |
| AUD-001-API003 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | Each measure carries the words of its own outcome. The Windows read-backs were not run. |
| AUD-001-FUN002 | fixed | `c57018a9888fb84335332ed49580e59724217e5c` | none | The worker is started from a thread with an ordinary stack. `worker`: a worker starts from a protected stack. The `fork` path of an old C library was not run. |
| AUD-001-FUN004 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | The lock flag comes from the C library's own definition. No architecture with another value was run. |
| AUD-001-FUN005 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | A work area is locked whenever Windows takes the lock. Not run on Windows. |
| AUD-001-FUN006 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | The attribute list is deleted only when it was initialized. Not run on Windows. |
| AUD-001-SEC004 | fixed | `2f28cb3e2cc317c339f0c7ddbdfcf8a1e89c980b` | none | The worker inherits no handle: a named pipe it opens itself, and the parent takes only the process it started. Not run on Windows. |
| AUD-001-SEC005 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | A refused probe counts only with this crate's sandbox profile in place. Not run on macOS. |
| AUD-001-SEC011 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | The dynamic-code policy holds only without a way out for a thread or another process. Not run on Windows. |
| AUD-002-SEC003 | fixed | `960647c5ccbcfe7bd93175d1c6266f17f4d66db2` | none | The Windows measures are read back and have fields of their own. Not run on Windows. |
| AUD-003-FUN001 | fixed | `c57018a9888fb84335332ed49580e59724217e5c` | none | A kill that fails is not waited for, and both waits are bounded. `worker`: the program that may not signal others. The Windows code was not run. |
| AUD-003-SEC003 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The filter itself tells the thread that asks whom its signal rule names. `isolation`: the forked child, its second thread, and the update that failed. |
| AUD-004-API001 | fixed | `c57018a9888fb84335332ed49580e59724217e5c` | none | One sandbox call at a time, and a success never goes back to false. Not run on macOS. |
| AUD-004-API002 | fixed | `c57018a9888fb84335332ed49580e59724217e5c` | none | The exception for secure processes counts as a way out of the child-process policy. Not run on Windows. |
| AUD-004-SEC001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The field and the documents promise the default search only, and say what a call with a path or flags of its own still does. Not run on Windows. |
| AUD-005-DOC001 | fixed | `c57018a9888fb84335332ed49580e59724217e5c` | none | The job's limits of the desktop and its one process are read back together. Not run on Windows. |
| AUD-006-BLD001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The test takes a grandchild that was not made or not waited for as a failure. |
| AUD-006-DOC001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The documents say that the crate reads no password and changes no terminal setting. |
| AUD-006-DOC002 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The documents give the outcome of file changes apart from that of sockets. |
| AUD-006-FUN001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | A worker is ended once: `end`, a failed call and the drop share one wait. `worker`: one second, not two, where the worker cannot be killed. |
| AUD-006-FUN002 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | No secret memory where signals cannot be blocked. `isolation`: a secret made where the mask is refused. |
| AUD-006-SEC001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | What a worker inherited is closed before its `main`; `serve` closes nothing and runs once. `worker`: the program with a file of its own, the second call of `serve`. |
| AUD-008-API001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | A setting is taken only as a parent writes it, and the pipe is opened before the isolation. Unit test of the setting. |
| AUD-008-FUN001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The worker's streams have one owner and end when `serve` returns. `worker`: a request left unread by a worker that lives on. The Windows code was not run. |
| AUD-008-SEC001 | fixed | `0b0aa7fd417e0d0c5d126c831bdffaebaa955977` | none | The documents describe the access list as it is and what another process of the user can do: take the place first, get nothing, and make the start fail. The list itself is unchanged. |
| AUD-009-SEC001 | fixed | `bebf3ff1db7fd84e41f892c258733aa92a7db87e` | none | The check reads the system's list of open descriptors every time: a worker that holds one above standard error, inherited or opened by the program since, says its start was not clean. `worker`: the program with a file of its own reports a clean byte of zero; seen failing without the fix. |
| AUD-009-SEC002 | fixed | `bebf3ff1db7fd84e41f892c258733aa92a7db87e` | none | The function that runs before `main` reads the variable by the rule of `serve` and closes nothing for any other text. `worker`: a program started with four texts that are no setting keeps the descriptor its parent left it; seen failing without the fix. That whoever sets the environment decides whether the program is a worker is stated in docs/TECHNICAL.md. |
| AUD-009-SEC003 | accepted | `bebf3ff1db7fd84e41f892c258733aa92a7db87e` | none | Mitigated: the parent puts off a client that is not the worker and listens again, and the worker keeps trying a busy pipe for a second, so that one connection by another program no longer fails the start (`worker`, Windows only: a thread takes the pipe first). Accepted: a process of the same user that takes the pipe again and again for that second still stops the start, and nothing is sent to it; docs/TECHNICAL.md, What is not covered. Such a process may end the worker in any case: the access list of the worker's process leaves that to its user. The user's entry stays in the pipe's list, since Windows checks a process in an AppContainer against the user's entries as well as the container's. Handles passed by inheritance are what AUD-001-SEC004 replaced. |
| AUD-009-FUN001 | fixed | `bebf3ff1db7fd84e41f892c258733aa92a7db87e` | none | The section is `__DATA,__mod_init_func,mod_init_funcs`: it names its kind, pointers to functions run before `main`, whatever the compiler and linker made before. The static had `#[used]` already, which the report took to be missing. Not run on macOS when this record was filed. |
| AUD-009-FUN002 | fixed | `bebf3ff1db7fd84e41f892c258733aa92a7db87e` | none | Where /dev/null could not be opened, the two descriptors are closed outright. `worker`: under a filter that refuses opening for reading and writing, a call to a worker that serves no more and lives on fails at once; seen failing without the fix. |
| AUD-009-SEC004 | fixed | `bebf3ff1db7fd84e41f892c258733aa92a7db87e` | none | A secret's anonymous pages are marked `MADV_NOHUGEPAGE` before they are locked. `secret_memory`: the mapping of such a secret has the flag and a work area's has not; both seen failing when the code is changed. A work area keeps the huge pages the system gives it, on purpose: a large computation is much slower without them; docs/TECHNICAL.md, What is not covered. |

## Release audit of the published Git source

| Audit | Date (UTC) | Source | Outcome |
| --- | --- | --- | --- |
| [AUD-010](AUD-010-2026-11-15.md) and [JSON](AUD-010-2026-11-15.json) | 2026-11-15 | `39e462e946cc300a8a3d3e145517957094eb7c8c` | Unrestricted production use is blocked by the lifetime of protected buffer owners in a continuing Unix child. Native CI run 4 passed on four runners. See the release report for the limits, independent results and remediation. |
