# Audits

| Audit | Completed (UTC) | Reviewed commit | Scope | Findings at the reviewed commit |
| --- | --- | --- | --- | --- |
| [AUD-001](AUD-001-2026-11-15.md) · [JSON](AUD-001-2026-11-15.json) | 2026-11-15 | `8081d010b8040483d3ede458f522fad0fa81c571` | Secret memory, process isolation and worker IPC | 22: 5 high, 11 medium, 6 low |
| [AUD-002](AUD-002-2026-11-15.md) · [JSON](AUD-002-2026-11-15.json) | 2026-11-15 | `8081d010b8040483d3ede458f522fad0fa81c571` | Full crate security review with Linux runtime probes and six-target compilation | 6: 1 high, 3 medium, 2 low |
| [AUD-015](AUD-015-2026-11-15.md) · [JSON](AUD-015-2026-11-15.json) | 2026-11-15 | Working tree on `fb2a6d345caf` | Verify 16 findings and five earlier partial fixes | Native Windows, macOS and Linux AArch64 pending |

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

## Errata

- AUD-001 links to `tests/isolation.rs` (lines 868 and 880). That file was later split into `tests/isolation/main.rs` and its modules; the lines are those of the commit AUD-001 reviewed, published as [8081d01](https://github.com/hobby-eng/secret-protection-core/blob/8081d010b8040483d3ede458f522fad0fa81c571/tests/isolation.rs#L868). The report itself is kept as it was written.
- The row of AUD-009-FUN002 above says that the two descriptors are closed outright where /dev/null cannot be opened. Since `e529376` they are pointed at the read end of an ended pipe instead, so that their numbers stay taken; since the fixes of AUD-010 a worker that can have neither refuses to start.
- The row of AUD-009-SEC002 describes the function that runs before `main` as closing the descriptors above standard error. Since the fixes of AUD-010 it closes only those its parent names in the setting, so that descriptors the program's libraries opened before it stay theirs.
- The rows of AUD-006-SEC001, AUD-009-SEC002 and AUD-010-SEC002, the erratum above and the paragraph after the AUD-010 table describe a function that runs before `main` and closes descriptors. Since the fixes of AUD-012, at `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6`, nothing in the worker closes a descriptor: `posix_spawn` closes those the worker would inherit in the child, before the program runs, and that function only counts forks.

## Release audit of the published Git source

| Audit | Date (UTC) | Source | Outcome |
| --- | --- | --- | --- |
| [AUD-010](AUD-010-2026-11-15.md) and [JSON](AUD-010-2026-11-15.json) | 2026-11-15 | `39e462e946cc300a8a3d3e145517957094eb7c8c` | Unrestricted production use is blocked by the lifetime of protected buffer owners in a continuing Unix child. Native CI run 4 passed on four runners. See the release report for the limits, independent results and remediation. |

## Where the findings of AUD-010 stand

| Finding ID | Status | Fix commit | Verification commit | Evidence |
| --- | --- | --- | --- | --- |
| AUD-010-SEC001 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | Each buffer keeps the count of forks it was made under, which a handler of `pthread_atfork` raises in every child. A child of `fork` drops its parent's buffers without touching their pages, reports them as not locked, out of dumps or out of children, and ends (`abort`) before it reads or writes one. `secret_memory`: a child drops a secret, a work area and a closed secret, sees them reported as not held, ends when it reads one, and uses a secret of its own; seen failing with each of four parts of the fix removed. Run on Linux; macOS in CI. |
| AUD-010-SEC002 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | Nothing in the worker closes descriptors by range before `main`. The parent lists those the worker will inherit, open without close-on-exec, and names them in the setting; the worker closes those numbers and no other, so the descriptors its libraries opened stay theirs. `worker`: named, an inherited descriptor is closed and the start is clean; not named, it stays and the start is not. Marking them between fork and exec was tried first and dropped: that makes the standard library fork, and the C library's child then reads the records of threads on protected stacks, which are zeros there. |
| AUD-010-API001 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The field says that on Windows the confirmed protection is the network policy of the worker's AppContainer token, not a socket refused or a connection tried. |
| AUD-010-BLD001 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The fork checks require a process number above zero, wait for exactly that child and require a normal exit; the search for an inherited descriptor of secret memory covers 3 to 255. |
| AUD-010-BLD002 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | One runner for the three test programs (`tests/support/run.rs`) reports a check this system cannot make as ignored, with its reason, and a part it left as such; a role that cannot make its check exits with its own status. The check of the worker's filter options is registered on Linux only. |
| AUD-010-BLD003 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The stray client counts and holds only a pipe whose server is this process (`GetNamedPipeServerProcessId`); another program's is let go at once. Not run on Windows when this record was filed. |
| AUD-010-BLD004 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | A worker asked to linger stays 30 seconds, so within a check it ends only when it is killed. Lower bounds of time hold every time; an upper bound that fails is tried three times, in a new process where the isolation cannot be undone. |
| AUD-010-DOC001 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The README and the description of `Secret` say that WebAssembly has no guard pages. |
| AUD-010-DOC002 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The documents say that `Isolation::enter` asks Windows to leave the heap out of error reports, which it cannot read back. |
| AUD-010-DOC003 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The notices name windows-link 0.2.1. |
| AUD-010-DOC004 | fixed | `b5408a5860f47f907c6022a6258845209541fefe` | none | The errata above give the old links with the commit they belong to, and what the two AUD-009 rows describe now. |

AUD-010 found AUD-009-SEC002 and AUD-009-FUN002 open in part. At `b5408a5860f47f907c6022a6258845209541fefe` a Unix setting holds only numbers of descriptors above standard error, so any other text closes nothing before `main`; and a worker that can point its streams at neither /dev/null nor an ended pipe refuses to start, while a refused `dup2` closes the stream outright.

## Final release audits of 2747028

| Audit | Completed (UTC) | Reviewed commit | Result |
| --- | --- | --- | --- |
| [AUD-011](AUD-011-2026-11-15.md) · [JSON](AUD-011-2026-11-15.json) | 2026-11-15 | `2747028f4452c3e36f2a500eabdbc795010bf295` | Conditional pass: the findings of AUD-010, and the two of AUD-009 that it found open in part, are fixed. Four new low findings and one observation. The documented coverage was reproduced. |
| [AUD-012](AUD-012-2026-11-15.md) · [JSON](AUD-012-2026-11-15.json) | 2026-11-15 | `2747028f4452c3e36f2a500eabdbc795010bf295` | One new medium finding: the worker's cleanup before `main` closes a descriptor that a library linked to the program closed and opened again under the same number. Blocked for native integrations that allow that until it is fixed. Every other check passed; a coverage run of its own measured 91.21%. |
| [AUD-013](AUD-013-2026-11-15.md) · [JSON](AUD-013-2026-11-15.json) | 2026-11-15 | `2747028f4452c3e36f2a500eabdbc795010bf295` | Not ready to tag while the start of a worker is described as it is: it reproduces the medium finding of AUD-012 on its own, and finds the four low findings and the observation of AUD-011. The tests passed; coverage, the sanitizers and fuzzing were not run again. |

The three reviews read the same commit at the same time, and each was first numbered AUD-011. The second became AUD-012 before it was filed. The first and the third were written outside the repository under other file names: the first is filed here byte for byte, the third as AUD-013, with its own identifiers changed and nothing else. The third names the commit that filed the first two, `6c8de7ffb29161be6de4a22091371b4ec97839cd`.

## Where the findings of AUD-011 to AUD-013 stand

| Finding ID | Status | Fix commit | Verification commit | Evidence |
| --- | --- | --- | --- | --- |
| AUD-012-SEC001 | fixed | `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6` | none | Nothing in the worker closes a descriptor by its number. `Worker::start` calls `posix_spawn`, and the child closes the descriptors the worker would inherit before the program runs: by `POSIX_SPAWN_CLOEXEC_DEFAULT` on macOS, by a list made just before on Linux. `worker`: the pipes a worker holds before `main`, as the start-up code of a library sees them, include none of its parent's; seen failing against the former start. The AUD-012 harness passes; it starts its child itself, so it shows only that nothing closes a descriptor before `main`. Not run on macOS when this record was filed. |
| AUD-011-API001 | fixed | `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6` | none | `ClosedSecret::is_closed` says false in a child of `fork`. `secret_memory`: the child checks it, beside the other answers of its parent's buffers. |
| AUD-011-DOC001 | fixed | `d840951ccf709d1f892749b958cba8829bfa95ff` | none | docs/COVERAGE.md names the commit whose source it measured, `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6`, with the fingerprint of that source, and says why a run without `%c` in the name of the profile measures less, as the run of AUD-012 did (91.21%). |
| AUD-011-DOC002 | fixed | `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6` | none | The notices name enumflags2_derive 0.7.12 and thiserror-impl 2.0.21, with their licenses and authors. |
| AUD-011-BLD001 | accepted | `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6` | none | The README carries no draft banner and the changelog no draft line. `publish = false`, the `Unreleased` heading and the metadata a registry needs stay until a version is released; the crate is not published. |
| AUD-011-ARC001 | accepted | none | none | tests/worker.rs stays one file: its checks and roles share their helpers and read best together, a little over the 800 lines of code of CORE-15. |

AUD-013 found the same points: AUD-013-SEC001 stands as AUD-012-SEC001, and AUD-013-API001, AUD-013-DOC001, AUD-013-DOC002, AUD-013-BLD001 and AUD-013-ARC001 as the findings of AUD-011 of the same name. A review of the fix before it was committed found seven low points, fixed in the same commit: pipe ends at 0 to 2 are moved with `F_DUPFD_CLOEXEC`, a worker on the terminal on macOS keeps standard error only when its parent would hand it on, a setting with a trailing comma is refused on Unix, and the documents say what another thread's descriptor and a lowered descriptor limit do to a start; the standard error of both kinds of worker and a program whose standard streams are closed are checked.

## Release audit of fb2a6d3

[AUD-014](AUD-014-2026-11-15.md) and its [JSON companion](AUD-014-2026-11-15.json) verify 34 entries from AUD-008 through AUD-013. Of those entries, 21 are verified within their original scope, eight remain accepted limitations or observations and five are partly open. The new review records six Medium and ten Low findings. Five Medium findings block the unrestricted native release. The report separates the frozen code, the editorial follow-up, the four native CI results and the independently measured Linux line coverage of 97.19%.

## Verification of AUD-014 fixes

[AUD-015](AUD-015-2026-11-15.md) and its [JSON companion](AUD-015-2026-11-15.json) record fixes to 16 findings and revisit five older partial verifications. The source manifest identifies the uncommitted revision. Native Windows, macOS and Linux AArch64 acceptance is pending.
