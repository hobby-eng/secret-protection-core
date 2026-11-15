# Findings and verification

[Audit catalogue](README.md) · [Native verification](#native-verification-after-aud-015) · [Corrections to the original records](#corrections-to-earlier-records)

Each ID below belongs to its original report. The status is the latest finding-specific disposition on record. A check mark means the cited verification covered that case. For a pending verification the fix commit is known, but the recorded checks do not establish the full case.

| Finding ID | Status | Fix commit | Verification commit | Evidence |
| --- | --- | --- | --- | --- |
| AUD-001-API001 | ✅ verified | `0b0aa7f` | `39e462e` | The unmarked lock yielded an unknown result in the Linux regression. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-API002 | ✅ verified | `960647c` | `c57018a` | Unreadable descriptors marked the Linux inventory incomplete. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-API003 | fixed · verification pending | `960647c` | — | Each measure carries the words of its own outcome. The Windows read-backs were not run. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-DOC001 | ✅ verified | `960647c` | `c57018a` | The serializer wipes its scratch buffer on drop. Encoding and redacted debug output passed on Linux. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-DOC002 | ✅ verified | `960647c` | `c57018a` | The documentation limits the wipe to owned buffers and acknowledges abrupt termination. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-FUN001 | ✅ verified | `960647c` | `c57018a` | The parent closed its pipes after rejecting a 4 MiB reply. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-FUN002 | fixed · verification pending | `c57018a` | — | The worker is started from a thread with an ordinary stack. `worker`: a worker starts from a protected stack. The `fork` path of an old C library was not run. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-FUN003 | ✅ verified | `960647c` | `c57018a` | The Linux regression returned an error for an oversized stack. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-FUN004 | fixed · verification pending | `960647c` | — | The lock flag comes from the C library's own definition. No architecture with another value was run. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-FUN005 | fixed · verification pending | `960647c` | — | A work area is locked whenever Windows takes the lock. The original Windows case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-FUN006 | fixed · verification pending | `960647c` | — | The attribute list is deleted only when it was initialized. The original Windows case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-SEC001 | ✅ verified | `c57018a` | `c57018a` | Late first use selected anonymous pages. The Linux review also exercised the registered fork gate. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC002 | ✅ verified | `960647c` | `c57018a` | Failed enumeration, detachment and early worker death each prevented a request. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC003 | ✅ verified | `960647c` | `c57018a` | The Linux check detected a tracer on a sibling thread in the same PID namespace. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC004 | ✅ verified | `2f28cb3` | `39e462e` | Windows launched an AppContainer worker without handle inheritance and checked the pipe client PID. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-SEC005 | fixed · verification pending | `960647c` | — | A refused probe counts only with this crate's sandbox profile in place. The original macOS case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-001-SEC006 | ✅ verified | `960647c` | `c57018a` | Linux tests distinguished the self-only filter from the Landlock signal scope. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC007 | ✅ verified | `960647c` | `c57018a` | The Linux parser distinguished a failed speculation query from a disabled mechanism. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC008 | ✅ verified | `960647c` | `c57018a` | The callback did not run on a stack that failed its required lock check. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC009 | ✅ verified | `960647c` | `c57018a` | Miri exercised the wipe of uninitialized stack bytes. Release x86-64 machine code retained the zero writes. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC010 | ✅ verified | `960647c` | `c57018a` | Refused page transitions preserved earlier permissions. The WASM check reported the pages as open. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-001-SEC011 | fixed · verification pending | `960647c` | — | The dynamic-code policy holds only without a way out for a thread or another process. The original Windows case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-002-API001 | ✅ verified | `960647c` | `c57018a` | An oversized stack request returned an error. [AUD-010](AUD-010-2026-11-15.md) · [AUD-007](AUD-007-2026-11-15.md) |
| AUD-002-DOC001 | ✅ verified | `960647c` | `c57018a` | The review checked the corrected test counts and scope of planned work. [AUD-010](AUD-010-2026-11-15.md) · [AUD-007](AUD-007-2026-11-15.md) |
| AUD-002-FUN001 | ✅ verified | `960647c` | `c57018a` | The oversized-reply regression completed worker teardown. [AUD-010](AUD-010-2026-11-15.md) · [AUD-007](AUD-007-2026-11-15.md) |
| AUD-002-SEC001 | ✅ verified | `960647c` | `c57018a` | Worker admission refused a failed check for inherited descriptors. [AUD-010](AUD-010-2026-11-15.md) · [AUD-007](AUD-007-2026-11-15.md) |
| AUD-002-SEC002 | ✅ verified | `960647c` | `c57018a` | The Linux namespace check observed IPC isolation as well as network isolation. [AUD-010](AUD-010-2026-11-15.md) · [AUD-007](AUD-007-2026-11-15.md) |
| AUD-002-SEC003 | fixed · verification pending | `960647c` | — | The Windows measures are read back and have fields of their own. The original Windows case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-003-API001 | ✅ verified | `c57018a` | `c57018a` | Linux retried a refused Landlock layer and avoided stacking it again after success. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-003-BLD001 | ✅ verified | `c57018a` | `c57018a` | ASan passed 53 checks. Four lock-sensitive cases were excluded. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-003-DOC001 | ✅ verified | `c57018a` | `c57018a` | The documented seccomp marker and option bits matched the source. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-003-FUN001 | fixed · verification pending | `c57018a` | — | A kill that fails is not waited for, and both waits are bounded. `worker`: the program that may not signal others. The Windows code was not run. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-003-SEC001 | ✅ verified | `c57018a` | `c57018a` | A foreign policy denying a probe could no longer confirm the crate’s own filter. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-003-SEC002 | ✅ verified | `c57018a` | `c57018a` | The nested PID namespace case returned Unknown for an outside tracer. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-003-SEC003 | ✅ verified | `0b0aa7f` | `39e462e` | The Linux jobs checked signal-filter ownership across threads and a fork. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-004-API001 | fixed · verification pending | `c57018a` | — | One sandbox call at a time, and a success never goes back to false. The original macOS case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-004-API002 | fixed · verification pending | `c57018a` | — | The exception for secure processes counts as a way out of the child-process policy. The original Windows case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-004-DOC001 | ✅ verified | `c57018a` | `c57018a` | A refused page closure and a WASM run both matched the documented is_closed contract. [AUD-010](AUD-010-2026-11-15.md) · [AUD-006](AUD-006-2026-11-15.md) |
| AUD-004-SEC001 | ✅ verified | `0b0aa7f` | `39e462e` | The Windows API documents the default DLL search and per-load overrides. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-005-DOC001 | fixed · verification pending | `c57018a` | — | The job's limits of the desktop and its one process are read back together. The original Windows case awaits independent verification. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-006-BLD001 | ✅ verified | `0b0aa7f` | `39e462e` | The namespace test required a successful inner fork and a matching wait result. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-006-DOC001 | ✅ verified | `0b0aa7f` | `39e462e` | Terminal mode preserves access to the terminal. The application must handle echo. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-006-DOC002 | ✅ verified | `0b0aa7f` | `39e462e` | The guide distinguished a failed file-change check from a refused socket probe. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-006-FUN001 | fixed · verification pending | `0b0aa7f` | — | A worker is ended once: `end`, a failed call and the drop share one wait. `worker`: one second, not two, where the worker cannot be killed. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-006-FUN002 | ✅ verified | `0b0aa7f` | `39e462e` | The allocation regression fell back when the thread could not block signals. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-006-SEC001 | fixed · verification pending | `0b0aa7f` | — | What a worker inherited is closed before its `main`; `serve` closes nothing and runs once. `worker`: the program with a file of its own, the second call of `serve`. [AUD-010](AUD-010-2026-11-15.md) |
| AUD-008-API001 | ✅ verified | `a4fd4c5` | `3d914c8` | The worker settings parser rejected noncanonical and malformed inputs. [AUD-015](AUD-015-2026-11-15.md) · [Windows CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323/job/132907272414) |
| AUD-008-FUN001 | ✅ verified | `0b0aa7f` | `fb2a6d3` | An owned handle closes the Windows client endpoint when service ends. Native CI exercised normal shutdown. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-008-SEC001 | accepted | `0b0aa7f` | — | Another process of the same user may connect before the worker. Its PID cannot satisfy admission. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-FUN001 | ✅ verified | `bebf3ff` | `fb2a6d3` | The Apple initializer had an explicit section type. Native macOS CI exercised startup. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-FUN002 | ✅ verified | `b5408a5` | `fb2a6d3` | Linux used an ended pipe without /dev/null and refused startup if neither sink was available. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-SEC001 | ✅ verified | `bebf3ff` | `fb2a6d3` | Unix rejected a startup it could not inventory. AUD-014-API001 later corrected which thread’s table it inspected. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-SEC002 | ✅ verified | `b5408a5` | `fb2a6d3` | The Unix constructor no longer closes descriptors on the strength of an environment string. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-SEC003 | accepted | `bebf3ff` | — | Repeated pipe contention by a local process can prevent worker startup. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-SEC004 | accepted | `bebf3ff` | — | Anonymous secret pages request small pages. The OS may refuse the advice; large work areas keep their normal policy. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-SEC005 | ✅ verified | — | `fb2a6d3` | Separately allocated secrets had distinct guarded mappings. Opening one left its neighbour unchanged. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-009-SEC006 | accepted | — | — | Allocating a Secret does not enter isolation. The caller must enter it before accepting secret input. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-API001 | ✅ verified | `b5408a5` | `fb2a6d3` | The public Windows contract matched the AppContainer token check. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-BLD001 | ✅ verified | `b5408a5` | `fb2a6d3` | The affected fork tests required a positive PID and checked the matching child’s exit status. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-BLD002 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The nested role communicates separate reasons for unavailable locking and namespace creation. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-010-BLD003 | ✅ verified | `b5408a5` | `fb2a6d3` | The Windows competing-client test checked the expected server PID before attributing its result. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-BLD004 | ✅ verified | `a4fd4c5` | `e7b0d38` | A FIFO controlled the worker’s exit. macOS checked the worker was alive at the deadline and later collected. [AUD-015](AUD-015-2026-11-15.md) · [macOS CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745920704/job/132909063540) |
| AUD-010-DOC001 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The WorkArea rustdoc and technical guide describe WASM heap allocation. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-010-DOC002 | ✅ verified | `b5408a5` | `fb2a6d3` | The docs describe Windows heap exclusion as a WER request without readback. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-DOC003 | ✅ verified | `b5408a5` | `fb2a6d3` | The windows-link notice matched version 0.2.1 in the lockfile. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-DOC004 | ✅ verified | `b5408a5` | `fb2a6d3` | The errata identified the revisions with the original test paths and behavior. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-010-SEC001 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The transient guard and the owning allocation both check the fork generation. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-010-SEC002 | ✅ verified | `b5408a5` | `fb2a6d3` | The worker constructor no longer closes a descriptor number reused by a library. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-011-API001 | ✅ verified | `9e08979` | `fb2a6d3` | An inherited ClosedSecret returned false from is_closed in the forked child. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-011-ARC001 | accepted | — | — | The original file-size exception was accepted. The worker test was later split at a4fd4c5. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-011-BLD001 | accepted | `9e08979` | — | Distribution uses Git. The package has publish = false. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-011-DOC001 | ✅ verified | `d840951` | `fb2a6d3` | The published coverage counts matched the source manifest of the measured revision. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-011-DOC002 | ✅ verified | `9e08979` | `fb2a6d3` | The notices named both build-time macro crates found in the lockfile. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-012-SEC001 | ✅ verified | `9e08979` | `fb2a6d3` | Startup left the library’s replacement descriptor open. The separate enumeration issue was tracked as AUD-014-SEC002. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-013-API001 | ✅ verified | `9e08979` | `fb2a6d3` | An inherited ClosedSecret returned false from is_closed in the forked child. Same case as AUD-011-API001. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-013-ARC001 | accepted | — | — | The original file-size exception was accepted. The worker test was later split at a4fd4c5. Also recorded as AUD-011-ARC001. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-013-BLD001 | accepted | `9e08979` | — | Distribution uses Git. The package has publish = false. Also recorded as AUD-011-BLD001. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-013-DOC001 | ✅ verified | `d840951` | `fb2a6d3` | The published coverage counts matched the source manifest of the measured revision. Same case as AUD-011-DOC001. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-013-DOC002 | ✅ verified | `9e08979` | `fb2a6d3` | The notices named both build-time macro crates found in the lockfile. Same case as AUD-011-DOC002. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-013-SEC001 | ✅ verified | `9e08979` | `fb2a6d3` | Startup left the library’s replacement descriptor open. The separate enumeration issue was tracked as AUD-014-SEC002. Same case as AUD-012-SEC001. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-014-API001 | ✅ verified | `a4fd4c5` | `a4fd4c5` | open_channels and startup inspect the calling thread’s table. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-API002 | ✅ verified | `a4fd4c5` | `a4fd4c5` | Linux integer arguments use libc::c_ulong in variadic slots. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-ARC001 | accepted | — | — | The original file-size exception was accepted. The worker test was later split at a4fd4c5. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-014-BLD001 | ✅ verified | `a4fd4c5` | `a4fd4c5` | Affected parents wait for a positive PID, retry EINTR, require a matching wait result and distinguish normal child exit from a signal. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-BLD002 | ✅ verified | `a4fd4c5` | `a4fd4c5` | Memory-lock refusal and refusal of a second namespace now produce distinct partial-check reasons. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-BLD003 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The channel test uses exclusive creation. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-BLD004 | ✅ verified | `a4fd4c5` | `a4fd4c5` | Linux tests expect Confirmed in the initial PID namespace and Unknown where an external tracer is invisible. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-BLD005 | accepted | — | — | Git distribution does not establish registry publication or a versioned release. [AUD-014](AUD-014-2026-11-15.md) |
| AUD-014-BLD006 | ✅ verified | `a4fd4c5` | `3d914c8` (CI), `f0ae463` (RustSec) | CI checks fuzz formatting and lints, and passes each lockfile to RustSec. [AUD-015](AUD-015-2026-11-15.md) · [CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323) · [RustSec](https://github.com/hobby-eng/secret-protection-core/actions/runs/43744780442) |
| AUD-014-BLD007 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The crate selects panic=abort, LTO and one code-generation unit for standalone releases. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-DOC001 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The technical guide and public rustdoc distinguish protected native allocations, heap-backed WASM buffers, inherited references and guarded cleanup. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-FUN001 | ✅ verified | `a4fd4c5` | `e7b0d38` | The library collected a worker that outlived the shutdown deadline. [AUD-015](AUD-015-2026-11-15.md) · [macOS CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745920704/job/132909063540) |
| AUD-014-SEC001 | ✅ verified | `a4fd4c5` | `a4fd4c5` | The permission guard checks its mapping generation before mprotect. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-SEC002 | ✅ verified | `a4fd4c5` | `3d914c8` | Linux and macOS closed inherited descriptors before startup. [AUD-015](AUD-015-2026-11-15.md) · [native CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323) |
| AUD-014-SEC003 | ✅ verified | `a4fd4c5` | `3d914c8` | Only a stable kernel handle permits forced termination. macOS uses cooperative shutdown. [AUD-015](AUD-015-2026-11-15.md) · [native CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323) |
| AUD-014-SEC004 | ✅ verified | `a4fd4c5` | `a4fd4c5` | Both sides require whole-process isolation. [AUD-015](AUD-015-2026-11-15.md) |
| AUD-014-SEC005 | ✅ verified | `3d914c8` | `3d914c8` | A low primary token with a higher-integrity sibling failed the worker integrity check. [AUD-015](AUD-015-2026-11-15.md) · [Windows CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323/job/132907272414) |
| AUD-014-SEC006 | ✅ verified | `a4fd4c5` | `3d914c8` | The retained handle had exactly wait and termination rights. [AUD-015](AUD-015-2026-11-15.md) · [Windows CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323/job/132907272414) |
| AUD-014-SEC007 | accepted | — | — | Existing Windows handles retain rights. A Linux seccomp marker cannot authenticate an adversarial host policy. [AUD-014](AUD-014-2026-11-15.md) |

## Native verification after AUD-015

All 38 SHA-256 entries in the [AUD-015 source manifest](AUD-015-2026-11-15.json) match `a4fd4c5`. That identifies the local checks on the initially uncommitted fixes. The following runs supplied the native results still pending in the report.

Windows passed 41 checks. The strict AppContainer worker answered a public request. A separate process held an above-low impersonation token on a sibling while the primary token was low and its parent supplied the thread list. The integrity check refused the process. The handle-rights test confirmed that the launcher retains only synchronization and termination rights on the worker process. [Windows CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323/job/132907272414)

macOS passed 44 checks, including descriptor cleanup before startup, cooperative shutdown and a false return from `end()` while the test held the worker’s exit FIFO open. Linux x86-64 and ARM64 each ran 84 checks. Both hosted Linux runners refused creation of a second PID namespace. The nested lock-ownership check ran in full on local x86-64 Linux. Clippy passed on the host and all configured targets. Both RustSec jobs passed on the preceding revision with identical manifests and lockfiles. [Native CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745335323) · [RustSec](https://github.com/hobby-eng/secret-protection-core/actions/runs/43744780442) · [Linux coverage](../COVERAGE.md)

At `e7b0d38fba46e45994cd8e7ecbdda185de9cee70`, the macOS test also verified that the worker was still alive at the shutdown deadline and that the library collected its exit status after the parent released it. The test observed the process with `waitid(WNOWAIT)`, leaving collection to the library. All four CI jobs passed on that revision. [Final native CI](https://github.com/hobby-eng/secret-protection-core/actions/runs/43745920704)

## Corrections to earlier records

- AUD-001 links to `tests/isolation.rs` (lines 868 and 880). That file was later split into `tests/isolation/main.rs` and its modules; the lines are those of the commit AUD-001 reviewed, published as [8081d01](https://github.com/hobby-eng/secret-protection-core/blob/8081d010b8040483d3ede458f522fad0fa81c571/tests/isolation.rs#L868).
- The original AUD-009-FUN002 fix record said that the two descriptors are closed outright where /dev/null cannot be opened. Since `e529376` they are pointed at the read end of an ended pipe instead, so that their numbers stay taken; since the fixes of AUD-010 a worker that can have neither refuses to start.
- The original AUD-009-SEC002 fix record described the function that runs before `main` as closing the descriptors above standard error. Since the fixes of AUD-010 it closes only those its parent names in the setting, so that descriptors the program's libraries opened before it stay theirs.
- The rows of AUD-006-SEC001, AUD-009-SEC002 and AUD-010-SEC002, the erratum above and the original AUD-010 fix register describe a function that runs before `main` and closes descriptors. Since the fixes of AUD-012, at `9e0897994b3c16ab1e07b8021ca8fce9fe4a5ad6`, nothing in the worker closes a descriptor: `posix_spawn` closes those the worker would inherit in the child, before the program runs, and that function only counts forks.

- The AUD-002 inherited-descriptor example bind-mounts the host root and substitutes a synthetic `/proc`. Its harness prints PASS when the worker starts with its socket closed. A startup refusal also prevents use of that socket, but the harness returns an error for that path. Its IPC check compares IPC namespace inodes and uses the crate’s own network report. On Windows the stack-size harness also accepts an unsupported result.
- The AUD-005 signal harness requires the specific outcome Refused. A nonzero exit also covers failure to install the test policy or start its subprocess. The AUD-012 harness prints FAIL when a descriptor was closed or replaced. Its other error exits can indicate a setup failure. Read the diagnostic alongside the exit code.

## Original and published commits

Both reviewers examined the same revision. Their reports originally shared the number AUD-001. The first report and its original JSON were recovered and verified by SHA-256. Commit `22855bf` contains an interim JSON reconstruction. The second report was renumbered AUD-002.

AUD-001 and AUD-010 now describe the applications they mention by role. To verify the SHA-256 values recorded in AUD-014, use the [original Markdown and JSON files at `e7b0d38`](https://github.com/hobby-eng/secret-protection-core/tree/e7b0d38fba46e45994cd8e7ecbdda185de9cee70/docs/audits).

The three reviews read the same commit at the same time, and each was first numbered AUD-011. The second became AUD-012 before it was filed. The first and the third were written outside the repository under other file names: the first is filed here byte for byte, the third as AUD-013, with its own identifiers changed and nothing else. The third names the commit that filed the first two, `6c8de7ffb29161be6de4a22091371b4ec97839cd`.

The reports AUD-001 to AUD-008 name commits by the hashes these had in the draft history, before it was published. The published commits hold the same trees; their dates are written in UTC, and their messages name the published commits. The index uses the published hashes, and so does AUD-009.

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
