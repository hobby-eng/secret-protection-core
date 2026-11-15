# Audits

| Audit | Completed (UTC) | Reviewed commit | Scope | Findings at the reviewed commit |
| --- | --- | --- | --- | --- |
| [AUD-001](AUD-001-2026-11-15.md) · [JSON](AUD-001-2026-11-15.json) | 2026-11-15 | `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca` | Secret memory, process isolation and worker IPC | 22: 5 high, 11 medium, 6 low |
| [AUD-002](AUD-002-2026-11-15.md) · [JSON](AUD-002-2026-11-15.json) | 2026-11-15 | `60adba5b2f2d144ccdd61cb4829e8e5abc9bc1ca` | Full crate security review with Linux runtime probes and six-target compilation | 6: 1 high, 3 medium, 2 low |

Both reviews read the same commit at the same time, and both were first written as AUD-001, the second over the first. The first report is restored byte for byte: its SHA-256 is the one its own validation recorded. Its JSON companion could not be recovered and was rebuilt from the report, as the file itself says. The second report became AUD-002 before publication: its identifiers and paths changed, nothing else.

The reports record the findings as they stood at the reviewed commit. The fixes follow in later commits, and each report gets their status once they are verified.

Audit evidence folders are machine-local and ignored by Git. The harnesses are kept beside the reports so that each check can be run again.
