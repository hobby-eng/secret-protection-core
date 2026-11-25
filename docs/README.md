# secret-protection-core documentation

For a summary of the crate and its supported targets, see the [library overview](../README.md).

## Using the library

| Guide                                   | What to use it for                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------- |
| [API description](API.md)               | Public Rust functions and methods by type, arguments, results, errors and code examples.    |
| [Platform implementation](TECHNICAL.md) | Check what each platform can confirm about memory, process restrictions and worker startup. |
| [Security](../SECURITY.md)              | Decide which threats the library covers and where the application takes responsibility.     |

## Testing and project records

| Document                                         | What to use it for                                                                      |
| ------------------------------------------------ | --------------------------------------------------------------------------------------- |
| [Test coverage](COVERAGE.md)                     | Read the per-file Linux results or reproduce the measurement for a particular revision. |
| [Targets and audit notes](audits/TARGETS.md)     | See which targets an audit builds and runs, on which runner, and its fuzzing budgets.   |
| [Audit reports](audits/README.md)                | Trace a finding to the reviewed source, its fix and the evidence for that fix.          |
| [Changelog](../CHANGELOG.md)                     | Check which protections and API behavior changed.                                       |
| [Third-party notices](../THIRD_PARTY_NOTICES.md) | Look up dependency licenses.                                                            |
