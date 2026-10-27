# Test fixtures

Every file here is a copy of a real diagnostic report from the development Mac,
passed through `python -m crashtriage.anonymize` (see that module for exactly what
it removes). All files were anonymized in one run with a random salt that was not
saved, so anonymized UUIDs are consistent across fixtures but cannot be traced back.
`tests/test_privacy.py` re-checks every file on each test run.

| Fixture | Source | Exception | Extra step |
|---|---|---|---|
| `coreaudiod-segv.ips` | coreaudiod, system folder `Retired/` | EXC_BAD_ACCESS / SIGSEGV | |
| `dotnet-abort-a.ips` | dotnet, user folder `Retired/` | EXC_CRASH / SIGABRT | |
| `dotnet-abort-b.ips` | dotnet (same bug as `-a`, different run) | EXC_CRASH / SIGABRT | |
| `dotnet-abort-long.ips` | dotnet (the `.000` report, longer stack) | EXC_CRASH / SIGABRT | |
| `crasher-segv.ips` | `crashers/src/segv.c` | EXC_BAD_ACCESS / SIGSEGV | |
| `crasher-bus.ips` | `crashers/src/bus.c` | EXC_BAD_ACCESS / SIGBUS | |
| `crasher-trap.ips` | `crashers/src/trap.c` | EXC_BREAKPOINT / SIGTRAP | |
| `crasher-swift.ips` | `crashers/src/fatal.swift` | EXC_BREAKPOINT / SIGTRAP | |
| `crasher-overflow.ips` | `crashers/src/overflow.c` | EXC_BAD_ACCESS / SIGSEGV | |
| `crasher-throw.ips` | `crashers/src/throw.cpp` | EXC_CRASH / SIGABRT | |
| `crasher-versioned-v1a.ips`, `-v1b.ips` | `versioned.c`, version 1.0, two runs | EXC_BAD_ACCESS / SIGSEGV | |
| `crasher-versioned-v2.ips` | `versioned.c`, version 2.0 | EXC_BAD_ACCESS / SIGSEGV | |
| `crasher-stripped-v1.ips`, `-v2.ips` | `versioned.c` stripped, 1.0 and 2.0 | EXC_BAD_ACCESS / SIGSEGV | |
| `malformed-truncated.ips` | dotnet crash report | (malformed) | `--truncate-bytes 4096` |
| `noncrash-jetsam.ips` | JetsamEvent, bug_type 298 | (not a crash) | `--max-list-items 3` |
| `noncrash-text.diag` | "cpu usage" text report | (not an .ips document) | `--truncate-bytes 700` |

The `crasher-*` reports were produced by running the programs in `crashers/`
(`crashers/build.sh`, then `crashers/run.sh`); macOS wrote them like any other crash.

To add a fixture:

```sh
.venv/bin/python -m crashtriage.anonymize ~/Library/Logs/DiagnosticReports/<file>.ips tests/fixtures/<name>.ips
.venv/bin/python -m pytest tests/test_privacy.py
```
