# crashtriage

A command-line tool that reads the crash reports macOS already keeps on a Mac,
groups them by root cause, and prints a ranked triage report.

macOS writes a JSON crash report (`.ips`) every time a user-space process crashes.
After a while, the same bug is spread over many reports with different process
ids, timestamps, load addresses and app versions. `crashtriage` parses those
reports, gives every crash a **fingerprint** that stays the same for the same bug,
stores everything in SQLite, and answers "what crashes most, since when, in which
versions, and where?"

Python 3.14, standard library only (pytest for the tests). It only reads the
report folders; it never writes to them.

## Quick start

```sh
python3.14 -m venv .venv
.venv/bin/python -m pip install -e .          # optional: installs the `crashtriage` command
.venv/bin/python -m crashtriage ingest        # read ~/Library/Logs/DiagnosticReports and /Library/Logs/DiagnosticReports
.venv/bin/python -m crashtriage report        # clusters ranked by count
.venv/bin/python -m crashtriage show <fingerprint-or-incident-id>
.venv/bin/python -m crashtriage trend --weeks 8
```

| Command | What it does |
|---|---|
| `ingest [FOLDER\|FILE ...] [--symbolicate DSYM]` | Parse reports into the database (default: both DiagnosticReports folders, including `Retired/`). Re-running adds nothing new. Prints what was skipped and why. `--symbolicate` names frames from your own binaries (see below). |
| `report [--since 7d] [--process NAME] [--top N]` | Markdown table of crash clusters ranked by count, with first/last seen, versions, exception and top frame. |
| `show <id>` | One crash and its faulting thread. Takes an incident id, a unique prefix of one, or a fingerprint (shows that cluster's latest crash). |
| `trend [--weeks N] [--process NAME]` | Crashes per ISO week (UTC) per process. |

Every command takes `--json` for machine-readable output and `--db PATH`
(default `./crashtriage.db`). `report` and `trend` take `--as-of DATE` to fix
"now", so relative windows are reproducible.

## Example

`crashtriage report` on the anonymized test fixtures (selected rows of
`tests/golden/report.md`):

| # | Count | Process | Exception | First seen (UTC) | Last seen (UTC) | Versions | Top frame | Fingerprint |
|--:|--:|---|---|---|---|---|---|---|
| 1 | 3 | ct-crasher-versioned | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:15 | 2026-10-27 20:15 | 1.0, 2.0 | `ct-crasher-versioned!parse_record` | `bd6f08520a5ab6c0` |
| 2 | 3 | dotnet | EXC_CRASH / SIGABRT | 2026-10-26 22:25 | 2026-10-26 22:36 | - | `libcoreclr.dylib!PROCAbort` | `edb224fcb71d2a42` |
| 3 | 1 | ct-crasher-stripped | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:17 | 2026-10-27 20:17 | 2.0 | `ct-crasher-stripped+0x5a4` | `9cdad49681fa0325` |
| 5 | 1 | ct-crasher-swift | EXC_BREAKPOINT / SIGTRAP | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-swift!requirePositive(_:)` | `05ba8b134d2a8c04` |
| 11 | 1 | coreaudiod | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 01:59 | 2026-10-27 01:59 | 5.0 | `BTAudioHALPlugin+0x746a4` (system) | `c16751fb76f17124` |

Row 1 is one bug seen in two app versions: every address changed between 1.0
and 2.0, and the fingerprint still puts the three crashes together.

`crashtriage show bd6f08` (excerpt):

```text
## Faulting thread 0 (queue com.apple.main-thread)

4 frames. `*` marks the frames in the fingerprint.

  #  image                 offset         symbol
  0  ct-crasher-versioned  0x5a4        * parse_record + 12  (versioned.c:24)
  1  ct-crasher-versioned  0x530        * handle_request + 60  (versioned.c:38)
  2  ct-crasher-versioned  0x4e8        * main + 56  (versioned.c:44)
  3  dyld                  0x204e4        start + 6992
```

## Symbolicating your own binaries

A report names a frame only if macOS found symbols when it wrote the report. For a
stripped binary you built, keep its dSYM and pass it (or a folder of them):

```sh
crashtriage ingest --symbolicate path/to/MyTool.dSYM      # or a folder searched for *.dSYM
```

`crashtriage` reads each dSYM's UUID from its Mach-O `LC_UUID` load command, and
for every stored crash whose image has the same UUID it asks `atos` for the frames
that have no name (`atos -o <dSYM> -arch <arch> -l <load address> <addresses>`).
Named frames get the function and source line, and the crash is re-fingerprinted,
so the same bug in two stripped builds joins one cluster. It applies to every
stored crash, it only fills frames that have no name, and running it again
changes nothing. On the development Mac, the stripped crasher's two builds went
from 3 clusters to 1 (6 frames named, none unresolved).

(macOS does this by itself when Spotlight can find the dSYM: the first run of the
stripped crasher came back fully symbolicated. `NOTES.md` has the details.)

## How the fingerprint works

Two crashes get the same fingerprint when the same process died with the same
kind of exception in the same functions. Concretely:

1. Look only at the thread that crashed.
2. Throw away frames in anonymous memory, such as code generated by a JIT. Their
   addresses are different on every run, so they cannot identify anything.
3. Prefer the program's own code. Frames from macOS itself (`/System`, `/usr/lib`,
   ...) are skipped when the crash also has frames from the program, because the
   OS frames on top of a crash (`abort`, `pthread_kill`, the C++ or Swift runtime)
   are the same for unrelated bugs. If the crash never reached the program's code,
   the OS frames are used and the report says "(system)".
4. Take the top five of those frames and name each by **library and function**
   (`ct-crasher-versioned!parse_record`). Only when a frame has no function name
   is its offset used (`ct-crasher-stripped+0x528`).
5. Hash the process name, the exception type and those five names.

What is left out on purpose: load addresses, offsets inside a function, binary
UUIDs, version numbers, pids and times. They change from build to build and run
to run, and the bug does not. The full rule, and why each step exists, is in
`crashtriage/fingerprint.py` and `NOTES.md`.

## What it reads, and privacy

- Inputs: `~/Library/Logs/DiagnosticReports/` and
  `/Library/Logs/DiagnosticReports/` (and their `Retired/` subfolders), or the
  folders and files you name. Files are opened read-only; a test checks that
  ingest leaves a read-only copy of the fixtures byte-for-byte unchanged.
- Only crash reports (`bug_type` 309) are stored. Other diagnostics in the same
  folders (analytics, jetsam events, CPU and disk-write reports, panic summaries)
  are recognized and counted as skipped, with the reason.
- Unreadable files or folders are counted and listed, not fatal. On the
  development Mac, macOS refused (`EPERM`) reads of some analytics files in the
  system folder; `ingest` reports them and carries on. No sudo is needed or used.
- The database (`crashtriage.db`) stays local and is git-ignored. Real crash
  reports never enter this repo. The test fixtures are real reports passed
  through `python -m crashtriage.anonymize`, which replaces UUIDs, device and
  signer ids, MAC addresses, emails, tokens, home folders and non-OS paths.
  `tests/test_privacy.py` runs on every test run: it checks each fixture for
  identifiers that were not anonymized, and checks every file in the repo (test
  code included) for the login name, full name, hostname, home folder, and every
  UUID, MAC address and device id found in this Mac's own crash reports.

## Limitations

- **No symbolication of third-party code.** Frames are named only if the report
  already names them or you have the binary's dSYM (`--symbolicate`). Without
  one, a stripped binary shows offsets, and offsets move between builds, so the
  same bug in two unsymbolicated builds gets two fingerprints
  (`ct-crasher-stripped` in the example). Frames named by `atos` have no
  "offset within the function" (`+ 12`); the fingerprint does not use it anyway.
- **User-space crash reports only.** Kernel panics, hangs, spins, jetsam
  (memory pressure) events and CPU or disk-write reports are skipped, as is the
  old plain-text crash format.
- **Managed runtimes look alike.** For .NET, the frames that would tell two
  managed bugs apart are JIT frames without names, so every unhandled exception
  in the same runtime lands in one cluster.
- **Crashes entirely inside macOS** are identified by offsets in Apple's stripped
  libraries, so they will split across macOS updates.
- **Built and tested on one machine** (macOS 26.6.2, Apple silicon) with 19 real
  crash reports, 13 of which came from the small crash programs in `crashers/`.
  The report format is undocumented, so `NOTES.md` records what was observed.

## Development

```sh
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pytest                        # unit, golden-output, privacy and defect tests
.venv/bin/python scripts/mutation_check.py        # breaks the code on purpose; every break must fail a test
crashers/build.sh && crashers/run.sh              # build and run the crash programs (makes real crash reports)
```

Golden files in `tests/golden/` are refreshed with
`UPDATE_GOLDEN=1 .venv/bin/python -m pytest tests/test_cli.py` after an
intended output change.

| Path | Contents |
|---|---|
| `crashtriage/parser.py` | `.ips` file to typed record, or a skip with a reason |
| `crashtriage/fingerprint.py` | the fingerprint rule |
| `crashtriage/store.py` | SQLite schema, idempotent ingest, round trip back to records |
| `crashtriage/report.py`, `cli.py` | the `report`, `show` and `trend` commands |
| `crashtriage/symbolicate.py` | Mach-O UUID reader and `atos` symbolication |
| `crashtriage/anonymize.py` | makes commit-safe copies of real reports |
| `crashers/` | small C, C++ and Swift programs that crash in distinct ways |
| `tests/fixtures/` | anonymized real reports (provenance in its README) |
| `NOTES.md` | decisions, observed format, counts, open questions |
