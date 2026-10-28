# NOTES

Working notes for `crashtriage`, kept as the project goes: decisions, what the real
data looked like, counts measured on the development Mac, open questions, and anything
I was unsure about. Process names appear; usernames, paths, hostnames and incident ids
do not.

## Environment

| Item | Value |
|---|---|
| Interpreter | CPython 3.14.8 (`/opt/homebrew/bin/python3.14`), repo-local `.venv` |
| Test runner | pytest 9.1.1 (pinned in `requirements.txt`; the only non-stdlib dependency) |
| OS | macOS 26.6.2 (build 25G83), Apple silicon (`arm64e`) |
| Date of Phase 0 survey | 2026-10-27 |

## Phase 0: what the data really looks like

### Access

- `~/Library/Logs/DiagnosticReports` is owned by the user, mode `0700`.
- `/Library/Logs/DiagnosticReports` is `root:_analyticsusers`, mode `0770`. The
  development account is in `_analyticsusers` (admin accounts are), so every file was
  readable without sudo. An account outside that group gets `PermissionError` on the
  whole system folder; the tool has to count that and keep going.
- Both folders have a `Retired/` subfolder; the system folder also has an empty
  `DiagnosticLogs/` subfolder. One file is hidden (`.contents.panic`).

### Counts (82 files)

| Folder | Extension | Header `bug_type` | Files | Content |
|---|---|---|---|---|
| user, top level | `.diag` | `"226"` | 20 | JSON header + JSON body (`events`, `postTime`) |
| user, top level | `.diag` | `"303"` | 14 | JSON header + protobuf-style **text** body |
| user, `Retired/` | `.ips` | `"309"` | 5 | **crash** (dotnet) |
| system, top level | `.diag` | (none) | 29 | plain **text** microstackshot reports: 19 "disk writes", 10 "cpu usage" |
| system, top level | `.panic` | (none) | 1 | a single JSON object (`panic_string`, `log_path`, ...); no body; `log_path` names a file that no longer exists |
| system, `Retired/` | `.ips` | `"298"` | 4 | JetsamEvent (JSON header + JSON body, not a crash) |
| system, `Retired/` | `.ips` | `"309"` | 1 | **crash** (coreaudiod) |
| system, `Retired/` | `.core_analytics` | `"211"` | 8 | JSON header + newline-delimited JSON |

Only **6 crash reports** exist on this machine: 5 from `dotnet` and 1 from `coreaudiod`,
with 2 exception types (`EXC_CRASH`/`SIGABRT` and `EXC_BAD_ACCESS`/`SIGSEGV`). All six
were already in `Retired/`, none at the top level. No `.spin`, `.hang` or `.wakeups`
files were present. The `bug_type` meanings (309 crash, 298 jetsam, 211 analytics) are
inferred from the file contents, not from Apple documentation.

### Where the real format differed from the brief

1. **`bug_type` is a string** (`"309"`, not `309`). The body repeats it.
2. **The extension does not identify a crash.** `.ips` also holds `298` Jetsam reports,
   so classification must use the header's `bug_type`, never the extension.
3. **Not every file is "header line + JSON body".** System `.diag` files are pure text
   (first line `Date/Time: ...`), the `.panic` file is one JSON object, `core_analytics`
   bodies are NDJSON, and `303` bodies are protobuf-style text.
4. **The header has no pid, exception or process path.** Those live in the body. The
   process name in the header is `app_name` and `name` (both equal in every file seen).
5. **`app_version` can be an empty string** (all five dotnet reports). An empty string
   has to be treated as "unknown", not as a version. `coreaudiod` also has
   `bundleInfo.CFBundleShortVersionString` in the body.
6. **No `sourceFile` / `sourceLine`** on any frame in any file.
7. **Anonymous images.** dotnet reports contain a `usedImages` entry with `source: "A"`,
   no `name`, no `path`, `base: 0`, `size: 0`. Frames pointing at it are .NET JIT code;
   their `imageOffset` is an absolute address (base 0), which changes every run.
8. **A thread queue name contains a Bluetooth MAC address**
   (`com.apple.audio.device.<MAC>:output.event`). The brief's privacy list did not
   mention MAC addresses; the anonymizer has to scrub them anywhere in the document.
9. When two reports for the same process land in the same second, the second one gets
   a `.000.ips` suffix (`<proc>-<date>.000.ips`).

### Crash report schema (bug_type 309), as observed

**Line 1, header object (13 keys):** `app_name`, `app_version`, `build_version`,
`bug_type`, `incident_id`, `is_first_party`, `name`, `os_version` (e.g.
`"macOS 26.6.2 (25G83)"`), `platform`, `roots_installed`, `share_with_app_devs`,
`slice_uuid`, `timestamp` (`"YYYY-MM-DD HH:MM:SS.ss ±HHMM"`, local time with offset).

**Rest of file, body object (54-56 keys).** The fields the tool uses:

| Field | Shape |
|---|---|
| `procName`, `procPath`, `pid`, `parentProc`, `responsibleProc` | strings / int |
| `cpuType` | `"ARM-64"` |
| `captureTime`, `procLaunch` | `"YYYY-MM-DD HH:MM:SS.ssss ±HHMM"` |
| `osVersion` | `{train, build, releaseType}` |
| `bundleInfo` | `{CFBundleVersion, CFBundleShortVersionString}` (optional) |
| `incident` | same UUID as header `incident_id` |
| `exception` | `{type, signal, subtype?, codes, rawCodes}` |
| `termination` | `{namespace, code, indicator, byProc, byPid, flags}` |
| `asi` | `{image: [messages]}`, e.g. `abort() called` (optional) |
| `faultingThread` | integer index into `threads` |
| `threads[]` | `{id, frames[], threadState, name?, queue?, triggered?}` |
| `frames[]` | `{imageIndex, imageOffset, symbol?, symbolLocation?}` |
| `usedImages[]` | `{source "P"/"A", arch?, base, size, uuid, name?, path?, CFBundleIdentifier?, CFBundleShortVersionString?, CFBundleVersion?}` |

The body also contains identifying fields the tool does not need and the anonymizer
must remove: `crashReporterKey`, `bootSessionUUID`, `sleepWakeUUID`, `userID`,
`trialInfo`, `codeSigningTeamID`, plus paths inside `procPath`, `vmregioninfo` and
`usedImages[].path`.

### Faulting thread versus the others

- Only the faulting thread has `triggered: true`. In all 6 files its index equals
  `faultingThread`.
- Every thread has `threadState` (`ARM_THREAD_STATE64`: `x[]`, `fp`, `lr`, `sp`, `pc`,
  `cpsr`, `far`, `esr`), not just the faulting one.
- Non-faulting threads are parked in the kernel: frame 0 is a wait trap
  (`mach_msg2_trap`, `__psynch_cvwait`, `__psynch_mutexwait`, `semaphore_wait_trap`,
  `poll`, `read`, `__open`).

### Symbol coverage (measured)

| Crash | Threads | Images | Faulting frames | Symbolized | Anonymous (JIT) | Named but unsymbolized |
|---|---|---|---|---|---|---|
| coreaudiod (SIGSEGV) | 30 | 23 | 20 | 17 | 0 | 3 (`BTAudioHALPlugin`, frames 0-2) |
| dotnet `.000` (SIGABRT) | 15 | 18 | 41 | 27 | 14 | 0 |
| dotnet x4 (SIGABRT) | 13-14 | 18 | 35 | 26 | 9 | 0 |

Across all threads of all 6 crashes: 810 frames, 740 with `symbol` and
`symbolLocation`, 70 with only `imageIndex` and `imageOffset`. The unsymbolized frames
are either in a stripped Apple plugin or in anonymous JIT memory.

### Early evidence for the fingerprint design

Four of the five dotnet crashes have an identical faulting stack when frames are
compared as (image name, symbol) with JIT frames dropped. Hashed by raw
`imageOffset`, all five are different, because the JIT frames carry per-run absolute
addresses. A naive offset hash would report one bug as several.

## Decisions

- **Classify by header `bug_type`.** `309` is a crash. A JSON header with any other
  `bug_type` is a known non-crash type, skipped with a reason. A file whose first line
  is not JSON is skipped as "not an .ips document". Legacy text crash reports
  (`bug_type` 109) were not seen and are skipped as unsupported.
- **Python 3.14 standard library only** (`json`, `sqlite3`, `argparse`, `hashlib`,
  `dataclasses`); pytest for tests.
- **Read only.** Input files are opened with mode `"rb"` and nothing else.
- **Crasher programs.** Because the machine had only 2 exception types, small C/C++/
  Swift programs under `crashers/` produce real reports for more crash types. Running
  them makes macOS write new `.ips` files into the user DiagnosticReports folder; no
  existing file is touched. Approved before doing it.
- **`/usr/local` is not "system".** It holds user-installed software (dotnet lives
  there), so its paths are redacted by the anonymizer and its frames count as app frames
  for fingerprinting.

## Phase 1: crashers, parser, anonymizer

### Crasher programs (approved before running)

`crashers/build.sh` builds eight small programs with dSYMs; `crashers/run.sh` runs
them. macOS wrote one report per crash into `~/Library/Logs/DiagnosticReports` (13
new files in total, counting a second run of the two stripped builds). Results:

| Program | Exception / signal | Subtype | Faulting frames |
|---|---|---|---|
| `ct-crasher-segv` | EXC_BAD_ACCESS / SIGSEGV | KERN_INVALID_ADDRESS at 0x0 | 3 |
| `ct-crasher-bus` | EXC_BAD_ACCESS / **SIGBUS** | KERN_PROTECTION_FAILURE | 3 |
| `ct-crasher-trap` | EXC_BREAKPOINT / SIGTRAP | (none) | 3 |
| `ct-crasher-swift` | EXC_BREAKPOINT / SIGTRAP | (none) | 4, top one in `libswiftCore` |
| `ct-crasher-overflow` | EXC_BAD_ACCESS / SIGSEGV | KERN_PROTECTION_FAILURE | 9 shown, 27,519 real |
| `ct-crasher-throw` | EXC_CRASH / SIGABRT | (none) | 12, top 9 in libsystem/libc++abi |
| `ct-crasher-versioned` 1.0 x2, 2.0 | EXC_BAD_ACCESS / SIGSEGV | KERN_INVALID_ADDRESS at 0x0 | 4 |
| `ct-crasher-stripped` 1.0, 2.0 | EXC_BAD_ACCESS / SIGSEGV | KERN_INVALID_ADDRESS at 0x0 | 4, no symbols |

### More things the real files showed

1. **macOS already redacts home folders in crash reports.** `procPath` and image
   paths under the home folder are written as `/Users/USER/Documents/*/<name>`.
   After JSON-decoding, none of the 23 `.ips` files contained the login name, the
   hostname, the full name or the real home path. The anonymizer is still needed
   for incident ids, UUIDs, device keys, MAC addresses and paths outside the OS.
2. **Slashes are escaped in the JSON** (`"\/usr\/lib\/dyld"`). A `grep` for `/Users/`
   on a raw file finds nothing even when the decoded value contains it, so privacy
   checks must decode the JSON first (`tests/test_privacy.py` does).
3. **`sourceFile` and `sourceLine` appear when a dSYM is available.** None of the
   original six reports had them; every crasher report did.
4. **ReportCrash finds dSYMs through Spotlight.** The first run of the "stripped"
   build came back fully symbolicated, because `mdfind
   "com_apple_xcode_dsym_uuids == <UUID>"` found the dSYM in the build folder.
   The stripped builds now keep their dSYMs in `crashers/build/dsyms.noindex/`
   (Spotlight skips `*.noindex`), and their second run produced the unsymbolicated
   reports used as fixtures.
5. **An embedded Info.plist gives a command-line tool a version.** With
   `-sectcreate __TEXT __info_plist`, the header's `app_version`/`build_version`
   and the body's `bundleInfo` were filled in (`1.0`/`1`, `2.0`/`2`).
6. **The header `timestamp` is when the report was written, not when the crash
   happened.** Two dotnet crashes captured at 18:25:39 and 18:25:52 both have the
   header timestamp 18:25:55. The body's `captureTime` is the crash time.
7. **Deep recursion is elided.** The stack-overflow report lists 9 frames; the
   thread carries `originalLength: 27519` and a `recursionInfoArray`
   (`depth`, `hottestElided`, `coldestElided`, `keyFrame`).
8. **Every report has an anonymous image** (`source: "A"`, base 0, size 0), even a
   plain C program. Only dotnet's frames point into it.
9. Other keys not mentioned in the brief: `os_fault` (EXC_BREAKPOINT reports),
   both `vmRegionInfo` and `vmregioninfo` (same text, two spellings), `asi`
   (`abort() called`), `instructionByteStream` (base64 bytes around the PC).
10. Two reports for the same process in the same second: the second is named
    `<proc>-<date>.000.ips` (seen again with the two stripped runs).

### Decisions

- **Crash time is `captureTime`**, falling back to the header `timestamp` (finding 6).
  Stored as UTC, whole seconds, ISO 8601 with `Z`.
- **Process version** is header `app_version`, then `bundleInfo.CFBundleShortVersionString`;
  an empty string is "unknown".
- **Skips have a kind**: `permission`, `unreadable`, `not-ips`, `non-crash`,
  `legacy`, `malformed`. A crash header with an empty, truncated or wrongly shaped
  body is `malformed`; a frame without `imageOffset` or with a bad `imageIndex`
  is kept and recorded as a warning on the report.
- **Non-UTF-8 bytes** are replaced with U+FFFD and recorded as a warning; the
  report is still parsed.
- **Missing incident id** falls back to `sha256-<first 32 hex of the file hash>`.
- **Header vs body incident id** are compared case-insensitively (UUID case has no
  meaning).
- **Anonymizer re-serializes the JSON** (2-space indent, unescaped slashes). Files
  grow (the coreaudiod report went from 60 KB to 115 KB) but parse identically.
  It replaces UUIDs with `00000000-0000-0000-XXXX-XXXXXXXXXXXX`, an HMAC of the
  original under a random salt that is not stored. Every fixture is a fixed point of
  the anonymizer (running it again changes no byte).
- **Free-text paths with spaces** are followed across a space only when the next
  word contains a `/`; a final path component with a space keeps its tail
  (`/REDACTED/Google Chrome`), which is the basename that is kept anyway.

### Parser run on this Mac (after the crasher runs)

95 files: 19 crash reports parsed with 0 warnings; 76 skipped (47 `non-crash`: 20
bug_type 226, 14 bug_type 303, 8 bug_type 211, 4 bug_type 298, 1 panic summary;
29 `not-ips` text reports). 0 permission or unreadable skips.

## Phase 2: store and fingerprint

### Fingerprint rule (version `crashtriage-fp-v1`)

Implemented in `crashtriage/fingerprint.py`; the module docstring is the exact
specification.

1. Use the faulting thread only.
2. Drop frames in anonymous memory (`source: "A"`): JIT code, whose offsets are
   per-run absolute addresses.
3. A frame is *system* when its image path starts with one of `/System/`,
   `/usr/lib/`, `/usr/libexec/`, `/usr/bin/`, `/usr/sbin/`, `/bin/`, `/sbin/`,
   `/Library/Apple/`, **unless** that image is the crashing executable itself
   (so a crash inside `/usr/sbin/coreaudiod`'s own code counts as app code). Every
   other frame is an *app* frame.
4. If any app frame exists, use only app frames: the system frames on top
   (`__pthread_kill`, `abort`, `__cxa_throw`, `_assertionFailure`) describe how
   the process died, which is the same for unrelated bugs. Otherwise use the
   system frames and record `basis = system-only`.
5. Take the first 5 and render each as `image!symbol`, or `image+0xOFFSET` when
   there is no symbol. `symbolLocation`, image UUID, load address, version and
   pid are left out: they change between builds while the bug does not.
6. `sha256("crashtriage-fp-v1" \0 process \0 exception type \0 tokens joined by
   newlines)`, first 16 hex digits.

Why N = 5: in every crasher fixture the crashing function is the first app frame,
and apart from the stack overflow (the same recursive function over and over) the
whole app call path fits in 3 frames; 5 leaves room for a shared helper on
top (e.g. a common `validate()` called from two places) without letting deep,
unrelated callers (`main`, run loops, thread entry points) split a cluster. (For
dotnet, no N helps: the identifying frames are unnamed JIT frames.) It is a
judgment call, pinned by a test, and the first thing to revisit with more data.

### Measured on the fixtures and this Mac

| Data | Crashes | Fingerprint clusters | Naive clusters (hash of the raw faulting stack) |
|---|---|---|---|
| Fixtures | 15 | 11 | 14 |
| This Mac, all | 19 | 12 | 16 |
| This Mac, excluding `ct-crasher-*` | 6 | 2 | 6 |

- `ct-crasher-versioned` 1.0 (x2) and 2.0 share one fingerprint although every
  image offset of the bug moved in 2.0. A raw-stack hash splits them into two.
- The five dotnet crashes share one fingerprint; a raw-stack hash gives five,
  because their JIT frames have different absolute addresses on every run.
- The two *symbolicated* stripped-build reports (the first run, when Spotlight
  found the dSYM) share one fingerprint; the two *unsymbolicated* ones split,
  as documented (fixed in Phase 5 by `--symbolicate`).
- Ingesting the real folders twice: 19 added, then 0 added and 19 duplicates;
  incidents 19, images 169, threads 112, frames 872 both times.

### Limitations found here

- **Managed runtimes.** For dotnet, the top app frames are the CLR's generic
  "unhandled managed exception" path (`PROCAbort`, `TerminateProcess`, `SfiNext`,
  `CallDescrWorkerInternal`, `DispatchCallSimple`). The frames that would tell two
  managed bugs apart are JIT frames with no symbols, which must be dropped. So every
  unhandled .NET exception in the same runtime lands in one cluster. The fifth dotnet
  crash (41 frames instead of 35) may really be a different managed bug; a native
  crash report cannot show that.
- **System-only crashes** (coreaudiod) use offsets in a stripped Apple plug-in, so
  they will split across macOS updates.

### Store decisions

- SQLite tables `incidents`, `images`, `threads`, `frames`, plus `meta` (schema and
  fingerprint versions). `incident_id` is the primary key; `source_sha256` is unique.
- **Idempotent ingest:** `INSERT OR IGNORE` on the incident row; when it is
  ignored, nothing else is written and the file counts as a duplicate. One
  transaction per file.
- **Duplicate incident id with different bytes:** the first file in walk order wins
  (within each folder, its files in name order, then its subfolders) and later ones
  count as duplicates.
- `load_report()` rebuilds the exact `CrashReport` from the tables (tested for
  every fixture), so `show` and re-fingerprinting work from the database alone.
- If the stored fingerprint version differs from the code's, every fingerprint is
  recomputed when the database is opened.
- The database stores each report's local source path. It is local
  (`*.db` is gitignored) and paths are not printed by `report`.

## Phase 3: triage CLI

### Decisions

- **Commands:** `ingest [FOLDER|FILE ...]`, `report [--since] [--process] [--top]`,
  `show <id>`, `trend [--weeks N] [--process]`. Every command takes `--db` (default
  `./crashtriage.db`) and `--json`. `report` and `trend` also take `--as-of`.
- **Determinism.** Output is a pure function of the database and the arguments.
  Nothing prints the current time. Relative windows (`--since 7d`, `trend`'s last N
  weeks) are measured from the clock unless `--as-of` is given, and the report echoes
  the filter as typed (`since 7d`), not as a resolved date, so the text does not
  change from one run to the next when the data does not. Tests pin this with golden
  files, with a database ingested in reverse order, and with repeated runs.
- **Ranking:** count (desc), then last seen (desc), then fingerprint (asc), which is
  a total order, so ties never depend on insertion order.
- **Filters apply before grouping.** Count, first seen, last seen and versions all
  describe the crashes that matched the filters.
- **`--since` / `--as-of` semantics:** `--as-of` is an exclusive end; a bare date
  means the end of that day (UTC). `--since` takes `24h`, `7d`, `2w`, a date (start of
  day, UTC) or an ISO time with an offset. A time without an offset is refused rather
  than guessed. Crashes without a timestamp are excluded by `--since` and are counted
  separately by `trend`.
- **Weeks** are ISO weeks in UTC, Monday to Sunday (2026-10-26 is the Monday that
  starts 2026-W44).
- **`show` accepts** a full incident id, a unique prefix of one, or a fingerprint
  (or prefix), in which case it shows that cluster's latest crash. The report table
  lists fingerprints rather than incident ids because the ids are 36 characters.
  `*` in the frame list marks the frames that went into the fingerprint.
- **Versions** sort numerically part by part; a text part sorts after numbers
  (`1.9`, `1.9.1`, `1.9-beta`, `1.10`). Not semver, but a total order.
- **Errors:** read commands on a missing database exit 1 without creating it;
  unknown or ambiguous ids exit 1 with the reason on stderr; bad arguments exit 2.
- Long C++ symbols are cut to 70 characters in the report table (`…`); `show` and
  `--json` keep them whole.

## Phase 4: verification on this Mac

### Real run (2026-10-27, after the crasher runs)

`crashtriage ingest` over both folders:

| | Files |
|---|---|
| Scanned | 96 |
| Crash reports parsed and stored | 19 (0 parser warnings) |
| Skipped, non-crash | 39 (20 bug_type 226, 14 bug_type 303, 4 bug_type 298, 1 panic summary) |
| Skipped, not an `.ips` document | 30 (plain-text CPU / disk-write reports) |
| Skipped, permission | 8 (see below) |

A second `ingest` added 0 and counted 19 duplicates. `report` gives **19 crashes in
12 clusters**. Top clusters (process names only):

| Rank | Count | Process | Exception | Top frame |
|---|---|---|---|---|
| 1 | 5 | dotnet | EXC_CRASH / SIGABRT | `libcoreclr.dylib!PROCAbort` |
| 2 | 3 | ct-crasher-versioned | EXC_BAD_ACCESS / SIGSEGV | `ct-crasher-versioned!parse_record` (versions 1.0, 2.0) |
| 3 | 2 | ct-crasher-stripped | EXC_BAD_ACCESS / SIGSEGV | `ct-crasher-stripped!parse_record` (the Spotlight-symbolicated pair) |
| 4-11 | 1 each | the other crashers | various | |
| 12 | 1 | coreaudiod | EXC_BAD_ACCESS / SIGSEGV | `BTAudioHALPlugin+0x746a4` (system-only) |

Without the crasher programs, the Mac's own history is 6 crashes in 2 clusters
(dotnet x5, coreaudiod x1). All 19 crashes fall in ISO week 2026-W44.

Timing (wall clock, including Python start-up): a fresh ingest of the 96 files took
0.06-0.11 s over three runs; re-ingest 0.05 s; `report` 0.04 s. The data set is
small, so these numbers say little about scale.

### New finding: EPERM on analytics files

Between Phase 0 and Phase 4 (same day), the 8 `Analytics-*.core_analytics` files in
`/Library/Logs/DiagnosticReports/Retired/` became unreadable: `open()` and `head`
both fail with `EPERM` ("Operation not permitted"). Unix permissions still allow the
read (`rw-rw---- root:_analyticsusers`, and this account is in that group), there
are no file flags or ACLs, and the JetsamEvent `.ips` files in the same folder are
still readable. So something beyond Unix permissions is refusing the read: a macOS
privacy restriction, or the sandbox the development shell runs under. I did not try
to work around it (it would need a new permission). The tool handled it as designed:
counted 8 `permission` skips, listed the files, and went on. These are analytics
files (bug_type 211), not crash reports, so the crash numbers are not affected.

### Injected defects

`tests/test_defects.py` builds each defect from a real fixture and runs it through
parse, fingerprint, ingest and the CLI:

| # | Defect | Documented handling | Test |
|---|---|---|---|
| 1 | A frame with no `imageOffset` | Report still parsed; frame kept with offset `None`; warning `thread T frame F: no imageOffset`; fingerprint token `image+?`; `show` prints `?` and the warning | `test_defect_frame_without_offset` |
| 2 | A duplicate incident (same file twice, plus an edited copy with the same incident id) | Stored once; the others count as duplicates; no rows added | `test_defect_duplicate_incident` |
| 3 | One bug in a rebuilt binary (new UUID, load address, offsets, symbolLocation, version) | Same fingerprint; a hash over raw frames differs | `test_defect_same_bug_naive_hash_splits` |
| 4 | A crash whose frames are all system frames | Fingerprint uses the top 5 system frames, basis `system-only`; with app frames present the system frames on top are skipped | `test_defect_all_system_frames` |
| 5 | A non-UTF-8 byte inside a symbol name | Decoded with U+FFFD, parsed, warning recorded, ingested | `test_defect_non_utf8_byte` |
| 6 | A crash header with an empty body | Skipped as `malformed` ("crash header but the body is empty"); the rest of the folder is ingested; the file is listed by `ingest` | `test_defect_empty_body` |

### Mutation check

`scripts/mutation_check.py` breaks the handling code for each defect in a temporary
copy of the repo and runs the full suite. Result: the baseline passes and every
mutation is caught. Failing-test counts below are from the final run (after Phase 5
and the final review); the Phase 4 run caught the same 9 with slightly fewer tests.

| Mutation (breaks the handling of ...) | Failing tests |
|---|---|
| frame with a missing offset | 2 (incl. `test_defect_frame_without_offset`) |
| duplicate incident (`INSERT OR REPLACE`) | 5 (incl. `test_defect_duplicate_incident`) |
| naive hash: symbolLocation hashed | 22 (incl. `test_defect_same_bug_naive_hash_splits`) |
| naive hash: JIT frames hashed | 12 |
| all system frames, no fallback | 5 (incl. `test_defect_all_system_frames`) |
| system frames on top not skipped | 16 (incl. `test_defect_all_system_frames`) |
| non-UTF-8 byte (strict decoding) | 3 (incl. `test_defect_non_utf8_byte`) |
| empty body check removed | 2 (incl. `test_defect_empty_body`) |
| inputs opened `r+b` instead of `rb` | 2 |

### Test suite

At the end of Phase 4: 214 tests, all passing, in about 1 s (`.venv/bin/python -m pytest`).

Resume bullets built from these numbers are in `RESUME_BULLETS.md`, which is kept
out of the public repo on purpose (`.gitignore`).

## Phase 5: `--symbolicate` with atos and dSYMs

### What it does

`crashtriage ingest --symbolicate <dSYM or folder>` (repeatable):

1. Reads the UUID and architecture of each Mach-O file in the dSYM bundles from
   the `LC_UUID` load command (thin and universal files), with `struct`. A test
   checks the result against `dwarfdump --uuid` on a freshly built binary.
2. For each stored crash with unnamed frames in an image whose UUID matches,
   runs `atos -o <dSYM DWARF file> -arch <image arch> -l <image base> <base+offset>...`,
   one call per image.
3. Parses `symbol (in image) (file:line)` lines; unresolved addresses come back as
   `0x... (in image)` or a bare address and are left unnamed. If atos prints a
   different number of lines than addresses were sent, nothing from that call is
   used, so a name can never land on the wrong frame.
4. Updates only frames whose symbol is NULL, then re-fingerprints those crashes.

### Observed `atos` behavior (macOS 26.6.2, /usr/bin/atos)

- Resolved, with a dSYM: `parse_record (in ct-crasher-stripped) (versioned.c:24)`.
  No `+ offset` is printed when there is line information, so `symbolLocation`
  stays empty for frames named this way.
- Address inside the image but not in a function: `0x0000000100000010 (in ...)`.
- Address outside the image: echoed back (`0x104099999`).
- Stripped binary, no dSYM: `0x00000001000005a4 (in ct-crasher-stripped) + 12`.
- Wrong architecture: an error on stderr and nothing on stdout.

### Result on this Mac

Before: 19 crashes in 12 clusters; `ct-crasher-stripped` split into 3 clusters
(the Spotlight-symbolicated pair, plus one cluster per unsymbolicated build).
`ingest --symbolicate crashers/build/dsyms.noindex` named 6 frames in 2 crashes
with 2 dSYMs (0 unresolved). After: **19 crashes in 10 clusters**, and all 4
`ct-crasher-stripped` crashes (versions 1.0 and 2.0) are one cluster whose
fingerprint equals the one macOS's own symbolication produced. A second run
changed 0 crashes.

### Decisions and limits

- Matching is by UUID only. A dSYM is never applied to a binary from another
  build, even with the same name.
- `--symbolicate` updates crashes already in the database, not only new ones,
  because the dSYM is often found after the crash was ingested.
- Each run of `crashers/build.sh` produced binaries with new UUIDs (observed three
  times), so the real-data result above only holds for the build that produced
  those crash reports. Rebuild, re-run the crashers, then symbolicate.
- System libraries are not symbolicated (their dSYMs are not on the machine).

## Final review

After Phase 5, an independent read-only review of the whole repo (code, docs, tests
and git history) found the following. All are fixed in the final commit.

### Privacy: real identifiers in test code

The anonymizer's unit test used values copied from real reports as "canaries":
this Mac's `crashReporterKey` (a stable per-device id), the Bluetooth MAC address
from the coreaudiod report, one dotnet incident id, and three build UUIDs (two of
the crasher builds, one of Microsoft's `dotnet`), plus Microsoft's public Team ID.
They were pushed in the Phase 1 and Phase 5 commits. The fixtures themselves were
clean; the privacy test only scanned fixtures for raw identifiers, so test code
slipped through.

- Replaced every one with an obviously synthetic value.
- New test `test_repo_has_no_identifiers_from_this_macs_reports` reads every UUID,
  MAC address, long hex id and team id from this Mac's real reports (read-only)
  and fails if any of them appears in any file of the repo. Run against the old
  test file in a scratch copy, it failed and listed all of them.
- A full scan of `git log -p` against all 1,663 identifiers in the local reports
  (1,642 UUIDs, 1 MAC address, 19 long hex ids, 1 team id) found these values and
  nothing else.
- With the owner's approval, the history was rewritten with `git filter-repo
  --replace-text` (each value swapped for the same synthetic value the tests now
  use) and force-pushed. The final file tree was byte-identical before and after
  (same tree hash); the rewritten Phase 1 and Phase 5 commits still pass their own
  tests (115 and 238) in a plain checkout; a re-scan of the new history against
  every identifier in the local reports (3,078 by then) found none. GitHub may keep
  serving the old commits by direct SHA until it garbage-collects them.
- Running the tests from a git worktree briefly tripped the repo-wide scan: a
  worktree's `.git` is a file holding its absolute path, which can contain the login
  name. The scan now skips `.git` whether it is a file or a folder.

### Bugs

1. The parser could still raise: a JSON integer longer than Python's 4,300-digit
   limit (`ValueError`, not `JSONDecodeError`) and a `captureTime` in year 9999 with
   a negative offset (`OverflowError`). Both are now a skip or a warning.
2. A `\ud800`-style escape decoded to a lone surrogate, which then failed to encode
   as UTF-8 in SQLite and in the fingerprint hash. Lone surrogates are now replaced
   with U+FFFD and reported as a warning; real surrogate pairs (emoji) are untouched.
3. A truncated fat Mach-O header (or a Java `.class` file, which also starts with
   `CAFEBABE`) raised `struct.error` out of `--symbolicate`. Now a `MachOError`,
   and the file is ignored.
4. `--symbolicate path/X.dSYM/` (trailing slash, as shell completion adds) found
   nothing. Paths are normalized now.
5. `report --as-of DATE` without `--since` ignored the date. `--as-of` now always
   hides crashes after it ("treat this time as now").
6. `trend --process NAME` counted undated crashes of every process. Fixed.
7. `report`, `show` and `trend` opened the database for writing, so a read-only
   database file failed, and a file that is not a database printed a traceback.
   Read commands now open it with SQLite's `mode=ro`, and database errors become a
   one-line message with exit status 1.

Test gap also fixed: two `--symbolicate` CLI tests patched a function the CLI had
imported by name, so the patch had no effect; the CLI now calls through the module
and the "atos is missing" path has its own test.

### Final checks

- Test suite: 252 tests, all passing (`.venv/bin/python -m pytest`, about 1.7 s),
  also from a fresh clone of the GitHub repo.
- Mutation check: 11 of 11 mutations caught (the 9 above, plus "atos output that
  does not line up" and "dSYM used without a UUID match").

## Open questions

- Is `faultingThread` always the thread with `triggered: true`? True for 6 of 6 files
  here; the parser records both and the tests check the agreement on fixtures.
- What exactly moves a report into `Retired/`? Every crash here was already there.
- The fifth dotnet crash (`.000`) has a longer faulting stack (41 frames, 14 JIT) than
  the other four. Is it the same bug reached by a different path, or a different bug?
  The fingerprint puts all five together (see "Limitations found here" in Phase 2);
  the native report cannot settle it.
- What made the analytics files unreadable (EPERM) partway through the day: a macOS
  privacy rule, or the sandbox of the shell the tool ran in? (Phase 4.)
- Is `N = 5` right? It is pinned by tests but rests on 19 crashes; more data from
  real apps might argue for 3 (fewer splits) or more (fewer false merges).
