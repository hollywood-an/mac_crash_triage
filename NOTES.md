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

Why N = 5: on every fixture the frames that identify the bug are within the
first 3 app frames, and 5 leaves room for a shared helper on top (e.g. a common
`validate()` called from two places) without letting deep, unrelated callers
(`main`, run loops, thread entry points) split a cluster. It is a judgment call,
pinned by a test, and the first thing to revisit with more data.

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
- **Duplicate incident id with different bytes:** the first file (in sorted path
  order) wins and the second counts as a duplicate.
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

## Open questions

- Is `faultingThread` always the thread with `triggered: true`? True for 6 of 6 files
  here; the parser records both and the tests check the agreement on fixtures.
- What exactly moves a report into `Retired/`? Every crash here was already there.
- The fifth dotnet crash (`.000`) has a longer faulting stack (41 frames, 14 JIT) than
  the other four. Is it the same bug reached by a different path, or a different bug?
