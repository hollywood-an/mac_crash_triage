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

## Open questions

- Is `faultingThread` always the thread with `triggered: true`? True for 6 of 6 files
  here; the parser records both and the tests check the agreement on fixtures.
- What exactly moves a report into `Retired/`? Every crash here was already there.
- The fifth dotnet crash (`.000`) has a longer faulting stack (41 frames, 14 JIT) than
  the other four. Is it the same bug reached by a different path, or a different bug?
