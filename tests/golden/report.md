# Crash clusters

15 crashes in 11 clusters.

| # | Count | Process | Exception | First seen (UTC) | Last seen (UTC) | Versions | Top frame | Fingerprint |
|--:|--:|---|---|---|---|---|---|---|
| 1 | 3 | ct-crasher-versioned | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:15 | 2026-10-27 20:15 | 1.0, 2.0 | `ct-crasher-versioned!parse_record` | `bd6f08520a5ab6c0` |
| 2 | 3 | dotnet | EXC_CRASH / SIGABRT | 2026-10-26 22:25 | 2026-10-26 22:36 | - | `libcoreclr.dylib!PROCAbort` | `edb224fcb71d2a42` |
| 3 | 1 | ct-crasher-stripped | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:17 | 2026-10-27 20:17 | 2.0 | `ct-crasher-stripped+0x5a4` | `9cdad49681fa0325` |
| 4 | 1 | ct-crasher-stripped | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:17 | 2026-10-27 20:17 | 1.0 | `ct-crasher-stripped+0x528` | `f27c55e84bc488a2` |
| 5 | 1 | ct-crasher-swift | EXC_BREAKPOINT / SIGTRAP | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-swift!requirePositive(_:)` | `05ba8b134d2a8c04` |
| 6 | 1 | ct-crasher-throw | EXC_CRASH / SIGABRT | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-throw!load_config(char const*)` | `15114a2f571b693f` |
| 7 | 1 | ct-crasher-overflow | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-overflow!descend` | `f36c76a2908487a2` |
| 8 | 1 | ct-crasher-trap | EXC_BREAKPOINT / SIGTRAP | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-trap!checked_div` | `4883d92e392fe767` |
| 9 | 1 | ct-crasher-bus | EXC_BAD_ACCESS / SIGBUS | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-bus!patch_code` | `25a87f1080c2040f` |
| 10 | 1 | ct-crasher-segv | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:15 | 2026-10-27 20:15 | - | `ct-crasher-segv!store_id` | `4543adc9f8af0478` |
| 11 | 1 | coreaudiod | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 01:59 | 2026-10-27 01:59 | 5.0 | `BTAudioHALPlugin+0x746a4` (system) | `c16751fb76f17124` |

Run `crashtriage show <fingerprint>` for the latest crash in a cluster.
