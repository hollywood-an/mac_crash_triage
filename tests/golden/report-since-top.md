# Crash clusters

12 crashes in 10 clusters (since 1d, as of 2026-10-27); showing the top 3.

| # | Count | Process | Exception | First seen (UTC) | Last seen (UTC) | Versions | Top frame | Fingerprint |
|--:|--:|---|---|---|---|---|---|---|
| 1 | 3 | ct-crasher-versioned | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:15 | 2026-10-27 20:15 | 1.0, 2.0 | `ct-crasher-versioned!parse_record` | `bd6f08520a5ab6c0` |
| 2 | 1 | ct-crasher-stripped | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:17 | 2026-10-27 20:17 | 2.0 | `ct-crasher-stripped+0x5a4` | `9cdad49681fa0325` |
| 3 | 1 | ct-crasher-stripped | EXC_BAD_ACCESS / SIGSEGV | 2026-10-27 20:17 | 2026-10-27 20:17 | 1.0 | `ct-crasher-stripped+0x528` | `f27c55e84bc488a2` |

Run `crashtriage show <fingerprint>` for the latest crash in a cluster.
