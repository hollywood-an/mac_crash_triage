# Crash clusters

3 crashes in 1 cluster (process DOTNET).

| # | Count | Process | Exception | First seen (UTC) | Last seen (UTC) | Versions | Top frame | Fingerprint |
|--:|--:|---|---|---|---|---|---|---|
| 1 | 3 | dotnet | EXC_CRASH / SIGABRT | 2026-10-26 22:25 | 2026-10-26 22:36 | - | `libcoreclr.dylib!PROCAbort` | `edb224fcb71d2a42` |

Run `crashtriage show <fingerprint>` for the latest crash in a cluster.
