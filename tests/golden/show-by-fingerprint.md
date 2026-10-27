# ct-crasher-versioned crash 00000000-0000-0000-6573-78D2AE2A476A

| Field | Value |
|---|---|
| Process | ct-crasher-versioned 2.0 (2), pid 4429 |
| Path | /REDACTED/ct-crasher-versioned |
| Crashed at | 2026-10-27 20:15:53 UTC (report: 2026-10-27 16:15:53.9109 -0400) |
| OS | macOS 26.6.2 (25G83), ARM-64 |
| Exception | EXC_BAD_ACCESS (SIGSEGV): KERN_INVALID_ADDRESS at 0x0000000000000000 |
| Termination | SIGNAL 11: Segmentation fault: 11 |
| Fingerprint | `bd6f08520a5ab6c0` (app frames; 3 crashes in this cluster) |

## Faulting thread 0 (queue com.apple.main-thread)

4 frames. `*` marks the frames in the fingerprint.

```text
  #  image                 offset         symbol
  0  ct-crasher-versioned  0x5a4        * parse_record + 12  (versioned.c:24)
  1  ct-crasher-versioned  0x530        * handle_request + 60  (versioned.c:38)
  2  ct-crasher-versioned  0x4e8        * main + 56  (versioned.c:44)
  3  dyld                  0x204e4        start + 6992
```
