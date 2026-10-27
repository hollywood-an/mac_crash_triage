# ct-crasher-overflow crash 00000000-0000-0000-4BDF-467A0254B6D1

| Field | Value |
|---|---|
| Process | ct-crasher-overflow (no version), pid 4311 |
| Path | /REDACTED/ct-crasher-overflow |
| Crashed at | 2026-10-27 20:15:42 UTC (report: 2026-10-27 16:15:42.8011 -0400) |
| OS | macOS 26.6.2 (25G83), ARM-64 |
| Exception | EXC_BAD_ACCESS (SIGSEGV): KERN_PROTECTION_FAILURE at 0x000000016b10bf74 |
| Termination | SIGNAL 11: Segmentation fault: 11 |
| Fingerprint | `f36c76a2908487a2` (app frames; 1 crash in this cluster) |

## Faulting thread 0 (queue com.apple.main-thread)

9 of 27519 frames; ReportCrash elided the rest. `*` marks the frames in the fingerprint.

```text
  #  image                offset         symbol
  0  ct-crasher-overflow  0x454        * descend + 32  (overflow.c:3)
  1  ct-crasher-overflow  0x46c        * descend + 56  (overflow.c:6)
  2  ct-crasher-overflow  0x46c        * descend + 56  (overflow.c:6)
  3  ct-crasher-overflow  0x46c        * descend + 56  (overflow.c:6)
  4  ct-crasher-overflow  0x46c        * descend + 56  (overflow.c:6)
  5  ct-crasher-overflow  0x46c          descend + 56  (overflow.c:6)
  6  ct-crasher-overflow  0x46c          descend + 56  (overflow.c:6)
  7  ct-crasher-overflow  0x428          main + 24  (overflow.c:10)
  8  dyld                 0x204e4        start + 6992
```
