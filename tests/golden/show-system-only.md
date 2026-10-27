# coreaudiod crash 00000000-0000-0000-3B51-9E7175764D46

| Field | Value |
|---|---|
| Process | coreaudiod 5.0, pid 425 |
| Path | /usr/sbin/coreaudiod |
| Crashed at | 2026-10-27 01:59:10 UTC (report: 2026-10-26 21:59:10.3663 -0400) |
| OS | macOS 26.6.2 (25G83), ARM-64 |
| Exception | EXC_BAD_ACCESS (SIGSEGV): KERN_INVALID_ADDRESS at 0x0000000000000000 |
| Termination | SIGNAL 11: Segmentation fault: 11 |
| Fingerprint | `c16751fb76f17124` (system-only frames; 1 crash in this cluster) |

## Faulting thread 25 (queue com.apple.audio.device.XX-XX-XX-XX-XX-XX:output.event)

20 frames. `*` marks the frames in the fingerprint.

```text
  #  image                    offset         symbol
  0  BTAudioHALPlugin         0x746a4      *
  1  BTAudioHALPlugin         0x746a0      *
  2  BTAudioHALPlugin         0x59414      *
  3  CoreAudio                0x32cb88     * HALS_UCPlugIn::ObjectSetPropertyData(unsigned int, int, AudioObjectPropertyAddress const&, unsigned int, void const*, unsigned int, void const*) + 68
  4  CoreAudio                0x360488     * HALS_PlugInControl::SetPropertyData(unsigned int, AudioObjectPropertyAddress const&, unsigned int, void const*, unsigned int, void const*, HALS_Client*) + 1516
  5  CoreAudio                0x617c1c       _XObject_SetPropertyData_DF32 + 456
  6  CoreAudio                0x61f10c       HALB_MIGServer_server + 108
  7  libdispatch.dylib        0x1f87c        dispatch_mig_server + 424
  8  CoreAudio                0x2c9ae8       invocation function for block in AMCP::Utility::Dispatch_Queue::install_mig_server(unsigned int, unsigned int, int (*)(mach_msg_header_t*, mach_msg_header_t*), bool, bool) + 52
  9  libdispatch.dylib        0x1b4b0        _dispatch_client_callout + 16
 10  libdispatch.dylib        0x61c8         _dispatch_continuation_pop + 596
 11  libdispatch.dylib        0x191b0        _dispatch_source_latch_and_call + 392
 12  libdispatch.dylib        0x17e84        _dispatch_source_invoke + 844
 13  libdispatch.dylib        0x9e98         _dispatch_lane_serial_drain + 332
 14  libdispatch.dylib        0xab64         _dispatch_lane_invoke + 448
 15  libdispatch.dylib        0xbec8         _dispatch_workloop_invoke + 1584
 16  libdispatch.dylib        0x14e34        _dispatch_root_queue_drain_deferred_wlh + 284
 17  libdispatch.dylib        0x14734        _dispatch_workloop_worker_thread + 720
 18  libsystem_pthread.dylib  0x2ec0         _pthread_wqthread + 292
 19  libsystem_pthread.dylib  0x1c10         start_wqthread + 8
```
