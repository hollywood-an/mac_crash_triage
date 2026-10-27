"""Parser tests on anonymized copies of real reports (tests/fixtures/README.md)."""

from __future__ import annotations

import json
import os

import pytest

from conftest import CRASH_FIXTURES, fixture_bytes, fixture_path, running_as_root
from crashtriage.model import CrashReport, Skipped
from crashtriage.parser import parse_bytes, parse_file, parse_timestamp


def parsed(name: str) -> CrashReport:
    report = parse_file(fixture_path(name))
    assert isinstance(report, CrashReport), report
    return report


# --- field by field, one case per crash type -----------------------------------

COMMON = {"bug_type": "309", "os_version": "macOS 26.6.2", "os_build": "25G83", "cpu_type": "ARM-64", "warnings": ()}

CASES = {
    # A system daemon: EXC_BAD_ACCESS / SIGSEGV on a NULL read, on a dispatch queue thread.
    "coreaudiod-segv.ips": {
        "incident_id": "00000000-0000-0000-3B51-9E7175764D46",
        "timestamp": "2026-10-27T01:59:10Z",
        "timestamp_raw": "2026-10-26 21:59:10.3663 -0400",
        "process_name": "coreaudiod",
        "process_version": "5.0",
        "build_version": "5.0",
        "process_path": "/usr/sbin/coreaudiod",
        "pid": 425,
        "exception_type": "EXC_BAD_ACCESS",
        "signal": "SIGSEGV",
        "exception_subtype": "KERN_INVALID_ADDRESS at 0x0000000000000000",
        "termination_namespace": "SIGNAL",
        "termination_code": 11,
        "termination_indicator": "Segmentation fault: 11",
        "faulting_thread": 25,
        "n_threads": 30,
        "n_images": 23,
    },
    # A third-party runtime: EXC_CRASH / SIGABRT from abort(), with JIT frames.
    "dotnet-abort-a.ips": {
        "incident_id": "00000000-0000-0000-B013-7C4C105FD146",
        "timestamp": "2026-10-26T22:25:39Z",
        "timestamp_raw": "2026-10-26 18:25:39.1157 -0400",
        "process_name": "dotnet",
        "process_version": None,  # app_version is "" in the report
        "build_version": None,
        "process_path": "/REDACTED/dotnet",
        "pid": 62350,
        "exception_type": "EXC_CRASH",
        "signal": "SIGABRT",
        "exception_subtype": None,
        "termination_namespace": "SIGNAL",
        "termination_code": 6,
        "termination_indicator": "Abort trap: 6",
        "faulting_thread": 0,
        "n_threads": 13,
        "n_images": 18,
    },
    # Write to a code page: EXC_BAD_ACCESS / SIGBUS (protection failure).
    "crasher-bus.ips": {
        "incident_id": "00000000-0000-0000-27FA-6F10B21096BA",
        "timestamp": "2026-10-27T20:15:38Z",
        "timestamp_raw": "2026-10-27 16:15:38.3283 -0400",
        "process_name": "ct-crasher-bus",
        "process_version": None,
        "build_version": None,
        "process_path": "/REDACTED/ct-crasher-bus",
        "pid": 4239,
        "exception_type": "EXC_BAD_ACCESS",
        "signal": "SIGBUS",
        "exception_subtype": "KERN_PROTECTION_FAILURE at 0x000000010436c37c",
        "termination_namespace": "SIGNAL",
        "termination_code": 10,
        "termination_indicator": "Bus error: 10",
        "faulting_thread": 0,
        "n_threads": 1,
        "n_images": 4,
    },
    # __builtin_trap: EXC_BREAKPOINT / SIGTRAP, no subtype.
    "crasher-trap.ips": {
        "incident_id": "00000000-0000-0000-498F-6A14DF237F4D",
        "timestamp": "2026-10-27T20:15:40Z",
        "timestamp_raw": "2026-10-27 16:15:40.5598 -0400",
        "process_name": "ct-crasher-trap",
        "process_version": None,
        "build_version": None,
        "process_path": "/REDACTED/ct-crasher-trap",
        "pid": 4285,
        "exception_type": "EXC_BREAKPOINT",
        "signal": "SIGTRAP",
        "exception_subtype": None,
        "termination_namespace": "SIGNAL",
        "termination_code": 5,
        "termination_indicator": "Trace/BPT trap: 5",
        "faulting_thread": 0,
        "n_threads": 1,
        "n_images": 4,
    },
    # Uncaught C++ exception: EXC_CRASH / SIGABRT through std::terminate.
    "crasher-throw.ips": {
        "incident_id": "00000000-0000-0000-8E98-8FC38E6D3F1F",
        "timestamp": "2026-10-27T20:15:45Z",
        "timestamp_raw": "2026-10-27 16:15:45.1095 -0400",
        "process_name": "ct-crasher-throw",
        "process_version": None,
        "build_version": None,
        "process_path": "/REDACTED/ct-crasher-throw",
        "pid": 4334,
        "exception_type": "EXC_CRASH",
        "signal": "SIGABRT",
        "exception_subtype": None,
        "termination_namespace": "SIGNAL",
        "termination_code": 6,
        "termination_indicator": "Abort trap: 6",
        "faulting_thread": 0,
        "n_threads": 1,
        "n_images": 8,
    },
    # Stack overflow: EXC_BAD_ACCESS / SIGSEGV on the guard page.
    "crasher-overflow.ips": {
        "incident_id": "00000000-0000-0000-4BDF-467A0254B6D1",
        "timestamp": "2026-10-27T20:15:42Z",
        "timestamp_raw": "2026-10-27 16:15:42.8011 -0400",
        "process_name": "ct-crasher-overflow",
        "process_version": None,
        "build_version": None,
        "process_path": "/REDACTED/ct-crasher-overflow",
        "pid": 4311,
        "exception_type": "EXC_BAD_ACCESS",
        "signal": "SIGSEGV",
        "exception_subtype": "KERN_PROTECTION_FAILURE at 0x000000016b10bf74",
        "termination_namespace": "SIGNAL",
        "termination_code": 11,
        "termination_indicator": "Segmentation fault: 11",
        "faulting_thread": 0,
        "n_threads": 1,
        "n_images": 4,
    },
    # A command-line tool with an embedded Info.plist: the version is reported.
    "crasher-versioned-v2.ips": {
        "incident_id": "00000000-0000-0000-6573-78D2AE2A476A",
        "timestamp": "2026-10-27T20:15:53Z",
        "timestamp_raw": "2026-10-27 16:15:53.9109 -0400",
        "process_name": "ct-crasher-versioned",
        "process_version": "2.0",
        "build_version": "2",
        "process_path": "/REDACTED/ct-crasher-versioned",
        "pid": 4429,
        "exception_type": "EXC_BAD_ACCESS",
        "signal": "SIGSEGV",
        "exception_subtype": "KERN_INVALID_ADDRESS at 0x0000000000000000",
        "termination_namespace": "SIGNAL",
        "termination_code": 11,
        "termination_indicator": "Segmentation fault: 11",
        "faulting_thread": 0,
        "n_threads": 1,
        "n_images": 4,
    },
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_fields(name: str) -> None:
    report = parsed(name)
    expected = {**COMMON, **CASES[name]}
    n_threads, n_images = expected.pop("n_threads"), expected.pop("n_images")
    for field_name, value in expected.items():
        assert getattr(report, field_name) == value, field_name
    assert len(report.threads) == n_threads
    assert len(report.images) == n_images
    assert len(report.source_sha256) == 64


def test_at_least_four_distinct_crash_types() -> None:
    kinds = {(parsed(n).exception_type, parsed(n).signal) for n in CASES}
    assert len(kinds) >= 4


def test_coreaudiod_faulting_thread() -> None:
    report = parsed("coreaudiod-segv.ips")
    thread = report.faulting
    assert thread is not None and thread.index == 25 and thread.triggered
    assert thread.thread_id == 12418283
    assert thread.queue == "com.apple.audio.device.XX-XX-XX-XX-XX-XX:output.event"
    assert len(thread.frames) == 20
    top = thread.frames[0]
    # A stripped Apple plug-in: image offset only, no symbol.
    assert (top.image_index, top.image_name, top.image_offset) == (6, "BTAudioHALPlugin", 476836)
    assert top.symbol is None and top.symbol_location is None
    fourth = thread.frames[3]
    assert fourth.image_name == "CoreAudio"
    assert fourth.image_offset == 3328904
    assert fourth.symbol.startswith("HALS_UCPlugIn::ObjectSetPropertyData(")
    assert fourth.symbol_location == 68
    assert report.main_image is not None and report.main_image.name == "coreaudiod"


def test_dotnet_jit_frames_point_at_the_anonymous_image() -> None:
    report = parsed("dotnet-abort-a.ips")
    anonymous = [image.index for image in report.images if image.is_anonymous]
    assert anonymous == [13]
    image = report.images[13]
    assert (image.source, image.name, image.path, image.base) == ("A", None, None, 0)
    frames = report.faulting.frames
    jit = [i for i, f in enumerate(frames) if f.image_index == 13]
    assert jit == [6, 7, 14, 15, 16, 17, 18, 19, 20]
    assert all(frames[i].image_name is None and frames[i].symbol is None for i in jit)
    assert frames[6].image_offset == 4474095956  # an absolute address: base is 0
    assert [f.symbol for f in frames[:4]] == ["__pthread_kill", "pthread_kill", "abort", "PROCAbort"]


def test_source_file_and_line_are_read_when_present() -> None:
    frame = parsed("crasher-bus.ips").faulting.frames[0]
    assert (frame.symbol, frame.symbol_location, frame.source_file, frame.source_line) == ("patch_code", 20, "bus.c", 7)
    assert (frame.image_name, frame.image_offset) == ("ct-crasher-bus", 880)


def test_elided_recursion_keeps_the_original_depth() -> None:
    thread = parsed("crasher-overflow.ips").faulting
    assert len(thread.frames) == 9
    assert thread.original_length == 27519
    assert [f.symbol for f in thread.frames] == ["descend"] * 7 + ["main", "start"]
    assert parsed("crasher-segv.ips").faulting.original_length is None


def test_stripped_binary_has_offsets_but_no_symbols() -> None:
    frames = parsed("crasher-stripped-v1.ips").faulting.frames
    assert [(f.image_name, f.image_offset, f.symbol) for f in frames[:3]] == [
        ("ct-crasher-stripped", 1320, None),
        ("ct-crasher-stripped", 1296, None),
        ("ct-crasher-stripped", 1256, None),
    ]
    assert (frames[3].image_name, frames[3].symbol) == ("dyld", "start")


@pytest.mark.parametrize("name", CRASH_FIXTURES)
def test_every_crash_fixture_parses_cleanly(name: str) -> None:
    report = parsed(name)
    assert report.warnings == ()
    assert report.faulting is not None
    # faultingThread and the `triggered` flag agree on every real report.
    assert [t.index for t in report.threads if t.triggered] == [report.faulting_thread]


# --- files that are not crash reports -----------------------------------------


def test_malformed_fixture_is_skipped_with_a_reason() -> None:
    result = parse_file(fixture_path("malformed-truncated.ips"))
    assert isinstance(result, Skipped)
    assert result.kind == "malformed"
    assert result.reason.startswith("body is not valid JSON")


def test_non_crash_ips_is_recognized_by_bug_type() -> None:
    result = parse_file(fixture_path("noncrash-jetsam.ips"))
    assert isinstance(result, Skipped)
    assert (result.kind, result.reason) == ("non-crash", "bug_type 298 (jetsam event)")


def test_text_diag_report_is_not_an_ips_document() -> None:
    result = parse_file(fixture_path("noncrash-text.diag"))
    assert isinstance(result, Skipped)
    assert (result.kind, result.reason) == ("not-ips", "first line is not a JSON header")


def _crash_doc(body: object, header: dict | None = None) -> bytes:
    header = header or {"bug_type": "309", "incident_id": "00000000-0000-0000-0000-000000000001", "app_name": "demo"}
    return (json.dumps(header) + "\n" + (body if isinstance(body, str) else json.dumps(body))).encode()


@pytest.mark.parametrize(
    ("data", "kind", "reason_start"),
    [
        (b'{"panic_string": "panic(cpu 0 ...)", "log_path": "/x"}', "non-crash", "header has no bug_type"),
        (b'{"bug_type": "109", "incident_id": "x"}\nIncident Identifier: x\n', "legacy", "bug_type 109"),
        (b'{"bug_type": 211}\n{"a": 1}\n{"b": 2}\n', "non-crash", "bug_type 211"),
        (b'{"bug_type": "999"}\n{}', "non-crash", "bug_type 999 (not a crash report)"),
        (b"", "not-ips", "first line is not a JSON header"),
        (b"[1, 2]\n{}", "not-ips", "first line is JSON but not an object"),
        (_crash_doc(""), "malformed", "crash header but the body is empty"),
        (_crash_doc("  \n\n"), "malformed", "crash header but the body is empty"),
        (_crash_doc([1, 2]), "malformed", "body is JSON but not an object"),
        (_crash_doc({"procName": "demo", "threads": "nope"}), "malformed", "threads should be a list"),
        (_crash_doc({"procName": "demo", "faultingThread": "zero"}), "malformed", "faultingThread should be an integer"),
        (_crash_doc({"procName": "demo", "threads": [{"frames": [7]}]}), "malformed", "threads[0].frames[0] should be an object"),
        (_crash_doc({"threads": []}, {"bug_type": "309"}), "malformed", "no process name"),
    ],
)
def test_bad_documents_are_skipped_not_raised(data: bytes, kind: str, reason_start: str) -> None:
    result = parse_bytes(data, "doc")
    assert isinstance(result, Skipped), result
    assert result.kind == kind
    assert result.reason.startswith(reason_start), result.reason


def test_bool_bug_type_is_not_a_crash() -> None:
    assert parse_bytes(b'{"bug_type": true}\n{}').kind == "non-crash"


def test_minimal_crash_document_parses_with_warnings() -> None:
    result = parse_bytes(_crash_doc({"procName": "demo"}))
    assert isinstance(result, CrashReport)
    assert result.process_name == "demo"
    assert result.threads == () and result.faulting is None
    assert "report has no threads" in result.warnings
    assert "no faultingThread" in result.warnings


def test_missing_incident_id_falls_back_to_content_hash() -> None:
    result = parse_bytes(_crash_doc({"procName": "demo"}, {"bug_type": "309"}))
    assert result.incident_id == "sha256-" + result.source_sha256[:32]


def test_frame_problems_become_warnings() -> None:
    body = {
        "procName": "demo",
        "captureTime": "2026-10-26 18:25:39.1157 -0400",
        "faultingThread": 0,
        "usedImages": [{"name": "demo", "path": "/x/demo", "source": "P"}],
        "threads": [{"triggered": True, "frames": [{"imageIndex": 0}, {"imageIndex": 9, "imageOffset": 4}]}],
    }
    result = parse_bytes(_crash_doc(body))
    assert isinstance(result, CrashReport)
    assert result.warnings == (
        "thread 0 frame 0: no imageOffset",
        "thread 0 frame 1: imageIndex 9 does not match an image",
    )
    assert result.faulting.frames[0].image_offset is None
    assert result.faulting.frames[1].image_name is None


def test_faulting_thread_out_of_range_is_a_warning() -> None:
    result = parse_bytes(_crash_doc({"procName": "demo", "faultingThread": 3, "threads": [{"frames": []}]}))
    assert result.faulting is None
    assert "faultingThread 3 is out of range (1 threads)" in result.warnings


def test_missing_faulting_thread_uses_triggered_thread() -> None:
    result = parse_bytes(_crash_doc({"procName": "demo", "threads": [{"frames": []}, {"triggered": True, "frames": []}]}))
    assert result.faulting_thread == 1
    assert "no faultingThread; using the thread marked triggered" in result.warnings


def test_non_utf8_byte_is_replaced_and_reported() -> None:
    data = fixture_bytes("crasher-segv.ips").replace(b'"procRole": "Unspecified"', b'"procRole": "Unspec\xffified"', 1)
    assert b"\xff" in data
    result = parse_bytes(data)
    assert isinstance(result, CrashReport)
    assert result.process_name == "ct-crasher-segv"
    assert len(result.warnings) == 1 and result.warnings[0].startswith("non-UTF-8 bytes replaced")


def test_byte_order_mark_is_ignored() -> None:
    result = parse_bytes(b"\xef\xbb\xbf" + fixture_bytes("crasher-segv.ips"))
    assert isinstance(result, CrashReport) and result.warnings == ()


@running_as_root
def test_unreadable_file_is_a_permission_skip(tmp_path) -> None:
    path = tmp_path / "locked.ips"
    path.write_bytes(fixture_bytes("crasher-segv.ips"))
    path.chmod(0)
    try:
        result = parse_file(path)
    finally:
        path.chmod(0o600)
    assert isinstance(result, Skipped) and result.kind == "permission"


def test_missing_file_is_an_unreadable_skip(tmp_path) -> None:
    result = parse_file(tmp_path / "gone.ips")
    assert isinstance(result, Skipped) and result.kind == "unreadable"
    assert result.reason.startswith("FileNotFoundError")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-26 18:25:55.00 -0400", "2026-10-26T22:25:55Z"),
        ("2026-10-26 21:59:10.3663 -0400", "2026-10-27T01:59:10Z"),
        ("2026-01-05 09:00:00 +0100", "2026-01-05T08:00:00Z"),
        ("yesterday", None),
        ("2026-10-26 18:25:55", None),  # no offset: refuse to guess the zone
    ],
)
def test_parse_timestamp(raw: str, expected: str | None) -> None:
    assert parse_timestamp(raw) == expected


def test_parser_only_opens_files_for_reading(tmp_path, monkeypatch) -> None:
    import builtins

    modes = []
    real_open = builtins.open

    def spy(file, mode="r", *args, **kwargs):
        modes.append(mode)
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", spy)
    parse_file(fixture_path("crasher-segv.ips"))
    assert modes == ["rb"]
    assert os.access(fixture_path("crasher-segv.ips"), os.R_OK)
