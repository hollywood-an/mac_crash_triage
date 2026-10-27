"""Fingerprint stability (same bug -> same id) and difference (different bug -> different id)."""

from __future__ import annotations

import dataclasses
import hashlib
from itertools import combinations

import pytest

from conftest import CRASH_FIXTURES, fixture_path
from crashtriage.fingerprint import TOP_N, classify, fingerprint, frame_token
from crashtriage.model import CrashReport, Frame
from crashtriage.parser import parse_file


def parsed(name: str) -> CrashReport:
    report = parse_file(fixture_path(name))
    assert isinstance(report, CrashReport)
    return report


def fp(name: str) -> str:
    return fingerprint(parsed(name)).value


def with_faulting_frames(report: CrashReport, change) -> CrashReport:
    """A copy of the report with the faulting thread's frames passed through `change`."""
    threads = tuple(
        dataclasses.replace(t, frames=tuple(change(list(t.frames)))) if t.index == report.faulting_thread else t
        for t in report.threads
    )
    return dataclasses.replace(report, threads=threads)


def naive_fingerprint(report: CrashReport) -> str:
    """What a first attempt would do: hash the faulting stack exactly as reported."""
    frames = report.faulting.frames
    material = repr([report.process_name, report.exception_type] + [(f.image_name, f.image_offset) for f in frames])
    return hashlib.sha256(material.encode()).hexdigest()[:16]


# --- the same bug ---------------------------------------------------------------


def test_same_bug_across_app_versions_shares_a_fingerprint() -> None:
    v1a, v1b, v2 = (parsed(f"crasher-versioned-{v}.ips") for v in ("v1a", "v1b", "v2"))
    assert (v1a.process_version, v2.process_version) == ("1.0", "2.0")
    assert fingerprint(v1a) == fingerprint(v1b) == fingerprint(v2)
    # Every image offset of the bug moved in version 2 ...
    assert v1a.faulting.frames[0].image_offset != v2.faulting.frames[0].image_offset
    # ... so a hash over raw frames splits one bug into two clusters.
    assert naive_fingerprint(v1a) == naive_fingerprint(v1b) != naive_fingerprint(v2)


def test_same_bug_in_jit_code_shares_a_fingerprint() -> None:
    a, b = parsed("dotnet-abort-a.ips"), parsed("dotnet-abort-b.ips")
    assert fingerprint(a) == fingerprint(b)
    # The JIT frames hold per-run absolute addresses, which a naive hash would include.
    assert naive_fingerprint(a) != naive_fingerprint(b)


def test_fingerprint_ignores_what_changes_between_builds() -> None:
    base = parsed("crasher-versioned-v1a.ips")
    expected = fingerprint(base).value

    def shift(frames):
        return [dataclasses.replace(f, image_offset=f.image_offset + 0x400, symbol_location=(f.symbol_location or 0) + 8) for f in frames]

    assert fingerprint(with_faulting_frames(base, shift)).value == expected
    images = tuple(dataclasses.replace(i, uuid="00000000-0000-0000-0000-000000000099", base=(i.base or 0) + 0x4000) for i in base.images)
    assert fingerprint(dataclasses.replace(base, images=images)).value == expected
    assert fingerprint(dataclasses.replace(base, process_version="9.9", pid=1, timestamp=None)).value == expected


def test_jit_frame_addresses_do_not_matter() -> None:
    base = parsed("dotnet-abort-a.ips")

    def move_jit(frames):
        return [dataclasses.replace(f, image_offset=f.image_offset + 0x1000) if f.image_index == 13 else f for f in frames]

    assert fingerprint(with_faulting_frames(base, move_jit)) == fingerprint(base)


def test_frames_below_the_top_n_do_not_matter() -> None:
    base = parsed("dotnet-abort-a.ips")
    used = fingerprint(base).tokens
    assert len(used) == TOP_N

    def change_deep_frames(frames):
        # dotnet frame 21 is the 6th app frame (frames 0-2 are system, 6-7 are JIT).
        return frames[:21] + [dataclasses.replace(f, symbol="something_else") for f in frames[21:]]

    assert fingerprint(with_faulting_frames(base, change_deep_frames)) == fingerprint(base)


# --- different bugs -------------------------------------------------------------


def test_every_distinct_crasher_bug_has_its_own_fingerprint() -> None:
    names = [n for n in CRASH_FIXTURES if n.startswith("crasher-") and not n.startswith(("crasher-versioned-v1b", "crasher-versioned-v2"))]
    values = {n: fp(n) for n in names}
    for a, b in combinations(names, 2):
        if {a, b} == {"crasher-stripped-v1.ips", "crasher-stripped-v2.ips"}:
            continue  # same bug; see the limitation test below
        assert values[a] != values[b], (a, b)


def test_same_signal_different_code_differs() -> None:
    # Both are EXC_BAD_ACCESS / SIGSEGV at address 0, in different functions.
    segv, versioned = parsed("crasher-segv.ips"), parsed("crasher-versioned-v1a.ips")
    assert (segv.exception_type, segv.exception_subtype) == (versioned.exception_type, versioned.exception_subtype)
    assert fingerprint(segv) != fingerprint(versioned)


@pytest.mark.parametrize(
    "change",
    [
        lambda r: dataclasses.replace(r, process_name="other"),
        lambda r: dataclasses.replace(r, exception_type="EXC_CRASH"),
        lambda r: with_faulting_frames(r, lambda fs: [dataclasses.replace(fs[0], symbol="validate")] + fs[1:]),
        lambda r: with_faulting_frames(r, lambda fs: fs[1:]),
    ],
    ids=["process", "exception-type", "top-symbol", "missing-top-frame"],
)
def test_each_input_of_the_hash_matters(change) -> None:
    base = parsed("crasher-versioned-v1a.ips")
    assert fingerprint(change(base)) != fingerprint(base)


# --- which frames are used ------------------------------------------------------


def test_system_frames_on_top_are_skipped() -> None:
    throw = fingerprint(parsed("crasher-throw.ips"))
    assert throw.basis == "app"
    assert throw.tokens == ("ct-crasher-throw!load_config(char const*)", "ct-crasher-throw!main")
    swift = fingerprint(parsed("crasher-swift.ips"))
    assert swift.top_frame == "ct-crasher-swift!requirePositive(_:)"
    dotnet = fingerprint(parsed("dotnet-abort-a.ips"))
    assert dotnet.tokens[:3] == ("libcoreclr.dylib!PROCAbort", "libcoreclr.dylib!TerminateProcess", "libcoreclr.dylib!SfiNext")


def test_crash_entirely_in_the_os_uses_system_frames() -> None:
    result = fingerprint(parsed("coreaudiod-segv.ips"))
    assert result.basis == "system-only"
    assert result.tokens[:3] == ("BTAudioHALPlugin+0x746a4", "BTAudioHALPlugin+0x746a0", "BTAudioHALPlugin+0x59414")
    assert result.tokens[3].startswith("CoreAudio!HALS_UCPlugIn::ObjectSetPropertyData(")


def test_unsymbolicated_frames_split_across_versions() -> None:
    """Documented limitation: without symbols, offsets identify frames, and offsets move."""
    v1, v2 = fingerprint(parsed("crasher-stripped-v1.ips")), fingerprint(parsed("crasher-stripped-v2.ips"))
    assert v1.tokens == ("ct-crasher-stripped+0x528", "ct-crasher-stripped+0x510", "ct-crasher-stripped+0x4e8")
    assert v1 != v2


def test_no_usable_frames() -> None:
    report = with_faulting_frames(parsed("crasher-segv.ips"), lambda fs: [])
    result = fingerprint(report)
    assert (result.basis, result.tokens, result.top_frame) == ("no-frames", (), None)


def test_classify_main_image_of_a_system_process_is_app() -> None:
    report = parsed("coreaudiod-segv.ips")
    main = report.main_image
    assert main.path == "/usr/sbin/coreaudiod"
    frame = Frame(image_index=main.index, image_name=main.name, image_offset=16)
    assert classify(frame, report) == "app"
    assert classify(Frame(image_index=99, image_name=None, image_offset=1), report) == "anonymous"


@pytest.mark.parametrize(
    ("frame", "token"),
    [
        (Frame(0, "app", 0x528, "parse_record", 12), "app!parse_record"),
        (Frame(0, "app", 0x528), "app+0x528"),
        (Frame(0, "app", None), "app+?"),
        (Frame(None, None, 7), "?+0x7"),
    ],
)
def test_frame_token(frame: Frame, token: str) -> None:
    assert frame_token(frame) == token


def test_fingerprint_values_are_pinned() -> None:
    """Changing the rule must be deliberate: bump FINGERPRINT_VERSION and update these."""
    assert fp("crasher-versioned-v1a.ips") == "bd6f08520a5ab6c0"
    assert fp("dotnet-abort-a.ips") == "edb224fcb71d2a42"
    assert fp("coreaudiod-segv.ips") == "c16751fb76f17124"
