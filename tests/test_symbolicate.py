"""--symbolicate: Mach-O UUIDs, atos output, frame updates, and a real atos run."""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import uuid as uuidlib

import pytest

from conftest import FIXTURES, fixture_path
from crashtriage import symbolicate as sym
from crashtriage.cli import main
from crashtriage.fingerprint import fingerprint
from crashtriage.model import CrashReport
from crashtriage.parser import parse_bytes, parse_file
from crashtriage.store import connect, ingest, load_report
from crashtriage.symbolicate import (
    DsymFile,
    MachOError,
    find_dsyms,
    macho_uuids,
    parse_atos_line,
    symbolicate_report,
    symbolicate_stored,
)

UUID_A = "5ca1ab1e-0000-4000-8000-000000000001"
UUID_B = "5ca1ab1e-0000-4000-8000-000000000002"


def thin_macho(uuid: str, cputype: int = sym.CPU_TYPE_ARM64, subtype: int = 0, with_uuid: bool = True) -> bytes:
    segment = struct.pack("<II", 0x19, 72) + bytes(64)  # an LC_SEGMENT_64 to step over
    commands = [segment]
    if with_uuid:
        commands.append(struct.pack("<II", sym.LC_UUID, 24) + uuidlib.UUID(uuid).bytes)
    body = b"".join(commands)
    header = struct.pack("<IiIIIIII", sym.MH_MAGIC_64, cputype, subtype, 2, len(commands), len(body), 0, 0)
    return header + body


def fat_macho(*slices: bytes) -> bytes:
    header = struct.pack(">II", sym.FAT_MAGIC, len(slices))
    offset = 4096
    entries, blobs = b"", b""
    for blob in slices:
        cputype = struct.unpack_from("<i", blob, 4)[0]
        entries += struct.pack(">iIIII", cputype, 0, offset + len(blobs), len(blob), 12)
        blobs += blob
    return (header + entries).ljust(offset, b"\0") + blobs


# --- Mach-O ---------------------------------------------------------------------------


def test_thin_macho_uuid_and_arch() -> None:
    assert macho_uuids(thin_macho(UUID_A)) == [(UUID_A, "arm64")]
    assert macho_uuids(thin_macho(UUID_A, subtype=0x80000002)) == [(UUID_A, "arm64e")]
    assert macho_uuids(thin_macho(UUID_A, cputype=sym.CPU_TYPE_X86_64)) == [(UUID_A, "x86_64")]


def test_fat_macho_lists_every_slice() -> None:
    data = fat_macho(thin_macho(UUID_A), thin_macho(UUID_B, cputype=sym.CPU_TYPE_X86_64))
    assert macho_uuids(data) == [(UUID_A, "arm64"), (UUID_B, "x86_64")]


@pytest.mark.parametrize(
    "data",
    [b"", b"\x7fELF" + bytes(60), thin_macho(UUID_A)[:40], thin_macho(UUID_A, with_uuid=False)],
    ids=["empty", "elf", "truncated", "no-uuid"],
)
def test_bad_macho_raises(data: bytes) -> None:
    with pytest.raises(MachOError):
        macho_uuids(data)


def test_find_dsyms_in_bundles_folders_and_files(tmp_path) -> None:
    bundle = tmp_path / "deep" / "app.dSYM" / "Contents" / "Resources" / "DWARF"
    bundle.mkdir(parents=True)
    (bundle / "app").write_bytes(thin_macho(UUID_A))
    (bundle / "README").write_text("not mach-o")
    loose = tmp_path / "loose-dwarf"
    loose.write_bytes(thin_macho(UUID_B))
    index = find_dsyms([tmp_path])
    assert list(index) == [UUID_A]
    assert index[UUID_A] == DsymFile(str(bundle / "app"), "arm64")
    assert set(find_dsyms([tmp_path / "deep" / "app.dSYM", loose])) == {UUID_A, UUID_B}
    assert find_dsyms([tmp_path / "missing"]) == {}


# --- atos output ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("parse_record (in ct-crasher-stripped) (versioned.c:24)", ("parse_record", "versioned.c", 24)),
        ("load_config(char const*) (in ct-crasher-throw) (throw.cpp:6)", ("load_config(char const*)", "throw.cpp", 6)),
        ("requirePositive(_:) (in ct-crasher-swift) (fatal.swift:6)", ("requirePositive(_:)", "fatal.swift", 6)),
        ("store_id (in segv) + 20", ("store_id", None, None)),
        ("0x0000000100000010 (in ct-crasher-stripped)", None),
        ("0x00000001000005a4 (in ct-crasher-stripped) + 12", None),
        ("0x104099999", None),
        ("", None),
    ],
)
def test_parse_atos_line(line, expected) -> None:
    result = parse_atos_line(line)
    assert (None if result is None else (result.symbol, result.source_file, result.source_line)) == expected


# --- symbolicating a report -----------------------------------------------------------

NAMES = {0x528: "parse_record", 0x510: "handle_request", 0x4e8: "main", 0x5a4: "parse_record", 0x530: "handle_request"}
LINES = {"parse_record": 24, "handle_request": 38, "main": 44}


def fake_atos(calls: list):
    def runner(args: list[str]) -> str:
        calls.append(args)
        assert args[0] == "-o" and args[2] == "-arch" and args[4] == "-l"
        base = int(args[5], 16)
        out = []
        for address in args[6:]:
            name = NAMES.get(int(address, 16) - base)
            out.append(f"{name} (in ct-crasher-stripped) (versioned.c:{LINES[name]})" if name else f"{address} (in ct-crasher-stripped)")
        return "\n".join(out) + "\n"

    return runner


def index_for(report: CrashReport) -> dict[str, DsymFile]:
    return {report.images[0].uuid.lower(): DsymFile("/fake/ct-crasher-stripped", "arm64")}


def test_stripped_builds_merge_after_symbolication() -> None:
    v1, v2 = parse_file(fixture_path("crasher-stripped-v1.ips")), parse_file(fixture_path("crasher-stripped-v2.ips"))
    assert fingerprint(v1) != fingerprint(v2)
    calls: list = []
    new1, stats1 = symbolicate_report(v1, index_for(v1), fake_atos(calls))
    new2, stats2 = symbolicate_report(v2, index_for(v2), fake_atos(calls))
    assert (stats1.frames_resolved, stats1.frames_unresolved, stats1.images_matched) == (3, 0, 1)
    assert stats2.frames_resolved == 3
    assert [(f.symbol, f.source_file, f.source_line) for f in new1.faulting.frames[:3]] == [
        ("parse_record", "versioned.c", 24),
        ("handle_request", "versioned.c", 38),
        ("main", "versioned.c", 44),
    ]
    assert fingerprint(new1) == fingerprint(new2)
    assert fingerprint(new1).tokens == ("ct-crasher-stripped!parse_record", "ct-crasher-stripped!handle_request", "ct-crasher-stripped!main")
    # One atos call per image, with load address = image base and address = base + offset.
    base = v1.images[0].base
    assert calls[0] == ["-o", "/fake/ct-crasher-stripped", "-arch", "arm64", "-l", hex(base)] + [hex(base + o) for o in (0x4E8, 0x510, 0x528)]
    # dyld's frame was already named and is untouched.
    assert new1.faulting.frames[3] == v1.faulting.frames[3]


def test_uuid_mismatch_leaves_report_alone() -> None:
    report = parse_file(fixture_path("crasher-stripped-v1.ips"))
    calls: list = []
    new, stats = symbolicate_report(report, {UUID_A: DsymFile("/x", "arm64")}, fake_atos(calls))
    assert new is report and calls == [] and stats.images_matched == 0


def test_already_symbolicated_report_needs_no_atos() -> None:
    report = parse_file(fixture_path("crasher-versioned-v1a.ips"))
    calls: list = []
    new, _ = symbolicate_report(report, index_for(report), fake_atos(calls))
    assert new is report and calls == []


def test_unexpected_atos_output_is_not_applied() -> None:
    report = parse_file(fixture_path("crasher-stripped-v1.ips"))
    new, stats = symbolicate_report(report, index_for(report), lambda args: "parse_record (in x) (versioned.c:24)\n")
    assert new is report
    assert (stats.frames_resolved, stats.frames_unresolved) == (0, 3)


def test_unresolved_addresses_stay_unnamed() -> None:
    report = parse_file(fixture_path("crasher-stripped-v1.ips"))
    lines = "main (in x) (versioned.c:44)\n0x0000000100000510 (in x)\n0x0000000100000528 (in x)\n"
    new, stats = symbolicate_report(report, index_for(report), lambda args: lines)
    assert (stats.frames_resolved, stats.frames_unresolved) == (1, 2)
    assert [f.symbol for f in new.faulting.frames[:3]] == [None, None, "main"]


def test_symbolicate_stored_merges_clusters_and_is_idempotent(tmp_path) -> None:
    conn = connect(tmp_path / "s.db")
    ingest(conn, [FIXTURES])
    v1 = parse_file(fixture_path("crasher-stripped-v1.ips"))
    v2 = parse_file(fixture_path("crasher-stripped-v2.ips"))
    index = {**index_for(v1), **index_for(v2)}
    first = symbolicate_stored(conn, index, fake_atos([]))
    assert (first.incidents_changed, first.frames_resolved, first.clusters_before, first.clusters_after) == (2, 6, 11, 10)
    for incident_id in (v1.incident_id, v2.incident_id):
        stored = conn.execute("SELECT fingerprint, top_frame FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        report = load_report(conn, incident_id)
        assert tuple(stored) == (fingerprint(report).value, "ct-crasher-stripped!parse_record")
    calls: list = []
    second = symbolicate_stored(conn, index, fake_atos(calls))
    assert (second.incidents_changed, second.frames_resolved, calls) == (0, 0, [])
    conn.close()


# --- the CLI flag ---------------------------------------------------------------------


def test_ingest_symbolicate_flag(tmp_path, monkeypatch, capsys) -> None:
    v1 = parse_file(fixture_path("crasher-stripped-v1.ips"))
    v2 = parse_file(fixture_path("crasher-stripped-v2.ips"))
    dsyms = tmp_path / "dsyms"
    for n, report in enumerate((v1, v2)):
        dwarf = dsyms / f"v{n}" / "ct-crasher-stripped.dSYM" / "Contents" / "Resources" / "DWARF"
        dwarf.mkdir(parents=True)
        (dwarf / "ct-crasher-stripped").write_bytes(thin_macho(report.images[0].uuid))
    monkeypatch.setattr(sym, "run_atos", fake_atos([]))
    monkeypatch.setattr(sym, "atos_path", lambda: "/usr/bin/atos")
    db = str(tmp_path / "cli.db")
    assert main(["ingest", str(FIXTURES), "--db", db, "--symbolicate", str(dsyms), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["symbolication"] == {
        "dsyms": 2,
        "incidents_changed": 2,
        "frames_resolved": 6,
        "frames_unresolved": 0,
        "clusters_before": 11,
        "clusters_after": 10,
    }
    assert main(["report", "--db", db, "--process", "ct-crasher-stripped"]) == 0
    assert "| 1 | 2 | ct-crasher-stripped |" in capsys.readouterr().out


def test_symbolicate_flag_without_dsyms_fails_before_ingesting(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sym, "atos_path", lambda: "/usr/bin/atos")
    db = tmp_path / "x.db"
    assert main(["ingest", str(FIXTURES), "--db", str(db), "--symbolicate", str(tmp_path)]) == 1
    assert capsys.readouterr().err == f"crashtriage: no dSYM found under {tmp_path}\n"
    assert not db.exists()


# --- the real toolchain ---------------------------------------------------------------

TOOLS = all(shutil.which(t) for t in ("xcrun", "atos")) and subprocess.run(["xcrun", "--find", "clang"], capture_output=True).returncode == 0
SOURCE = """
#include <stdio.h>
__attribute__((noinline)) int work_func(int x) { return x * 3 + 1; }
int main(int argc, char **argv) { (void)argv; printf("%d\\n", work_func(argc)); return 0; }
"""


@pytest.mark.skipif(not TOOLS, reason="needs the Xcode command line tools (clang, dsymutil, atos)")
def test_real_atos_names_a_stripped_binary(tmp_path) -> None:
    (tmp_path / "app.c").write_text(SOURCE)
    run = lambda *cmd: subprocess.run(cmd, cwd=tmp_path, check=True, capture_output=True, text=True).stdout  # noqa: E731
    run("xcrun", "clang", "-g", "-O0", "-c", "app.c", "-o", "app.o")
    run("xcrun", "clang", "app.o", "-o", "app")
    run("xcrun", "dsymutil", "app", "-o", "dsyms/app.dSYM")
    address = int(next(line.split()[0] for line in run("xcrun", "nm", "app").splitlines() if line.endswith(" _work_func")), 16)
    run("xcrun", "strip", "app")
    run("codesign", "--force", "--sign", "-", "app")

    [(binary_uuid, arch)] = macho_uuids((tmp_path / "app").read_bytes())
    dwarfdump = run("xcrun", "dwarfdump", "--uuid", "dsyms/app.dSYM")
    assert binary_uuid.upper() in dwarfdump  # our LC_UUID reader agrees with dwarfdump

    base = 0x104000000
    offset = address - 0x100000000 + 4  # inside work_func
    body = {
        "procName": "app",
        "captureTime": "2026-10-27 12:00:00.0000 -0400",
        "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"},
        "faultingThread": 0,
        "usedImages": [{"source": "P", "arch": arch, "base": base, "size": 16384, "uuid": binary_uuid, "name": "app", "path": "/tmp/app"}],
        "threads": [{"triggered": True, "frames": [{"imageIndex": 0, "imageOffset": offset}]}],
    }
    header = {"bug_type": "309", "incident_id": "00000000-0000-0000-0000-00000000c0de", "app_name": "app"}
    report = parse_bytes((json.dumps(header) + "\n" + json.dumps(body)).encode())
    assert report.faulting.frames[0].symbol is None

    named, stats = symbolicate_report(report, find_dsyms([tmp_path / "dsyms"]))
    frame = named.faulting.frames[0]
    assert stats.frames_resolved == 1
    assert (frame.symbol, frame.source_file, frame.source_line) == ("work_func", "app.c", 3)
