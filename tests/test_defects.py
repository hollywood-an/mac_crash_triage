"""Phase 4: six deliberately injected defects, each traced to its documented handling.

Every defect is made by editing a copy of a real (anonymized) fixture, then run
through the whole pipeline: parse -> fingerprint -> ingest -> report/show. The
expected behavior for each is written in NOTES.md ("Injected defects").
`scripts/mutation_check.py` goes the other way: it breaks the code that handles
each defect and confirms these tests fail.
"""

from __future__ import annotations

import dataclasses
import json
import shutil

import pytest

from conftest import fixture_bytes, fixture_path
from crashtriage.cli import main
from crashtriage.fingerprint import fingerprint
from crashtriage.model import CrashReport, Skipped
from crashtriage.parser import parse_bytes
from crashtriage.store import connect, ingest, row_counts


def split(raw: bytes) -> tuple[dict, dict]:
    header, _, body = raw.decode("utf-8").partition("\n")
    return json.loads(header), json.loads(body)


def join(header: dict, body: dict) -> bytes:
    return (json.dumps(header) + "\n" + json.dumps(body, indent=2)).encode("utf-8")


@pytest.fixture
def conn(tmp_path):
    connection = connect(tmp_path / "defects.db")
    yield connection
    connection.close()


# 1. A frame with a missing offset --------------------------------------------------


def test_defect_frame_without_offset(conn, tmp_path, capsys) -> None:
    header, body = split(fixture_bytes("crasher-stripped-v1.ips"))
    del body["threads"][0]["frames"][1]["imageOffset"]  # an unsymbolicated app frame
    report = parse_bytes(join(header, body))

    # Handled: the report is still parsed, the frame is kept with offset None,
    # and the problem is recorded as a warning.
    assert isinstance(report, CrashReport)
    assert report.warnings == ("thread 0 frame 1: no imageOffset",)
    assert report.faulting.frames[1].image_offset is None
    fp = fingerprint(report)
    assert fp.tokens[1] == "ct-crasher-stripped+?"

    # ... and it flows through storage and display.
    path = tmp_path / "in" / "x.ips"
    path.parent.mkdir()
    path.write_bytes(join(header, body))
    assert ingest(conn, [path.parent]).added == 1
    stored = conn.execute("SELECT image_offset FROM frames WHERE frame_index = 1").fetchone()[0]
    assert stored is None
    conn.close()
    assert main(["show", report.incident_id, "--db", str(tmp_path / "defects.db")]) == 0
    out = capsys.readouterr().out
    assert "  1  ct-crasher-stripped  ?" in out
    assert "- thread 0 frame 1: no imageOffset" in out


# 2. A duplicate incident -----------------------------------------------------------


def test_defect_duplicate_incident(conn, tmp_path) -> None:
    folder = tmp_path / "reports"
    (folder / "Retired").mkdir(parents=True)
    raw = fixture_bytes("crasher-segv.ips")
    (folder / "crash.ips").write_bytes(raw)
    (folder / "Retired" / "crash.ips").write_bytes(raw)  # the same file, moved and copied
    header, body = split(raw)
    body["procRole"] = "Background"  # same incident id, different bytes
    (folder / "crash-edited.ips").write_bytes(join(header, body))

    # Handled: stored once; the other two count as duplicates; nothing else is written.
    result = ingest(conn, [folder])
    assert (result.parsed, result.added, result.duplicates) == (3, 1, 2)
    counts = row_counts(conn)
    assert counts["incidents"] == 1
    assert counts["frames"] == len(parse_bytes(raw).faulting.frames)


# 3. Two crashes of one bug that a naive hash would split ------------------------------


def test_defect_same_bug_naive_hash_splits(conn) -> None:
    base = parse_bytes(fixture_bytes("crasher-versioned-v1a.ips"))
    # A rebuilt binary: new UUID, new load address, every offset and symbolLocation
    # moved, a new version string. The bug (the functions on the stack) is the same.
    images = tuple(
        dataclasses.replace(i, uuid="00000000-0000-0000-0000-0000000000aa", base=(i.base or 0) + 0x8000) if i.index == 0 else i
        for i in base.images
    )
    frames = tuple(
        dataclasses.replace(f, image_offset=f.image_offset + 0x7c, symbol_location=(f.symbol_location or 0) + 4) if f.image_index == 0 else f
        for f in base.faulting.frames
    )
    rebuilt = dataclasses.replace(
        base,
        incident_id="00000000-0000-0000-0000-0000000000bb",
        source_sha256="b" * 64,
        process_version="1.1",
        images=images,
        threads=(dataclasses.replace(base.faulting, frames=frames),),
    )

    def naive(report):
        return hash(tuple((f.image_name, f.image_offset, f.symbol_location) for f in report.faulting.frames))

    assert naive(base) != naive(rebuilt)  # what the defect would look like
    assert fingerprint(base) == fingerprint(rebuilt)  # handled: one cluster


# 4. A crash whose top frames are all system frames ---------------------------------


def test_defect_all_system_frames(conn) -> None:
    raw = fixture_bytes("crasher-throw.ips")
    header, body = split(raw)
    # Point every frame at system images, as if the crash never reached app code.
    system = [i for i, image in enumerate(body["usedImages"]) if (image.get("path") or "").startswith("/usr/lib/")]
    for n, frame in enumerate(body["threads"][0]["frames"]):
        frame["imageIndex"] = system[n % len(system)]
    report = parse_bytes(join(header, body))
    fp = fingerprint(report)

    # Handled: the fingerprint falls back to the top system frames and says so.
    assert fp.basis == "system-only"
    assert fp.frame_indices == (0, 1, 2, 3, 4)

    # With the app frames left in place, the system frames on top are skipped.
    original = fingerprint(parse_bytes(raw))
    assert original.basis == "app" and original.frame_indices[0] == 9
    assert fp != original


# 5. A non-UTF-8 byte -----------------------------------------------------------------


def test_defect_non_utf8_byte(conn, tmp_path) -> None:
    raw = fixture_bytes("crasher-segv.ips").replace(b'"symbol": "store_id"', b'"symbol": "store_\xffid"', 1)
    assert b"\xff" in raw
    report = parse_bytes(raw)

    # Handled: decoded with U+FFFD in place of the bad byte, parsed, warned about.
    assert isinstance(report, CrashReport)
    assert report.faulting.frames[0].symbol == "store_�id"
    assert report.warnings[0].startswith("non-UTF-8 bytes replaced")
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "bad-byte.ips").write_bytes(raw)
    assert ingest(conn, [folder]).added == 1


# 6. An empty body ----------------------------------------------------------------------


def test_defect_empty_body(conn, tmp_path, capsys) -> None:
    header_line = fixture_bytes("crasher-segv.ips").split(b"\n", 1)[0]
    folder = tmp_path / "in"
    folder.mkdir()
    (folder / "empty-body.ips").write_bytes(header_line + b"\n")
    shutil.copy(fixture_path("crasher-trap.ips"), folder / "fine.ips")

    # Handled: skipped as malformed with a reason, and the rest of the folder is ingested.
    result = parse_bytes(header_line + b"\n")
    assert isinstance(result, Skipped)
    assert (result.kind, result.reason) == ("malformed", "crash header but the body is empty")
    assert main(["ingest", str(folder), "--db", str(tmp_path / "cli.db"), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["added"] == 1
    assert data["skipped"]["files"] == [
        {"path": str(folder / "empty-body.ips"), "kind": "malformed", "reason": "crash header but the body is empty"}
    ]
