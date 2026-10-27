"""SQLite store: idempotent ingest, faithful round trip, read-only inputs."""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3

import pytest

from conftest import CRASH_FIXTURES, FIXTURES, fixture_bytes, fixture_path
from crashtriage.fingerprint import fingerprint
from crashtriage.model import CrashReport
from crashtriage.parser import parse_file
from crashtriage.store import SchemaMismatch, add_report, connect, ingest, load_report, refingerprint, row_counts


@pytest.fixture
def conn(tmp_path):
    connection = connect(tmp_path / "test.db")
    yield connection
    connection.close()


def test_ingest_fixture_folder(conn) -> None:
    result = ingest(conn, [FIXTURES])
    assert result.parsed == result.added == len(CRASH_FIXTURES) == 15
    assert result.duplicates == 0
    # malformed, non-crash .ips, text .diag, and the README
    assert sorted(s.kind for s in result.skipped) == ["malformed", "non-crash", "not-ips", "not-ips"]
    assert result.files_seen == 19
    counts = row_counts(conn)
    assert counts["incidents"] == 15
    assert counts["threads"] == sum(len(parse_file(fixture_path(n)).threads) for n in CRASH_FIXTURES)
    assert counts["frames"] == sum(len(t.frames) for n in CRASH_FIXTURES for t in parse_file(fixture_path(n)).threads)


def test_ingest_is_idempotent(conn) -> None:
    ingest(conn, [FIXTURES])
    before = row_counts(conn)
    again = ingest(conn, [FIXTURES])
    assert (again.added, again.duplicates) == (0, 15)
    assert row_counts(conn) == before


def test_same_file_in_two_folders_is_stored_once(conn, tmp_path) -> None:
    for folder in ("a", "b/Retired"):
        (tmp_path / folder).mkdir(parents=True)
        shutil.copy(fixture_path("crasher-segv.ips"), tmp_path / folder / "copy.ips")
    result = ingest(conn, [tmp_path / "a", tmp_path / "b"])
    assert (result.added, result.duplicates) == (1, 1)
    assert row_counts(conn)["incidents"] == 1


def test_duplicate_incident_id_with_different_bytes_is_ignored(conn, tmp_path) -> None:
    original = fixture_bytes("crasher-segv.ips")
    edited = original.replace(b'"procRole": "Unspecified"', b'"procRole": "Edited"', 1)
    assert edited != original
    (tmp_path / "one.ips").write_bytes(original)
    (tmp_path / "two.ips").write_bytes(edited)
    result = ingest(conn, [tmp_path])
    assert (result.added, result.duplicates) == (1, 1)
    stored = conn.execute("SELECT source_path FROM incidents").fetchone()[0]
    assert stored.endswith("one.ips")  # first one wins; files are visited in sorted order


@pytest.mark.parametrize("name", CRASH_FIXTURES)
def test_round_trip_is_exact(conn, name) -> None:
    report = parse_file(fixture_path(name))
    assert add_report(conn, report) is True
    assert load_report(conn, report.incident_id) == report


def test_stored_fingerprint_matches(conn) -> None:
    ingest(conn, [FIXTURES])
    for incident_id, value, basis, top in conn.execute("SELECT incident_id, fingerprint, fingerprint_basis, top_frame FROM incidents"):
        expected = fingerprint(load_report(conn, incident_id))
        assert (value, basis, top) == (expected.value, expected.basis, expected.top_frame)


def test_clusters_in_the_fixture_set(conn) -> None:
    ingest(conn, [FIXTURES])
    rows = conn.execute(
        "SELECT process_name, COUNT(*) FROM incidents GROUP BY fingerprint HAVING COUNT(*) > 1 ORDER BY process_name"
    ).fetchall()
    assert [tuple(r) for r in rows] == [("ct-crasher-versioned", 3), ("dotnet", 3)]
    assert conn.execute("SELECT COUNT(DISTINCT fingerprint) FROM incidents").fetchone()[0] == 11


def test_load_missing_incident(conn) -> None:
    assert load_report(conn, "nope") is None


def test_refingerprint_reports_changes(conn) -> None:
    ingest(conn, [FIXTURES])
    assert refingerprint(conn) == 0
    conn.execute("UPDATE incidents SET fingerprint = 'stale'")
    conn.commit()
    assert refingerprint(conn) == 15


def test_reopening_keeps_data(tmp_path) -> None:
    path = tmp_path / "x.db"
    with connect(path) as first:
        ingest(first, [fixture_path("crasher-segv.ips")])
    first.close()
    second = connect(path)
    assert row_counts(second)["incidents"] == 1
    second.close()


def test_schema_mismatch_is_refused(tmp_path) -> None:
    path = tmp_path / "x.db"
    connect(path).close()
    raw = sqlite3.connect(path)
    raw.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'")
    raw.commit()
    raw.close()
    with pytest.raises(SchemaMismatch):
        connect(path)


def test_changed_fingerprint_version_recomputes_on_open(tmp_path) -> None:
    path = tmp_path / "x.db"
    conn = connect(path)
    ingest(conn, [FIXTURES])
    conn.execute("UPDATE incidents SET fingerprint = 'old'")
    conn.execute("UPDATE meta SET value = 'crashtriage-fp-v0' WHERE key = 'fingerprint_version'")
    conn.commit()
    conn.close()
    reopened = connect(path)
    assert reopened.execute("SELECT COUNT(*) FROM incidents WHERE fingerprint = 'old'").fetchone()[0] == 0
    reopened.close()


def _snapshot(folder):
    state = {}
    for dirpath, dirnames, filenames in os.walk(folder):
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.stat(path)
            digest = hashlib.sha256(open(path, "rb").read()).hexdigest() if os.path.isfile(path) else None
            state[path] = (st.st_mode, st.st_size, st.st_mtime_ns, digest)
    return state


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_ingest_never_writes_to_the_input_folders(conn, tmp_path) -> None:
    source = tmp_path / "DiagnosticReports"
    shutil.copytree(FIXTURES, source)
    for dirpath, dirnames, filenames in os.walk(source):
        for name in filenames:
            os.chmod(os.path.join(dirpath, name), 0o444)
    os.chmod(source, 0o555)
    try:
        before = _snapshot(source)
        result = ingest(conn, [source])
        after = _snapshot(source)
    finally:
        os.chmod(source, 0o755)
    assert result.added == 15
    assert after == before
