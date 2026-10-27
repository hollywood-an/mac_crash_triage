"""SQLite storage for parsed crash reports.

Tables: incidents (one row per crash), images, threads and frames. Ingest is
idempotent: an incident whose id or file contents are already stored is counted as
a duplicate and adds no rows. Each file is written in its own transaction, so a
failure never leaves half an incident behind.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from .discover import scan
from .fingerprint import FINGERPRINT_VERSION, fingerprint
from .model import CrashReport, Frame, Image, Skipped, ThreadRec

SCHEMA_VERSION = "1"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id           TEXT PRIMARY KEY,
    source_sha256         TEXT NOT NULL UNIQUE,
    source_path           TEXT NOT NULL,
    timestamp             TEXT,
    timestamp_raw         TEXT,
    process_name          TEXT NOT NULL,
    process_version       TEXT,
    build_version         TEXT,
    process_path          TEXT,
    pid                   INTEGER,
    os_version            TEXT,
    os_build              TEXT,
    bug_type              TEXT NOT NULL,
    cpu_type              TEXT,
    exception_type        TEXT,
    signal                TEXT,
    exception_subtype     TEXT,
    termination_namespace TEXT,
    termination_code      INTEGER,
    termination_indicator TEXT,
    faulting_thread       INTEGER,
    warnings              TEXT NOT NULL,
    fingerprint           TEXT NOT NULL,
    fingerprint_basis     TEXT NOT NULL,
    top_frame             TEXT
);
CREATE INDEX IF NOT EXISTS incidents_by_fingerprint ON incidents (fingerprint);
CREATE INDEX IF NOT EXISTS incidents_by_process ON incidents (process_name);
CREATE INDEX IF NOT EXISTS incidents_by_time ON incidents (timestamp);

CREATE TABLE IF NOT EXISTS images (
    incident_id TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    image_index INTEGER NOT NULL,
    name        TEXT,
    path        TEXT,
    uuid        TEXT,
    base        INTEGER,
    size        INTEGER,
    source      TEXT,
    arch        TEXT,
    bundle_id   TEXT,
    version     TEXT,
    PRIMARY KEY (incident_id, image_index)
);

CREATE TABLE IF NOT EXISTS threads (
    incident_id     TEXT NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    thread_index    INTEGER NOT NULL,
    thread_id       INTEGER,
    name            TEXT,
    queue           TEXT,
    triggered       INTEGER NOT NULL,
    original_length INTEGER,
    PRIMARY KEY (incident_id, thread_index)
);

CREATE TABLE IF NOT EXISTS frames (
    incident_id     TEXT NOT NULL,
    thread_index    INTEGER NOT NULL,
    frame_index     INTEGER NOT NULL,
    image_index     INTEGER,
    image_name      TEXT,
    image_offset    INTEGER,
    symbol          TEXT,
    symbol_location INTEGER,
    source_file     TEXT,
    source_line     INTEGER,
    PRIMARY KEY (incident_id, thread_index, frame_index),
    FOREIGN KEY (incident_id, thread_index) REFERENCES threads (incident_id, thread_index) ON DELETE CASCADE
);
"""


class SchemaMismatch(Exception):
    pass


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (or create) a crashtriage database."""
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    with conn:
        conn.executescript(SCHEMA)
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)", (SCHEMA_VERSION,))
        conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('fingerprint_version', ?)", (FINGERPRINT_VERSION,))
    meta = dict(conn.execute("SELECT key, value FROM meta").fetchall())
    if meta["schema_version"] != SCHEMA_VERSION:
        raise SchemaMismatch(f"database schema {meta['schema_version']}, this tool writes {SCHEMA_VERSION}")
    if meta["fingerprint_version"] != FINGERPRINT_VERSION:
        refingerprint(conn)
        with conn:
            conn.execute("UPDATE meta SET value = ? WHERE key = 'fingerprint_version'", (FINGERPRINT_VERSION,))
    return conn


@dataclass
class IngestResult:
    files_seen: int = 0
    parsed: int = 0
    added: int = 0
    duplicates: int = 0
    skipped: list[Skipped] = field(default_factory=list)


def ingest(conn: sqlite3.Connection, folders: list[str | Path]) -> IngestResult:
    result = scan(folders)
    out = IngestResult(files_seen=result.files_seen, parsed=len(result.reports), skipped=result.skipped)
    for report in result.reports:
        if add_report(conn, report):
            out.added += 1
        else:
            out.duplicates += 1
    return out


def add_report(conn: sqlite3.Connection, report: CrashReport) -> bool:
    """Store one report. Returns False (and writes nothing) if it is already stored."""
    fp = fingerprint(report)
    with conn:
        cursor = conn.execute(
            """INSERT OR IGNORE INTO incidents VALUES (
                :incident_id, :source_sha256, :source_path, :timestamp, :timestamp_raw,
                :process_name, :process_version, :build_version, :process_path, :pid,
                :os_version, :os_build, :bug_type, :cpu_type, :exception_type, :signal,
                :exception_subtype, :termination_namespace, :termination_code,
                :termination_indicator, :faulting_thread, :warnings, :fingerprint,
                :fingerprint_basis, :top_frame)""",
            {
                "incident_id": report.incident_id,
                "source_sha256": report.source_sha256,
                "source_path": report.source_path,
                "timestamp": report.timestamp,
                "timestamp_raw": report.timestamp_raw,
                "process_name": report.process_name,
                "process_version": report.process_version,
                "build_version": report.build_version,
                "process_path": report.process_path,
                "pid": report.pid,
                "os_version": report.os_version,
                "os_build": report.os_build,
                "bug_type": report.bug_type,
                "cpu_type": report.cpu_type,
                "exception_type": report.exception_type,
                "signal": report.signal,
                "exception_subtype": report.exception_subtype,
                "termination_namespace": report.termination_namespace,
                "termination_code": report.termination_code,
                "termination_indicator": report.termination_indicator,
                "faulting_thread": report.faulting_thread,
                "warnings": json.dumps(list(report.warnings)),
                "fingerprint": fp.value,
                "fingerprint_basis": fp.basis,
                "top_frame": fp.top_frame,
            },
        )
        if cursor.rowcount == 0:
            return False
        conn.executemany(
            "INSERT INTO images VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (report.incident_id, i.index, i.name, i.path, i.uuid, i.base, i.size, i.source, i.arch, i.bundle_id, i.version)
                for i in report.images
            ],
        )
        conn.executemany(
            "INSERT INTO threads VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (report.incident_id, t.index, t.thread_id, t.name, t.queue, int(t.triggered), t.original_length)
                for t in report.threads
            ],
        )
        conn.executemany(
            "INSERT INTO frames VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    report.incident_id,
                    t.index,
                    n,
                    f.image_index,
                    f.image_name,
                    f.image_offset,
                    f.symbol,
                    f.symbol_location,
                    f.source_file,
                    f.source_line,
                )
                for t in report.threads
                for n, f in enumerate(t.frames)
            ],
        )
    return True


def load_report(conn: sqlite3.Connection, incident_id: str) -> CrashReport | None:
    """Rebuild a CrashReport from the database (the inverse of add_report)."""
    row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        return None
    images = tuple(
        Image(
            index=r["image_index"],
            name=r["name"],
            path=r["path"],
            uuid=r["uuid"],
            base=r["base"],
            size=r["size"],
            source=r["source"],
            arch=r["arch"],
            bundle_id=r["bundle_id"],
            version=r["version"],
        )
        for r in conn.execute("SELECT * FROM images WHERE incident_id = ? ORDER BY image_index", (incident_id,))
    )
    frames: dict[int, list[Frame]] = {}
    for r in conn.execute("SELECT * FROM frames WHERE incident_id = ? ORDER BY thread_index, frame_index", (incident_id,)):
        frames.setdefault(r["thread_index"], []).append(
            Frame(
                image_index=r["image_index"],
                image_name=r["image_name"],
                image_offset=r["image_offset"],
                symbol=r["symbol"],
                symbol_location=r["symbol_location"],
                source_file=r["source_file"],
                source_line=r["source_line"],
            )
        )
    threads = tuple(
        ThreadRec(
            index=r["thread_index"],
            thread_id=r["thread_id"],
            name=r["name"],
            queue=r["queue"],
            triggered=bool(r["triggered"]),
            frames=tuple(frames.get(r["thread_index"], ())),
            original_length=r["original_length"],
        )
        for r in conn.execute("SELECT * FROM threads WHERE incident_id = ? ORDER BY thread_index", (incident_id,))
    )
    return CrashReport(
        incident_id=row["incident_id"],
        timestamp=row["timestamp"],
        timestamp_raw=row["timestamp_raw"],
        process_name=row["process_name"],
        process_version=row["process_version"],
        build_version=row["build_version"],
        process_path=row["process_path"],
        pid=row["pid"],
        os_version=row["os_version"],
        os_build=row["os_build"],
        bug_type=row["bug_type"],
        cpu_type=row["cpu_type"],
        exception_type=row["exception_type"],
        signal=row["signal"],
        exception_subtype=row["exception_subtype"],
        termination_namespace=row["termination_namespace"],
        termination_code=row["termination_code"],
        termination_indicator=row["termination_indicator"],
        faulting_thread=row["faulting_thread"],
        threads=threads,
        images=images,
        source_sha256=row["source_sha256"],
        warnings=tuple(json.loads(row["warnings"])),
        source_path=row["source_path"],
    )


def incident_ids(conn: sqlite3.Connection) -> list[str]:
    return [r[0] for r in conn.execute("SELECT incident_id FROM incidents ORDER BY incident_id")]


def refingerprint(conn: sqlite3.Connection) -> int:
    """Recompute every stored fingerprint (after the rule or the frames changed).
    Returns how many incidents changed cluster."""
    changed = 0
    for incident_id in incident_ids(conn):
        report = load_report(conn, incident_id)
        fp = fingerprint(report)
        with conn:
            cursor = conn.execute(
                """UPDATE incidents SET fingerprint = ?, fingerprint_basis = ?, top_frame = ?
                   WHERE incident_id = ? AND (fingerprint != ? OR fingerprint_basis != ? OR top_frame IS NOT ?)""",
                (fp.value, fp.basis, fp.top_frame, incident_id, fp.value, fp.basis, fp.top_frame),
            )
            changed += cursor.rowcount
    return changed


def row_counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in ("incidents", "images", "threads", "frames")}
