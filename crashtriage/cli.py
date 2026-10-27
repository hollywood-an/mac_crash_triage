"""Command-line interface.

    crashtriage ingest [FOLDER ...]                        read reports into the database
    crashtriage report [--since 7d] [--process NAME] [--top N]
    crashtriage show <incident-id | fingerprint>
    crashtriage trend [--weeks N] [--process NAME]

Every command takes --db PATH (default ./crashtriage.db) and --json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from typing import Any

from . import __version__
from .discover import default_folders
from .report import (
    NotFound,
    clusters,
    parse_as_of,
    parse_since,
    render_report_markdown,
    render_show_markdown,
    render_trend_markdown,
    report_json,
    resolve,
    show_json,
    trend,
)
from .store import SchemaMismatch, connect, ingest, row_counts

# Skips worth listing file by file; the rest are expected and only counted.
_LISTED_KINDS = ("permission", "unreadable", "malformed")
_LIST_LIMIT = 10


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default="crashtriage.db", help="SQLite database file (default: ./crashtriage.db)")
    common.add_argument("--json", action="store_true", help="print machine-readable JSON")

    parser = argparse.ArgumentParser(prog="crashtriage", description="Group macOS crash reports by root cause and rank them.")
    parser.add_argument("--version", action="version", version=f"crashtriage {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = commands.add_parser("ingest", parents=[common], help="read crash reports into the database (read-only on the inputs)")
    p.add_argument("folders", nargs="*", help="folders or files (default: ~/Library/Logs/DiagnosticReports and /Library/Logs/DiagnosticReports)")

    p = commands.add_parser("report", parents=[common], help="crash clusters ranked by count, as a Markdown table")
    p.add_argument("--since", help="only crashes since 7d, 24h, 2w, YYYY-MM-DD or an ISO 8601 time")
    p.add_argument("--process", help="only this process (exact name, any case)")
    p.add_argument("--top", type=_positive_int, help="show only the N largest clusters")
    p.add_argument("--as-of", help="treat this time as now (YYYY-MM-DD means the end of that day, UTC)")

    p = commands.add_parser("show", parents=[common], help="one crash and its faulting thread")
    p.add_argument("id", help="incident id (or a unique prefix), or a cluster fingerprint (shows its latest crash)")

    p = commands.add_parser("trend", parents=[common], help="crashes per ISO week per process")
    p.add_argument("--weeks", type=_positive_int, default=4, help="number of weeks ending with the current one (default 4)")
    p.add_argument("--process", help="only this process (exact name, any case)")
    p.add_argument("--as-of", help="treat this time as now (YYYY-MM-DD means the end of that day, UTC)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "ingest":
            return _ingest(args)
        if not os.path.exists(args.db):
            _error(f"no database at {args.db}; run `crashtriage ingest` first")
            return 1
        if args.command == "report":
            return _report(args, parser)
        if args.command == "show":
            return _show(args)
        return _trend(args, parser)
    except SchemaMismatch as exc:
        _error(str(exc))
        return 1
    except BrokenPipeError:  # e.g. `crashtriage report | head`
        sys.stderr.close()
        return 0


def _error(message: str) -> None:
    print(f"crashtriage: {message}", file=sys.stderr)


def _emit(args: argparse.Namespace, data: Any, text: str) -> None:
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print(text, end="")


def _tilde(path: str) -> str:
    home = os.path.expanduser("~")
    return "~" + path[len(home) :] if path == home or path.startswith(home + os.sep) else path


def _ingest(args: argparse.Namespace) -> int:
    folders = args.folders or [str(p) for p in default_folders()]
    conn = connect(args.db)
    try:
        result = ingest(conn, folders)
        stored = row_counts(conn)["incidents"]
    finally:
        conn.close()

    by_kind = Counter(s.kind for s in result.skipped)
    by_reason = Counter((s.kind, s.reason) for s in result.skipped)
    reasons = sorted(by_reason.items(), key=lambda item: (-item[1], item[0]))
    listed = [s for s in result.skipped if s.kind in _LISTED_KINDS]
    data = {
        "folders": folders,
        "files_seen": result.files_seen,
        "crash_reports": result.parsed,
        "added": result.added,
        "duplicates": result.duplicates,
        "skipped": {
            "total": len(result.skipped),
            "by_kind": dict(sorted(by_kind.items())),
            "by_reason": [{"kind": k, "reason": r, "count": n} for (k, r), n in reasons],
            "files": [{"path": s.path, "kind": s.kind, "reason": s.reason} for s in listed],
        },
        "database": {"path": args.db, "incidents": stored},
    }

    lines = [
        "Folders: " + ", ".join(_tilde(f) for f in folders),
        f"Scanned {result.files_seen} files.",
        f"Crash reports: {result.parsed} parsed, {result.added} added, {result.duplicates} already in the database.",
        f"Skipped {len(result.skipped)} files:" if result.skipped else "Skipped 0 files.",
    ]
    for kind in sorted(by_kind, key=lambda k: (-by_kind[k], k)):
        lines.append(f"  {kind:<11} {by_kind[kind]:>5}")
        for (k, reason), n in reasons:
            if k == kind:
                lines.append(f"  {'':<11} {n:>5}  {reason}")
        shown = [s for s in listed if s.kind == kind]
        for s in shown[:_LIST_LIMIT]:
            lines.append(f"  {'':<11}        - {_tilde(s.path)}")
        if len(shown) > _LIST_LIMIT:
            lines.append(f"  {'':<11}        ... and {len(shown) - _LIST_LIMIT} more (see --json)")
    lines.append(f"Database {args.db} now holds {stored} crashes.")
    _emit(args, data, "\n".join(lines) + "\n")
    return 0


def _report(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        as_of = parse_as_of(args.as_of)
        since = parse_since(args.since, as_of) if args.since else None
    except ValueError as exc:
        parser.error(str(exc))
    conn = connect(args.db)
    try:
        found, total, total_clusters = clusters(conn, since=since, as_of=as_of, process=args.process, top=args.top)
    finally:
        conn.close()
    described = []
    if args.since:
        described.append(f"since {args.since}")
    if args.as_of:
        described.append(f"as of {args.as_of}")
    if args.process:
        described.append(f"process {args.process}")
    filters = {"since": args.since, "as_of": args.as_of, "process": args.process, "top": args.top}
    _emit(args, report_json(found, total, total_clusters, filters), render_report_markdown(found, total, total_clusters, described))
    return 0


def _show(args: argparse.Namespace) -> int:
    conn = connect(args.db)
    try:
        try:
            incident_id, size = resolve(conn, args.id)
        except NotFound as exc:
            _error(str(exc))
            return 1
        data = show_json(conn, incident_id, size) if args.json else None
        text = "" if args.json else render_show_markdown(conn, incident_id, size)
    finally:
        conn.close()
    _emit(args, data, text)
    return 0


def _trend(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        as_of = parse_as_of(args.as_of)
    except ValueError as exc:
        parser.error(str(exc))
    conn = connect(args.db)
    try:
        data = trend(conn, weeks=args.weeks, as_of=as_of, process=args.process)
    finally:
        conn.close()
    _emit(args, data, render_trend_markdown(data))
    return 0
