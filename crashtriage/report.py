"""Queries and renderers behind the `report`, `show` and `trend` commands.

Every function here is a pure function of the database and its arguments. The only
"now" is the `as_of` argument, which the CLI fills from the clock unless --as-of
is given, so a fixed database and fixed arguments give byte-identical output.
"""

from __future__ import annotations

import dataclasses
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from .fingerprint import fingerprint
from .store import load_report

# --- time arguments -------------------------------------------------------------

_RELATIVE = re.compile(r"^(\d+)([hdw])$")
_UNITS = {"h": timedelta(hours=1), "d": timedelta(days=1), "w": timedelta(weeks=1)}


def parse_as_of(text: str | None) -> datetime:
    """The reference "now". A bare date means the end of that day (UTC)."""
    if text is None:
        return datetime.now(UTC).replace(microsecond=0)
    try:
        day = datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        pass
    else:
        return day + timedelta(days=1)
    return _parse_instant(text)


def parse_since(text: str, as_of: datetime) -> datetime:
    """'7d', '24h', '2w' (relative to as_of), a date (its start, UTC) or an ISO instant."""
    match = _RELATIVE.match(text.strip())
    if match:
        return as_of - int(match[1]) * _UNITS[match[2]]
    try:
        return datetime.strptime(text, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return _parse_instant(text)


def _parse_instant(text: str) -> datetime:
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"not a time: {text!r} (use 7d, 24h, 2w, YYYY-MM-DD or an ISO 8601 time)") from None
    if moment.tzinfo is None:
        raise ValueError(f"time needs a UTC offset or 'Z': {text!r}")
    return moment.astimezone(UTC)


def _stamp(moment: datetime) -> str:
    """The stored timestamp format, so SQL can compare strings."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _display(stamp: str | None, *, seconds: bool = False) -> str:
    """'2026-10-26T22:25:39Z' -> '2026-10-26 22:25' (or '... 22:25:39')."""
    if not stamp:
        return "unknown"
    return stamp[: 19 if seconds else 16].replace("T", " ")


def version_key(version: str) -> tuple:
    """Sort key for version strings: numeric parts compare as numbers and sort before
    text parts ("1.9" < "1.9.1" < "1.9-beta" < "1.10"). Display order only."""
    return tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in re.split(r"[.\-+ ]", version))


# --- report -----------------------------------------------------------------------


@dataclass(frozen=True)
class Cluster:
    rank: int
    fingerprint: str
    basis: str
    count: int
    process: str
    exception_type: str | None
    signals: tuple[str, ...]
    first_seen: str | None
    last_seen: str | None
    versions: tuple[str, ...]
    top_frame: str | None
    incident_ids: tuple[str, ...]  # newest first


def clusters(
    conn: sqlite3.Connection,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    process: str | None = None,
    top: int | None = None,
) -> tuple[list[Cluster], int, int]:
    """Clusters ranked by count (then most recent, then fingerprint). Returns the
    clusters (cut to `top`), the number of crashes that matched the filters and the
    number of clusters before the cut. `since` and `until` bound the crash time
    (until is exclusive); with either one, crashes without a timestamp are left out."""
    where, params = [], []
    if since is not None or until is not None:
        where.append("timestamp IS NOT NULL")
    if since is not None:
        where.append("timestamp >= ?")
        params.append(_stamp(since))
    if until is not None:
        where.append("timestamp < ?")
        params.append(_stamp(until))
    if process is not None:
        where.append("process_name = ? COLLATE NOCASE")
        params.append(process)
    sql = "SELECT * FROM incidents" + (" WHERE " + " AND ".join(where) if where else "")
    rows = conn.execute(sql, params).fetchall()

    groups: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault(row["fingerprint"], []).append(row)

    built = []
    for value, members in groups.items():
        stamps = sorted(r["timestamp"] for r in members if r["timestamp"])
        newest_first = sorted(members, key=lambda r: (r["timestamp"] or "", r["incident_id"]), reverse=True)
        built.append(
            Cluster(
                rank=0,
                fingerprint=value,
                basis=members[0]["fingerprint_basis"],
                count=len(members),
                process=members[0]["process_name"],
                exception_type=members[0]["exception_type"],
                signals=tuple(sorted({r["signal"] for r in members if r["signal"]})),
                first_seen=stamps[0] if stamps else None,
                last_seen=stamps[-1] if stamps else None,
                versions=tuple(sorted({r["process_version"] for r in members if r["process_version"]}, key=version_key)),
                top_frame=members[0]["top_frame"],
                incident_ids=tuple(r["incident_id"] for r in newest_first),
            )
        )
    # count desc, then last seen desc, then fingerprint asc: a total order.
    built.sort(key=lambda c: c.fingerprint)
    built.sort(key=lambda c: c.last_seen or "", reverse=True)
    built.sort(key=lambda c: c.count, reverse=True)
    total_clusters = len(built)
    if top is not None:
        built = built[:top]
    ranked = [dataclasses.replace(c, rank=i) for i, c in enumerate(built, 1)]
    return ranked, len(rows), total_clusters


def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _shorten(text: str, limit: int = 70) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def render_report_markdown(found: list[Cluster], total: int, total_clusters: int, filters: list[str]) -> str:
    lines = ["# Crash clusters", ""]
    summary = f"{_plural(total, 'crash', 'crashes')} in {_plural(total_clusters, 'cluster')}"
    if filters:
        summary += " (" + ", ".join(filters) + ")"
    if len(found) < total_clusters:
        summary += f"; showing the top {len(found)}"
    lines += [summary + ".", ""]
    if not found:
        lines.append("No crashes match.")
        return "\n".join(lines) + "\n"
    lines += [
        "| # | Count | Process | Exception | First seen (UTC) | Last seen (UTC) | Versions | Top frame | Fingerprint |",
        "|--:|--:|---|---|---|---|---|---|---|",
    ]
    for c in found:
        exception = c.exception_type or "?"
        if c.signals:
            exception += " / " + ", ".join(c.signals)
        top_frame = f"`{_cell(_shorten(c.top_frame))}`" if c.top_frame else "(none)"
        if c.basis == "system-only":
            top_frame += " (system)"
        lines.append(
            f"| {c.rank} | {c.count} | {_cell(c.process)} | {exception} | {_display(c.first_seen)} | "
            f"{_display(c.last_seen)} | {_cell(', '.join(c.versions)) or '-'} | {top_frame} | `{c.fingerprint}` |"
        )
    lines += ["", "Run `crashtriage show <fingerprint>` for the latest crash in a cluster."]
    return "\n".join(lines) + "\n"


def report_json(found: list[Cluster], total: int, total_clusters: int, filters: dict[str, Any]) -> dict[str, Any]:
    return {
        "filters": filters,
        "crashes": total,
        "total_clusters": total_clusters,
        "clusters": [
            {
                "rank": c.rank,
                "fingerprint": c.fingerprint,
                "basis": c.basis,
                "count": c.count,
                "process": c.process,
                "exception_type": c.exception_type,
                "signals": list(c.signals),
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "versions": list(c.versions),
                "top_frame": c.top_frame,
                "incident_ids": list(c.incident_ids),
            }
            for c in found
        ],
    }


# --- show -------------------------------------------------------------------------


class NotFound(Exception):
    """The id did not name exactly one incident."""


def resolve(conn: sqlite3.Connection, key: str) -> tuple[str, int]:
    """Find an incident by id, unique id prefix, or fingerprint (prefix).
    Returns (incident_id, size of its cluster)."""
    key = key.strip()
    if not key:
        raise NotFound("empty id")
    row = conn.execute("SELECT incident_id FROM incidents WHERE incident_id = ? COLLATE NOCASE", (key,)).fetchone()
    if row is None:
        escaped = key.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        matches = conn.execute(
            "SELECT incident_id FROM incidents WHERE incident_id LIKE ? ESCAPE '\\' ORDER BY incident_id", (escaped + "%",)
        ).fetchall()
        if len(matches) > 1:
            raise NotFound(f"{key!r} matches {len(matches)} incidents; give more of the id")
        if len(matches) == 1:
            row = matches[0]
    if row is None:
        escaped = key.lower().replace("%", "").replace("_", "")
        prints = conn.execute(
            "SELECT DISTINCT fingerprint FROM incidents WHERE fingerprint LIKE ? ORDER BY fingerprint", (escaped + "%",)
        ).fetchall()
        if len(prints) > 1:
            raise NotFound(f"{key!r} matches {len(prints)} fingerprints; give more of it")
        if len(prints) == 1:
            row = conn.execute(
                "SELECT incident_id FROM incidents WHERE fingerprint = ? ORDER BY timestamp DESC, incident_id DESC LIMIT 1",
                (prints[0][0],),
            ).fetchone()
    if row is None:
        raise NotFound(f"no incident or fingerprint matches {key!r}")
    incident_id = row[0]
    size = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE fingerprint = (SELECT fingerprint FROM incidents WHERE incident_id = ?)",
        (incident_id,),
    ).fetchone()[0]
    return incident_id, size


def _frame_line(index: int, frame, used: bool, width: int) -> str:
    image = frame.image_name or "<anonymous>"
    offset = f"0x{frame.image_offset:x}" if frame.image_offset is not None else "?"
    text = f"{index:>3}  {image:<{width}}  {offset:<12} {'*' if used else ' '} "
    if frame.symbol:
        text += frame.symbol
        if frame.symbol_location is not None:
            text += f" + {frame.symbol_location}"
        if frame.source_file:
            text += f"  ({frame.source_file}:{frame.source_line})" if frame.source_line is not None else f"  ({frame.source_file})"
    return text.rstrip()


def render_show_markdown(conn: sqlite3.Connection, incident_id: str, cluster_size: int) -> str:
    report = load_report(conn, incident_id)
    fp = fingerprint(report)
    version = report.process_version or "(no version)"
    if report.process_version and report.build_version and report.build_version != report.process_version:
        version += f" ({report.build_version})"
    exception = report.exception_type or "?"
    if report.signal:
        exception += f" ({report.signal})"
    if report.exception_subtype:
        exception += f": {report.exception_subtype}"
    termination = " ".join(str(x) for x in (report.termination_namespace, report.termination_code) if x is not None) or "?"
    if report.termination_indicator:
        termination += f": {report.termination_indicator}"
    crashes = "crash" if cluster_size == 1 else "crashes"
    rows = [
        ("Process", f"{report.process_name} {version}" + (f", pid {report.pid}" if report.pid is not None else "")),
        ("Path", report.process_path or "unknown"),
        ("Crashed at", (_display(report.timestamp, seconds=True) + " UTC" if report.timestamp else "unknown") + (f" (report: {report.timestamp_raw})" if report.timestamp_raw else "")),
        ("OS", f"{report.os_version or '?'} ({report.os_build or '?'})" + (f", {report.cpu_type}" if report.cpu_type else "")),
        ("Exception", exception),
        ("Termination", termination),
        ("Fingerprint", f"`{fp.value}` ({fp.basis} frames; {cluster_size} {crashes} in this cluster)"),
    ]
    lines = [f"# {report.process_name} crash {report.incident_id}", "", "| Field | Value |", "|---|---|"]
    lines += [f"| {k} | {_cell(v)} |" for k, v in rows]
    lines.append("")

    thread = report.faulting
    if thread is None:
        lines.append("No faulting thread in this report.")
    else:
        label = f"## Faulting thread {thread.index}"
        detail = [f"queue {thread.queue}" if thread.queue else None, f"name {thread.name}" if thread.name else None]
        detail = [d for d in detail if d]
        count = f"{len(thread.frames)} frames"
        if thread.original_length and thread.original_length > len(thread.frames):
            count = f"{len(thread.frames)} of {thread.original_length} frames; ReportCrash elided the rest"
        lines += [label + (" (" + ", ".join(detail) + ")" if detail else ""), "", count + ". `*` marks the frames in the fingerprint.", ""]
        width = max([len(f.image_name or "<anonymous>") for f in thread.frames] + [5])
        lines.append("```text")
        lines.append(f"{'#':>3}  {'image':<{width}}  {'offset':<12}   symbol")
        used = set(fp.frame_indices)
        lines += [_frame_line(i, f, i in used, width) for i, f in enumerate(thread.frames)]
        lines.append("```")
    if report.warnings:
        lines += ["", "## Parser warnings", ""] + [f"- {w}" for w in report.warnings]
    return "\n".join(lines) + "\n"


def show_json(conn: sqlite3.Connection, incident_id: str, cluster_size: int) -> dict[str, Any]:
    report = load_report(conn, incident_id)
    fp = fingerprint(report)

    def frame_dict(f):
        return {
            "image": f.image_name,
            "image_index": f.image_index,
            "offset": f.image_offset,
            "symbol": f.symbol,
            "symbol_location": f.symbol_location,
            "source_file": f.source_file,
            "source_line": f.source_line,
        }

    return {
        "incident_id": report.incident_id,
        "timestamp": report.timestamp,
        "timestamp_raw": report.timestamp_raw,
        "process": report.process_name,
        "version": report.process_version,
        "build": report.build_version,
        "pid": report.pid,
        "path": report.process_path,
        "os_version": report.os_version,
        "os_build": report.os_build,
        "cpu_type": report.cpu_type,
        "exception_type": report.exception_type,
        "signal": report.signal,
        "exception_subtype": report.exception_subtype,
        "termination": {
            "namespace": report.termination_namespace,
            "code": report.termination_code,
            "indicator": report.termination_indicator,
        },
        "fingerprint": {"value": fp.value, "basis": fp.basis, "tokens": list(fp.tokens), "frame_indices": list(fp.frame_indices)},
        "cluster_size": cluster_size,
        "faulting_thread": report.faulting_thread,
        "threads": [
            {
                "index": t.index,
                "id": t.thread_id,
                "name": t.name,
                "queue": t.queue,
                "triggered": t.triggered,
                "original_length": t.original_length,
                "frames": [frame_dict(f) for f in t.frames],
            }
            for t in report.threads
        ],
        "warnings": list(report.warnings),
    }


# --- trend ------------------------------------------------------------------------


def week_label(moment: datetime) -> str:
    year, week, _ = moment.isocalendar()
    return f"{year}-W{week:02d}"


def trend(conn: sqlite3.Connection, *, weeks: int, as_of: datetime, process: str | None = None) -> dict[str, Any]:
    """Crashes per ISO week (UTC, weeks start on Monday) per process, for the
    `weeks` weeks ending with the week that contains as_of."""
    if weeks < 1:
        raise ValueError("--weeks must be at least 1")
    # as_of is an exclusive end (a bare --as-of date means the end of that day), so
    # the last week shown is the one containing the second before it.
    last = as_of - timedelta(seconds=1)
    start_of_last_week = (last - timedelta(days=last.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    starts = [start_of_last_week - timedelta(weeks=n) for n in range(weeks - 1, -1, -1)]
    labels = [week_label(s) for s in starts]
    window_start, window_end = starts[0], min(start_of_last_week + timedelta(weeks=1), as_of)

    where, params = ["timestamp IS NOT NULL", "timestamp >= ?", "timestamp < ?"], [_stamp(window_start), _stamp(window_end)]
    if process is not None:
        where.append("process_name = ? COLLATE NOCASE")
        params.append(process)
    counts: dict[str, list[int]] = {}
    for name, stamp in conn.execute(f"SELECT process_name, timestamp FROM incidents WHERE {' AND '.join(where)}", params):
        moment = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        column = labels.index(week_label(moment))
        counts.setdefault(name, [0] * weeks)[column] += 1
    rows = sorted(counts.items(), key=lambda item: (-sum(item[1]), item[0]))
    undated_sql, undated_params = "SELECT COUNT(*) FROM incidents WHERE timestamp IS NULL", []
    if process is not None:
        undated_sql += " AND process_name = ? COLLATE NOCASE"
        undated_params.append(process)
    undated = conn.execute(undated_sql, undated_params).fetchone()[0]
    return {
        "weeks": labels,
        "window": {"start": _stamp(window_start), "end": _stamp(window_end)},
        "rows": [{"process": name, "counts": values, "total": sum(values)} for name, values in rows],
        "totals": [sum(values[i] for _, values in rows) for i in range(weeks)],
        "undated_crashes": undated,
    }


def render_trend_markdown(data: dict[str, Any]) -> str:
    weeks = data["weeks"]
    lines = ["# Crashes per week", "", f"ISO weeks {weeks[0]} to {weeks[-1]} (UTC, Monday to Sunday).", ""]
    if not data["rows"]:
        lines.append("No crashes in these weeks.")
    else:
        lines.append("| Process | " + " | ".join(weeks) + " | Total |")
        lines.append("|---|" + "--:|" * (len(weeks) + 1))
        for row in data["rows"]:
            lines.append(f"| {_cell(row['process'])} | " + " | ".join(str(n) for n in row["counts"]) + f" | {row['total']} |")
        lines.append("| **All** | " + " | ".join(str(n) for n in data["totals"]) + f" | {sum(data['totals'])} |")
    if data["undated_crashes"]:
        lines += ["", f"{data['undated_crashes']} crash(es) without a timestamp are not counted."]
    return "\n".join(lines) + "\n"
