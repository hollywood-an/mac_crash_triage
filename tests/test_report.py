"""Unit tests for the report/trend logic: time arguments, ranking, week boundaries."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from conftest import fixture_path
from crashtriage.fingerprint import fingerprint
from crashtriage.parser import parse_file
from crashtriage.report import clusters, parse_as_of, parse_since, render_trend_markdown, trend, version_key
from crashtriage.store import add_report, connect

AS_OF = datetime(2026, 10, 28, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("7d", datetime(2026, 10, 21, tzinfo=UTC)),
        ("24h", datetime(2026, 10, 27, tzinfo=UTC)),
        ("2w", datetime(2026, 10, 14, tzinfo=UTC)),
        ("2026-10-01", datetime(2026, 10, 1, tzinfo=UTC)),
        ("2026-10-01T12:30:00Z", datetime(2026, 10, 1, 12, 30, tzinfo=UTC)),
        ("2026-10-01T12:30:00-04:00", datetime(2026, 10, 1, 16, 30, tzinfo=UTC)),
    ],
)
def test_parse_since(text, expected) -> None:
    assert parse_since(text, AS_OF) == expected


@pytest.mark.parametrize("text", ["yesterday", "7x", "2026-13-01", "2026-10-01T12:30:00"])
def test_parse_since_rejects(text) -> None:
    with pytest.raises(ValueError):
        parse_since(text, AS_OF)


def test_as_of_date_means_end_of_day() -> None:
    assert parse_as_of("2026-10-27") == datetime(2026, 10, 28, tzinfo=UTC)
    assert parse_as_of("2026-10-27T06:00:00Z") == datetime(2026, 10, 27, 6, tzinfo=UTC)
    assert parse_as_of(None).tzinfo is not None


def test_version_sort_is_numeric() -> None:
    # Numbers compare as numbers; a text part sorts after any number. Not semver,
    # but a total order, which is what deterministic output needs.
    assert sorted(["1.10", "1.9", "2.0", "1.9.1", "1.9-beta"], key=version_key) == ["1.9", "1.9.1", "1.9-beta", "1.10", "2.0"]


def _copy(name: str, n: int, timestamp: str | None, **changes):
    report = parse_file(fixture_path(name))
    return dataclasses.replace(
        report,
        incident_id=f"00000000-0000-0000-0000-{n:012d}",
        source_sha256=f"{n:064d}",
        timestamp=timestamp,
        **changes,
    )


@pytest.fixture
def conn(tmp_path):
    connection = connect(tmp_path / "t.db")
    yield connection
    connection.close()


def test_ranking_ties_break_on_last_seen_then_fingerprint(conn) -> None:
    # Two clusters of 2 with the same last-seen time, one cluster of 2 seen later,
    # and one cluster of 3.
    add_report(conn, _copy("crasher-segv.ips", 1, "2026-10-20T00:00:00Z"))
    add_report(conn, _copy("crasher-segv.ips", 2, "2026-10-21T00:00:00Z"))
    add_report(conn, _copy("crasher-trap.ips", 3, "2026-10-20T00:00:00Z"))
    add_report(conn, _copy("crasher-trap.ips", 4, "2026-10-21T00:00:00Z"))
    add_report(conn, _copy("crasher-bus.ips", 5, "2026-10-22T00:00:00Z"))
    add_report(conn, _copy("crasher-bus.ips", 6, "2026-10-22T00:00:00Z"))
    for n in (7, 8, 9):
        add_report(conn, _copy("crasher-throw.ips", n, "2026-10-01T00:00:00Z"))
    found, total, total_clusters = clusters(conn)
    assert (total, total_clusters) == (9, 4)
    segv = fingerprint(parse_file(fixture_path("crasher-segv.ips"))).value
    trap = fingerprint(parse_file(fixture_path("crasher-trap.ips"))).value
    tied = sorted([segv, trap])
    assert [c.process for c in found[:2]] == ["ct-crasher-throw", "ct-crasher-bus"]
    assert [c.fingerprint for c in found[2:]] == tied
    assert [c.rank for c in found] == [1, 2, 3, 4]
    assert found[0].incident_ids == tuple(f"00000000-0000-0000-0000-{n:012d}" for n in (9, 8, 7))


def test_since_filter_excludes_undated_and_future(conn) -> None:
    add_report(conn, _copy("crasher-segv.ips", 1, "2026-10-27T23:59:59Z"))
    add_report(conn, _copy("crasher-segv.ips", 2, "2026-10-28T00:00:00Z"))  # at as_of: excluded
    add_report(conn, _copy("crasher-segv.ips", 3, None))
    add_report(conn, _copy("crasher-segv.ips", 4, "2026-10-20T23:59:59Z"))  # before since
    found, total, _ = clusters(conn, since=parse_since("7d", AS_OF), until=AS_OF)
    assert total == 1 and found[0].incident_ids == ("00000000-0000-0000-0000-000000000001",)
    found, total, _ = clusters(conn)
    assert total == 4
    assert found[0].first_seen == "2026-10-20T23:59:59Z"
    assert found[0].last_seen == "2026-10-28T00:00:00Z"


def test_cluster_versions_and_signals(conn) -> None:
    add_report(conn, _copy("crasher-versioned-v1a.ips", 1, "2026-10-20T00:00:00Z", process_version="1.10"))
    add_report(conn, _copy("crasher-versioned-v1a.ips", 2, "2026-10-20T00:00:00Z", process_version="1.9"))
    add_report(conn, _copy("crasher-versioned-v1a.ips", 3, "2026-10-20T00:00:00Z", process_version=None, signal="SIGBUS"))
    [cluster], _, _ = clusters(conn)
    assert cluster.versions == ("1.9", "1.10")
    assert cluster.signals == ("SIGBUS", "SIGSEGV")


def test_trend_week_boundaries(conn) -> None:
    add_report(conn, _copy("crasher-segv.ips", 1, "2026-10-25T23:59:59Z"))  # Sunday: week 43
    add_report(conn, _copy("crasher-segv.ips", 2, "2026-10-26T00:00:00Z"))  # Monday: week 44
    add_report(conn, _copy("crasher-trap.ips", 3, "2026-10-12T00:00:00Z"))  # week 42: outside 2 weeks
    add_report(conn, _copy("crasher-trap.ips", 4, None))
    data = trend(conn, weeks=2, as_of=AS_OF)
    assert data["weeks"] == ["2026-W43", "2026-W44"]
    assert data["rows"] == [{"process": "ct-crasher-segv", "counts": [1, 1], "total": 2}]
    assert data["undated_crashes"] == 1
    assert "1 crash(es) without a timestamp are not counted." in render_trend_markdown(data)
    wider = trend(conn, weeks=3, as_of=AS_OF)
    assert [r["process"] for r in wider["rows"]] == ["ct-crasher-segv", "ct-crasher-trap"]


def test_trend_as_of_is_an_exclusive_end(conn) -> None:
    add_report(conn, _copy("crasher-segv.ips", 1, "2026-10-26T00:00:00Z"))
    # as_of exactly Monday 00:00: the last full week shown is the one before it.
    data = trend(conn, weeks=1, as_of=datetime(2026, 10, 26, tzinfo=UTC))
    assert data["weeks"] == ["2026-W43"] and data["rows"] == []


def test_trend_undated_count_respects_process(conn) -> None:
    add_report(conn, _copy("crasher-segv.ips", 1, None))
    add_report(conn, _copy("crasher-trap.ips", 2, "2026-10-26T00:00:00Z"))
    assert trend(conn, weeks=1, as_of=AS_OF, process="ct-crasher-trap")["undated_crashes"] == 0
    assert trend(conn, weeks=1, as_of=AS_OF, process="ct-crasher-segv")["undated_crashes"] == 1
    assert trend(conn, weeks=1, as_of=AS_OF)["undated_crashes"] == 1


def test_until_alone_bounds_the_crashes(conn) -> None:
    add_report(conn, _copy("crasher-segv.ips", 1, "2026-10-26T23:59:59Z"))
    add_report(conn, _copy("crasher-segv.ips", 2, "2026-10-27T00:00:00Z"))
    add_report(conn, _copy("crasher-segv.ips", 3, None))
    _, total, _ = clusters(conn, until=datetime(2026, 10, 27, tzinfo=UTC))
    assert total == 1
