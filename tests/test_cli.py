"""CLI tests: every command against a database built from the fixtures, compared
with golden files in tests/golden/. To refresh them after an intended change:

    UPDATE_GOLDEN=1 .venv/bin/python -m pytest tests/test_cli.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import FIXTURES, REPO
from crashtriage.cli import main

GOLDEN = Path(__file__).parent / "golden"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"

OVERFLOW_ID = "00000000-0000-0000-4BDF-467A0254B6D1"
COREAUDIOD_ID = "00000000-0000-0000-3B51-9E7175764D46"
THROW_ID = "00000000-0000-0000-8E98-8FC38E6D3F1F"


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """A temp folder holding a copy of the fixtures and an ingested crashtriage.db."""
    shutil.copytree(FIXTURES, tmp_path / "fixtures")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def check_golden(name: str, actual: str) -> None:
    path = GOLDEN / name
    if UPDATE:
        GOLDEN.mkdir(exist_ok=True)
        path.write_text(actual, encoding="utf-8")
    assert path.exists(), f"missing golden file {name}; run with UPDATE_GOLDEN=1"
    assert actual == path.read_text(encoding="utf-8")


GOLDEN_RUNS = [
    ("report.md", ["report"]),
    ("report-process.md", ["report", "--process", "DOTNET"]),
    ("report-since-top.md", ["report", "--since", "1d", "--as-of", "2026-10-27", "--top", "3"]),
    ("report-top2.json", ["report", "--top", "2", "--json"]),
    ("report-empty.md", ["report", "--process", "Finder"]),
    ("show-by-fingerprint.md", ["show", "bd6f08"]),
    ("show-recursion.md", ["show", OVERFLOW_ID]),
    ("show-system-only.md", ["show", COREAUDIOD_ID.lower()]),
    ("show-throw.json", ["show", THROW_ID, "--json"]),
    ("trend.md", ["trend", "--weeks", "3", "--as-of", "2026-10-28"]),
    ("trend-process.json", ["trend", "--weeks", "2", "--as-of", "2026-10-28", "--process", "dotnet", "--json"]),
]


@pytest.mark.parametrize(("name", "argv"), GOLDEN_RUNS, ids=[name for name, _ in GOLDEN_RUNS])
def test_golden_output(workdir, capsys, name, argv) -> None:
    assert run(capsys, "ingest", "fixtures")[0] == 0
    code, out, err = run(capsys, *argv)
    assert (code, err) == (0, "")
    check_golden(name, out)


def test_ingest_output(workdir, capsys) -> None:
    code, out, err = run(capsys, "ingest", "fixtures")
    assert (code, err) == (0, "")
    check_golden("ingest.txt", out)
    code, out, err = run(capsys, "ingest", "fixtures", "--json")
    assert code == 0
    check_golden("ingest-again.json", out)
    data = json.loads(out)
    assert (data["added"], data["duplicates"]) == (0, 15)


def test_output_does_not_depend_on_ingest_order(workdir, capsys) -> None:
    files = sorted(str(p) for p in (workdir / "fixtures").iterdir())
    run(capsys, "ingest", *files, "--db", "forward.db")
    run(capsys, "ingest", *reversed(files), "--db", "backward.db")
    for argv in (["report"], ["report", "--json"], ["trend", "--as-of", "2026-10-28"], ["show", "edb224"]):
        forward = run(capsys, *argv, "--db", "forward.db")
        backward = run(capsys, *argv, "--db", "backward.db")
        assert forward == backward, argv
        assert forward[0] == 0


def test_repeated_runs_are_identical(workdir, capsys) -> None:
    run(capsys, "ingest", "fixtures")
    first = [run(capsys, *argv) for argv in (["report"], ["trend"], ["show", "bd6f08"])]
    second = [run(capsys, *argv) for argv in (["report"], ["trend"], ["show", "bd6f08"])]
    assert first == second


@pytest.mark.parametrize(
    "argv",
    [["ingest", "fixtures"], ["report"], ["show", "edb224"], ["trend"]],
    ids=["ingest", "report", "show", "trend"],
)
def test_every_command_has_json(workdir, capsys, argv) -> None:
    run(capsys, "ingest", "fixtures")
    code, out, _ = run(capsys, *argv, "--json")
    assert code == 0
    assert isinstance(json.loads(out), dict)


def test_read_commands_need_a_database(workdir, capsys) -> None:
    for argv in (["report"], ["show", "x"], ["trend"]):
        code, out, err = run(capsys, *argv)
        assert (code, out) == (1, "")
        assert err == "crashtriage: no database at crashtriage.db; run `crashtriage ingest` first\n"
    assert not (workdir / "crashtriage.db").exists()


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("nothing-like-this", "no incident or fingerprint matches 'nothing-like-this'"),
        ("00000000", "'00000000' matches 15 incidents; give more of the id"),
    ],
)
def test_show_lookup_errors(workdir, capsys, key, message) -> None:
    run(capsys, "ingest", "fixtures")
    code, out, err = run(capsys, "show", key)
    assert (code, out, err) == (1, "", f"crashtriage: {message}\n")


def test_show_accepts_a_unique_id_prefix(workdir, capsys) -> None:
    run(capsys, "ingest", "fixtures")
    code, out, _ = run(capsys, "show", "00000000-0000-0000-4BDF")
    assert code == 0 and out.startswith(f"# ct-crasher-overflow crash {OVERFLOW_ID}\n")


@pytest.mark.parametrize(
    "argv",
    [["report", "--since", "yesterday"], ["report", "--top", "0"], ["trend", "--weeks", "0"], ["report", "--as-of", "2026-10-27T10:00"]],
)
def test_bad_arguments_exit_2(workdir, capsys, argv) -> None:
    run(capsys, "ingest", "fixtures")
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_ingest_of_a_missing_folder_reports_it(workdir, capsys) -> None:
    code, out, _ = run(capsys, "ingest", "no-such-folder", "--json")
    data = json.loads(out)
    assert code == 0
    assert data["skipped"]["files"] == [{"path": "no-such-folder", "kind": "unreadable", "reason": "folder does not exist"}]


def test_module_entry_point_runs() -> None:
    result = subprocess.run([sys.executable, "-m", "crashtriage", "--version"], capture_output=True, text=True, cwd=REPO, check=True)
    assert result.stdout.startswith("crashtriage ")
