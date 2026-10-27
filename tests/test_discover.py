from __future__ import annotations

import shutil

from conftest import fixture_path, running_as_root
from crashtriage.discover import find_files, scan


def _make_tree(root):
    (root / "Retired").mkdir(parents=True)
    (root / "Empty").mkdir()
    shutil.copy(fixture_path("crasher-segv.ips"), root / "a.ips")
    shutil.copy(fixture_path("crasher-trap.ips"), root / "Retired" / "b.ips")
    shutil.copy(fixture_path("noncrash-jetsam.ips"), root / "Retired" / "c.ips")
    shutil.copy(fixture_path("noncrash-text.diag"), root / "d.diag")
    (root / ".hidden.panic").write_text('{"panic_string": "x"}')


def test_find_files_walks_subfolders_and_hidden_files_in_order(tmp_path) -> None:
    _make_tree(tmp_path)
    files, skipped = find_files([tmp_path])
    names = [p.removeprefix(str(tmp_path) + "/") for p in files]
    assert names == [".hidden.panic", "a.ips", "d.diag", "Retired/b.ips", "Retired/c.ips"]
    assert skipped == []


def test_scan_sorts_reports_from_skips(tmp_path) -> None:
    _make_tree(tmp_path)
    result = scan([tmp_path])
    assert result.files_seen == 5
    assert sorted(r.process_name for r in result.reports) == ["ct-crasher-segv", "ct-crasher-trap"]
    assert sorted(s.kind for s in result.skipped) == ["non-crash", "non-crash", "not-ips"]


def test_missing_folder_is_reported(tmp_path) -> None:
    files, skipped = find_files([tmp_path / "nope"])
    assert files == []
    assert [(s.kind, s.reason) for s in skipped] == [("unreadable", "folder does not exist")]


def test_a_single_file_can_be_given(tmp_path) -> None:
    files, _ = find_files([fixture_path("crasher-segv.ips")])
    assert files == [str(fixture_path("crasher-segv.ips"))]


@running_as_root
def test_unlistable_folder_is_counted_not_fatal(tmp_path) -> None:
    _make_tree(tmp_path)
    locked = tmp_path / "Retired"
    locked.chmod(0)
    try:
        result = scan([tmp_path])
    finally:
        locked.chmod(0o755)
    assert sorted(r.process_name for r in result.reports) == ["ct-crasher-segv"]
    permission = [s for s in result.skipped if s.kind == "permission"]
    assert len(permission) == 1
    assert permission[0].path == str(locked)
    assert permission[0].reason == "cannot list folder: permission denied"


@running_as_root
def test_unreadable_file_is_counted_not_fatal(tmp_path) -> None:
    _make_tree(tmp_path)
    (tmp_path / "a.ips").chmod(0)
    try:
        result = scan([tmp_path])
    finally:
        (tmp_path / "a.ips").chmod(0o644)
    assert [r.process_name for r in result.reports] == ["ct-crasher-trap"]
    assert [s.kind for s in result.skipped].count("permission") == 1
