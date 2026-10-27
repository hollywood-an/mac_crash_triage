from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parent.parent

CRASH_FIXTURES = sorted(p.name for p in FIXTURES.glob("*.ips") if not p.name.startswith(("malformed-", "noncrash-")))


def fixture_path(name: str) -> Path:
    path = FIXTURES / name
    assert path.is_file(), f"missing fixture {name}"
    return path


def fixture_bytes(name: str) -> bytes:
    return fixture_path(name).read_bytes()


running_as_root = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
