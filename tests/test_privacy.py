"""Guards for the public repo: no fixture or tracked file may identify this machine.

The identifiers are read from the machine running the tests, so nothing private is
written into the repo to check for it. Patterns here are independent of the
anonymizer's own, so these tests check its output rather than repeat it.
"""

from __future__ import annotations

import getpass
import json
import os
import pwd
import re
import socket
from pathlib import Path

import pytest

from conftest import FIXTURES, REPO

UUID = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
MAC = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}")
TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|xox[abposr]-")

# Words too common to search for if they happen to be the login name.
COMMON_WORDS = {"admin", "user", "dev", "test", "main", "home", "root", "mac", "build"}


def _local_identifiers() -> dict[str, str]:
    found = {}
    user = getpass.getuser()
    if len(user) >= 4 and user.lower() not in COMMON_WORDS:
        found["login name"] = user
    found["home folder"] = os.path.expanduser("~")
    host = socket.gethostname().split(".")[0]
    if len(host) >= 4 and host.lower() not in ("localhost",):
        found["hostname"] = host
    try:
        real = pwd.getpwuid(os.getuid()).pw_gecos.split(",")[0].strip()
    except KeyError:
        real = ""
    if len(real) >= 4:
        found["full name"] = real
    return found


def _decoded(path: Path) -> str:
    """File text plus the JSON-decoded form, so escaped "\\/" paths are seen too."""
    raw = path.read_bytes().decode("utf-8", errors="replace")
    parts = [raw]
    first, _, rest = raw.partition("\n")
    for chunk in (first, rest):
        try:
            parts.append(json.dumps(json.loads(chunk), ensure_ascii=False))
        except ValueError:
            pass
    return "\n".join(parts)


FIXTURE_FILES = sorted(p for p in FIXTURES.iterdir() if p.is_file() and p.name != "README.md")


def test_there_are_fixtures() -> None:
    assert len(FIXTURE_FILES) >= 10


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_has_no_local_identifiers(path: Path) -> None:
    text = _decoded(path).lower()
    for label, value in _local_identifiers().items():
        assert value.lower() not in text, f"{path.name} contains the {label}"


@pytest.mark.parametrize("path", FIXTURE_FILES, ids=lambda p: p.name)
def test_fixture_has_no_raw_identifiers(path: Path) -> None:
    text = _decoded(path)
    raw_uuids = [u for u in UUID.findall(text) if not u.startswith("00000000-0000-0000-")]
    assert raw_uuids == [], f"{path.name}: UUIDs not anonymized"
    assert MAC.findall(text) == [], f"{path.name}: MAC address"
    assert [e for e in EMAIL.findall(text) if not e.endswith("@example.invalid")] == [], f"{path.name}: email"
    assert TOKEN.findall(text) == [], f"{path.name}: token"
    assert "/Users/" not in text, f"{path.name}: home folder path"
    assert '"crashReporterKey": "REDACTED"' in text or "crashReporterKey" not in text


def _tracked_text_files() -> list[Path]:
    skip_dirs = {".git", ".venv", "__pycache__", ".pytest_cache", "build"}
    files = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.endswith((".dSYM", ".noindex"))]
        for name in filenames:
            path = Path(dirpath) / name
            # A git worktree has a .git *file* that records where it lives on disk.
            if path.suffix in {".db", ".pyc"} or name in {"RESUME_BULLETS.md", ".git"}:
                continue
            files.append(path)
    return files


REPORT_FOLDERS = [Path.home() / "Library" / "Logs" / "DiagnosticReports", Path("/Library/Logs/DiagnosticReports")]
HEX_RUN = re.compile(r"\b[0-9a-f]{32,}\b")
TEAM_ID = re.compile(r'"?(?:codeSigningTeamID|Team ID)"?\s*:\s*"?([A-Z0-9]{10})\b')


def _normalize(text: str) -> str:
    return text.lower().replace(":", "-")


def _identifiers_in(text: str) -> set[str]:
    """UUIDs, MAC addresses and long hex runs, lowercased, ':' written as '-'."""
    text = _normalize(text)
    found = set(UUID.findall(text)) | set(MAC.findall(text)) | set(HEX_RUN.findall(text))
    return {v for v in found if not v.startswith("00000000-0000-0000-") and set(v) - {"0", "-"}}


def _identifiers_from_this_macs_reports() -> tuple[set[str], set[str]]:
    """Every UUID, MAC address, long hex id and team id in the real reports on this
    machine (read-only). Empty where the folders do not exist or cannot be read."""
    ids, team_ids = set(), set()
    for folder in REPORT_FOLDERS:
        for dirpath, _dirnames, filenames in os.walk(folder):
            for name in filenames:
                try:
                    with open(os.path.join(dirpath, name), "rb") as fh:
                        text = fh.read().decode("utf-8", errors="replace")
                except OSError:
                    continue
                ids |= _identifiers_in(text)
                team_ids |= {t.lower() for t in TEAM_ID.findall(text)}
    return ids, team_ids


def test_repo_has_no_identifiers_from_this_macs_reports() -> None:
    """The check that matters most: nothing copied out of a real report (a device's
    crashReporterKey, an incident id, a Bluetooth MAC, a build UUID) is in the repo,
    in any file, test code included."""
    ids, team_ids = _identifiers_from_this_macs_reports()
    if not ids:
        pytest.skip("no readable crash reports on this machine to compare against")
    offenders = []
    for path in _tracked_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lowered = text.lower()
        leaked = (_identifiers_in(text) & ids) | {t for t in team_ids if t in lowered}
        offenders += [f"{path.relative_to(REPO)}: {value[:8]}..." for value in sorted(leaked)]
    assert offenders == []


def test_repo_files_have_no_local_identifiers() -> None:
    identifiers = _local_identifiers()
    # The home folder path contains the login name, and NOTES/README may mention
    # neither. Fixtures are covered above with a stricter check.
    offenders = []
    for path in _tracked_text_files():
        try:
            text = path.read_text(encoding="utf-8").lower()
        except (UnicodeDecodeError, OSError):
            continue
        for label, value in identifiers.items():
            if value.lower() in text:
                offenders.append(f"{path.relative_to(REPO)}: {label}")
    assert offenders == []
