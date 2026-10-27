"""Find report files under the DiagnosticReports folders and parse them.

Read-only: folders are listed with os.walk and files are opened with mode "rb" by
the parser. Nothing is created, renamed or deleted under the input folders.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .model import CrashReport, Skipped
from .parser import parse_file


def default_folders() -> list[Path]:
    return [
        Path.home() / "Library" / "Logs" / "DiagnosticReports",
        Path("/Library/Logs/DiagnosticReports"),
    ]


@dataclass
class ScanResult:
    reports: list[CrashReport] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    files_seen: int = 0


def find_files(folders: list[str | Path]) -> tuple[list[str], list[Skipped]]:
    """All regular files under the folders (subfolders and hidden files included),
    in a stable sorted order, plus a Skipped for every folder that could not be listed."""
    files: list[str] = []
    skipped: list[Skipped] = []

    def on_error(exc: OSError) -> None:
        where = exc.filename or "?"
        if isinstance(exc, PermissionError):
            skipped.append(Skipped(str(where), "permission", "cannot list folder: permission denied"))
        else:
            skipped.append(Skipped(str(where), "unreadable", f"cannot list folder: {exc.strerror or exc}"))

    for folder in folders:
        folder = str(folder)
        if os.path.isfile(folder):
            files.append(folder)
            continue
        if not os.path.exists(folder):
            skipped.append(Skipped(folder, "unreadable", "folder does not exist"))
            continue
        for dirpath, dirnames, filenames in os.walk(folder, onerror=on_error):
            dirnames.sort()
            for name in sorted(filenames):
                files.append(os.path.join(dirpath, name))
    return files, skipped


def scan(folders: list[str | Path]) -> ScanResult:
    files, skipped = find_files(folders)
    result = ScanResult(skipped=skipped, files_seen=len(files))
    for path in files:
        parsed = parse_file(path)
        if isinstance(parsed, CrashReport):
            result.reports.append(parsed)
        else:
            result.skipped.append(parsed)
    return result
