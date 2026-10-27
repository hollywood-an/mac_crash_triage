"""Typed records produced by the parser."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Image:
    """One entry of a report's `usedImages` list."""

    index: int
    name: str | None
    path: str | None
    uuid: str | None
    base: int | None
    size: int | None
    source: str | None  # "P" for a mapped Mach-O, "A" for anonymous memory (e.g. JIT)
    arch: str | None
    bundle_id: str | None
    version: str | None

    @property
    def is_anonymous(self) -> bool:
        return self.source == "A" or (self.name is None and self.path is None)


@dataclass(frozen=True, slots=True)
class Frame:
    """One stack frame. Only `image_index` and `image_offset` are always present."""

    image_index: int | None
    image_name: str | None
    image_offset: int | None
    symbol: str | None = None
    symbol_location: int | None = None
    source_file: str | None = None
    source_line: int | None = None


@dataclass(frozen=True, slots=True)
class ThreadRec:
    index: int
    thread_id: int | None
    name: str | None
    queue: str | None
    triggered: bool
    frames: tuple[Frame, ...]
    # Set when ReportCrash elided frames (deep recursion): the real stack depth.
    original_length: int | None = None


@dataclass(frozen=True, slots=True)
class CrashReport:
    """A parsed crash report (header bug_type 309)."""

    incident_id: str
    timestamp: str | None  # crash time in UTC, ISO 8601 with a trailing "Z"
    timestamp_raw: str | None  # body captureTime (or header timestamp) as written
    process_name: str
    process_version: str | None
    build_version: str | None
    process_path: str | None
    pid: int | None
    os_version: str | None  # e.g. "macOS 26.6.2"
    os_build: str | None  # e.g. "25G83"
    bug_type: str
    cpu_type: str | None
    exception_type: str | None
    signal: str | None
    exception_subtype: str | None
    termination_namespace: str | None
    termination_code: int | None
    termination_indicator: str | None
    faulting_thread: int | None
    threads: tuple[ThreadRec, ...]
    images: tuple[Image, ...]
    source_sha256: str
    warnings: tuple[str, ...] = field(default=())

    @property
    def faulting(self) -> ThreadRec | None:
        """The faulting thread, or None when the index is missing or out of range."""
        if self.faulting_thread is None:
            return None
        for thread in self.threads:
            if thread.index == self.faulting_thread:
                return thread
        return None

    @property
    def main_image(self) -> Image | None:
        """The process's own executable: the image whose path is `procPath`."""
        if self.process_path:
            for image in self.images:
                if image.path == self.process_path:
                    return image
        for image in self.images:
            if image.name == self.process_name:
                return image
        return None


# Why a file was not turned into a CrashReport. Kept as a closed set so the CLI
# can summarize skips by kind.
SKIP_KINDS = (
    "permission",  # PermissionError opening a file or listing a folder
    "unreadable",  # any other OSError
    "not-ips",  # first line is not a JSON header (text .diag reports, etc.)
    "non-crash",  # valid header whose bug_type is not a crash
    "legacy",  # the old text crash format (bug_type 109)
    "malformed",  # crash header, but the body is empty, truncated or the wrong shape
)


@dataclass(frozen=True, slots=True)
class Skipped:
    path: str
    kind: str
    reason: str

    def __post_init__(self) -> None:
        if self.kind not in SKIP_KINDS:
            raise ValueError(f"unknown skip kind {self.kind!r}")
