"""Name unsymbolicated frames using dSYMs you have, with Apple's `atos`.

A crash report names a frame only if macOS could find symbols when it wrote the
report. For binaries you built yourself, the dSYM written at build time holds the
names. This module:

1. reads the UUID and architecture of every Mach-O file inside the given dSYM
   bundles (`LC_UUID`, parsed here with `struct`, no external tools),
2. for each report image whose UUID matches a dSYM, asks `atos` for the frames
   that have no symbol (`atos -o <dSYM DWARF file> -arch <arch> -l <load address>
   <address> ...`, one call per image), and
3. fills in the symbol and source location of the frames atos resolved.

Matching is by UUID only, so a dSYM from a different build is never used. Frames
that already have a symbol, and frames in anonymous memory, are left alone.
"""

from __future__ import annotations

import dataclasses
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from .fingerprint import fingerprint
from .model import CrashReport, Frame
from .store import load_report

# --- Mach-O --------------------------------------------------------------------

MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_UUID = 0x1B
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_MASK = 0xFF000000


class MachOError(ValueError):
    pass


def _arch_name(cputype: int, cpusubtype: int) -> str:
    if cputype == CPU_TYPE_ARM64:
        return "arm64e" if (cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E else "arm64"
    if cputype == CPU_TYPE_X86_64:
        return "x86_64"
    return f"cpu{cputype:#x}"


def _thin_uuid(data: bytes, start: int) -> tuple[str, str]:
    if len(data) < start + 28:
        raise MachOError("truncated Mach-O header")
    (magic,) = struct.unpack_from("<I", data, start)
    if magic == MH_MAGIC_64:
        header_size = 32
    elif magic == MH_MAGIC:
        header_size = 28
    else:
        raise MachOError(f"not a little-endian Mach-O file (magic {magic:#x})")
    cputype, cpusubtype, _filetype, ncmds, _sizeofcmds = struct.unpack_from("<iIIII", data, start + 4)
    offset = start + header_size
    for _ in range(ncmds):
        if len(data) < offset + 8:
            raise MachOError("truncated load command")
        cmd, cmdsize = struct.unpack_from("<II", data, offset)
        if cmd == LC_UUID:
            if cmdsize < 24 or len(data) < offset + 24:
                raise MachOError("truncated LC_UUID")
            return str(uuid.UUID(bytes=data[offset + 8 : offset + 24])), _arch_name(cputype & 0xFFFFFFFF, cpusubtype)
        if cmdsize < 8:
            raise MachOError("bad load command size")
        offset += cmdsize
    raise MachOError("no LC_UUID load command")


def macho_uuids(data: bytes) -> list[tuple[str, str]]:
    """(uuid, arch) for every slice of a thin or universal (fat) Mach-O file."""
    if len(data) < 8:
        raise MachOError("file too small")
    (magic,) = struct.unpack_from(">I", data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        (count,) = struct.unpack_from(">I", data, 4)
        result = []
        for i in range(count):
            if magic == FAT_MAGIC:
                _cputype, _sub, offset, _size, _align = struct.unpack_from(">iIIII", data, 8 + 20 * i)
            else:
                _cputype, _sub, offset, _size, _align, _reserved = struct.unpack_from(">iIQQII", data, 8 + 32 * i)
            result.append(_thin_uuid(data, offset))
        return result
    return [_thin_uuid(data, 0)]


@dataclass(frozen=True)
class DsymFile:
    path: str  # the DWARF file inside the bundle: X.dSYM/Contents/Resources/DWARF/X
    arch: str


def find_dsyms(paths: Iterable[str | Path]) -> dict[str, DsymFile]:
    """Index dSYMs by lowercase UUID. Each path is a .dSYM bundle, a DWARF file, or
    a folder searched recursively for .dSYM bundles."""
    index: dict[str, DsymFile] = {}

    def add_file(path: str) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            slices = macho_uuids(data)
        except (OSError, MachOError):
            return
        for value, arch in slices:
            index.setdefault(value.lower(), DsymFile(path, arch))

    def add_bundle(bundle: str) -> None:
        dwarf = os.path.join(bundle, "Contents", "Resources", "DWARF")
        if os.path.isdir(dwarf):
            for name in sorted(os.listdir(dwarf)):
                add_file(os.path.join(dwarf, name))

    for path in paths:
        path = str(path)
        if path.endswith(".dSYM") and os.path.isdir(path):
            add_bundle(path)
        elif os.path.isfile(path):
            add_file(path)
        elif os.path.isdir(path):
            for dirpath, dirnames, _ in os.walk(path):
                dirnames.sort()
                for name in list(dirnames):
                    if name.endswith(".dSYM"):
                        add_bundle(os.path.join(dirpath, name))
                        dirnames.remove(name)
    return index


# --- atos ------------------------------------------------------------------------

# "parse_record (in ct-crasher-stripped) (versioned.c:24)"
# "parse_record (in ct-crasher-stripped) + 12"
# Unresolved addresses come back as "0x..." (optionally with "(in image)").
_ATOS_LINE = re.compile(
    r"^(?P<symbol>.+?) \(in (?P<image>[^)]+)\)(?: \+ (?P<offset>\d+))?(?: \((?P<file>[^():]+):(?P<line>\d+)\))?$"
)


@dataclass(frozen=True)
class Resolved:
    symbol: str
    source_file: str | None
    source_line: int | None


def parse_atos_line(line: str) -> Resolved | None:
    match = _ATOS_LINE.match(line.strip())
    if match is None or match["symbol"].startswith("0x"):
        return None
    return Resolved(match["symbol"], match["file"], int(match["line"]) if match["line"] else None)


AtosRunner = Callable[[list[str]], str]


def atos_path() -> str | None:
    found = shutil.which("atos")
    if found:
        return found
    return "/usr/bin/atos" if os.access("/usr/bin/atos", os.X_OK) else None


def run_atos(args: list[str]) -> str:
    """Run atos and return its stdout. Any failure returns "", which the caller
    treats as "nothing resolved" (atos prints its errors on stderr)."""
    atos = atos_path()
    if atos is None:
        return ""
    try:
        result = subprocess.run([atos, *args], capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout


@dataclass
class SymbolicationResult:
    frames_resolved: int = 0
    frames_unresolved: int = 0
    images_matched: int = 0


def symbolicate_report(
    report: CrashReport,
    dsyms: dict[str, DsymFile],
    runner: AtosRunner | None = None,
) -> tuple[CrashReport, SymbolicationResult]:
    """Return a copy of the report with matching frames named, and counts."""
    runner = runner or run_atos
    stats = SymbolicationResult()
    # (thread index, frame index) of frames to resolve, grouped by image index.
    wanted: dict[int, list[tuple[int, int]]] = {}
    for thread in report.threads:
        for n, frame in enumerate(thread.frames):
            if frame.symbol or frame.image_offset is None or frame.image_index is None:
                continue
            if not 0 <= frame.image_index < len(report.images):
                continue
            image = report.images[frame.image_index]
            if image.is_anonymous or image.uuid is None or image.base is None or image.uuid.lower() not in dsyms:
                continue
            wanted.setdefault(frame.image_index, []).append((thread.index, n))

    resolved: dict[tuple[int, int], Resolved] = {}
    frames_by_thread = {t.index: t.frames for t in report.threads}
    for image_index, positions in sorted(wanted.items()):
        image = report.images[image_index]
        dsym = dsyms[image.uuid.lower()]
        offsets = sorted({frames_by_thread[t][n].image_offset for t, n in positions})
        args = ["-o", dsym.path, "-arch", image.arch or dsym.arch, "-l", f"{image.base:#x}"]
        args += [f"{image.base + offset:#x}" for offset in offsets]
        lines = runner(args).splitlines()
        stats.images_matched += 1
        if len(lines) != len(offsets):
            # atos failed or printed something unexpected: use nothing rather than
            # risk pairing a name with the wrong address.
            stats.frames_unresolved += len(positions)
            continue
        names = dict(zip(offsets, (parse_atos_line(line) for line in lines), strict=True))
        for t, n in positions:
            name = names[frames_by_thread[t][n].image_offset]
            if name is None:
                stats.frames_unresolved += 1
            else:
                resolved[(t, n)] = name
                stats.frames_resolved += 1

    if not resolved:
        return report, stats

    def update(thread_index: int, n: int, frame: Frame) -> Frame:
        name = resolved.get((thread_index, n))
        if name is None:
            return frame
        return dataclasses.replace(frame, symbol=name.symbol, source_file=name.source_file, source_line=name.source_line)

    threads = tuple(
        dataclasses.replace(t, frames=tuple(update(t.index, n, f) for n, f in enumerate(t.frames))) for t in report.threads
    )
    return dataclasses.replace(report, threads=threads), stats


# --- the database ------------------------------------------------------------------


@dataclass
class StoredSymbolication:
    incidents_changed: int = 0
    frames_resolved: int = 0
    frames_unresolved: int = 0
    clusters_before: int = 0
    clusters_after: int = 0


def symbolicate_stored(conn: sqlite3.Connection, dsyms: dict[str, DsymFile], runner: AtosRunner | None = None) -> StoredSymbolication:
    """Symbolicate every stored incident that has unnamed frames in an image with a
    matching dSYM, update those frames, and recompute the incidents' fingerprints.
    Running it again changes nothing: named frames are never touched."""
    out = StoredSymbolication()
    out.clusters_before = conn.execute("SELECT COUNT(DISTINCT fingerprint) FROM incidents").fetchone()[0]
    if dsyms:
        marks = ",".join("?" * len(dsyms))
        candidates = [
            row[0]
            for row in conn.execute(
                f"""SELECT DISTINCT f.incident_id FROM frames f
                    JOIN images i ON i.incident_id = f.incident_id AND i.image_index = f.image_index
                    WHERE f.symbol IS NULL AND lower(i.uuid) IN ({marks})
                    ORDER BY f.incident_id""",
                list(dsyms),
            )
        ]
    else:
        candidates = []
    for incident_id in candidates:
        before = load_report(conn, incident_id)
        after, stats = symbolicate_report(before, dsyms, runner)
        out.frames_resolved += stats.frames_resolved
        out.frames_unresolved += stats.frames_unresolved
        if after is before:
            continue
        fp = fingerprint(after)
        with conn:
            for old_thread, new_thread in zip(before.threads, after.threads, strict=True):
                for n, (old, new) in enumerate(zip(old_thread.frames, new_thread.frames, strict=True)):
                    if old.symbol is None and new.symbol is not None:
                        conn.execute(
                            """UPDATE frames SET symbol = ?, source_file = ?, source_line = ?
                               WHERE incident_id = ? AND thread_index = ? AND frame_index = ? AND symbol IS NULL""",
                            (new.symbol, new.source_file, new.source_line, incident_id, new_thread.index, n),
                        )
            conn.execute(
                "UPDATE incidents SET fingerprint = ?, fingerprint_basis = ?, top_frame = ? WHERE incident_id = ?",
                (fp.value, fp.basis, fp.top_frame, incident_id),
            )
        out.incidents_changed += 1
    out.clusters_after = conn.execute("SELECT COUNT(DISTINCT fingerprint) FROM incidents").fetchone()[0]
    return out
