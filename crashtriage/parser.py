"""Turn one .ips file into a CrashReport, or into a Skipped that says why not.

The layout (observed on macOS 26, see NOTES.md): line 1 is a JSON header object;
for crash reports (bug_type "309") the rest of the file is one JSON body object.
Other diagnostic types share the folder and are recognized and skipped. Nothing in
here raises for bad input: every problem becomes a Skipped or a warning.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .model import CrashReport, Frame, Image, Skipped, ThreadRec

CRASH_BUG_TYPES = frozenset({"309"})
LEGACY_CRASH_BUG_TYPES = frozenset({"109"})

# Labels for the non-crash bug_types seen on the development Mac. They are inferred
# from file contents, not from Apple documentation, and are only used in messages.
NON_CRASH_LABELS = {
    "211": "analytics",
    "226": "analytics log",
    "298": "jetsam event",
    "303": "event tracker",
}


class _Malformed(Exception):
    """Raised inside the builder when the body has an unexpected shape."""


def parse_file(path: str | Path) -> CrashReport | Skipped:
    """Read one file (read-only) and parse it."""
    path = str(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except PermissionError as exc:
        return Skipped(path, "permission", f"permission denied: {exc.strerror or exc}")
    except OSError as exc:
        return Skipped(path, "unreadable", f"{type(exc).__name__}: {exc.strerror or exc}")
    return parse_bytes(data, path)


def parse_bytes(data: bytes, path: str = "<memory>") -> CrashReport | Skipped:
    warnings: list[str] = []
    sha256 = hashlib.sha256(data).hexdigest()

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        text = data.decode("utf-8", errors="replace")
        warnings.append(f"non-UTF-8 bytes replaced with U+FFFD (first at byte {exc.start})")
    text = text.removeprefix("\ufeff")

    header_line, _, body_text = text.partition("\n")
    try:
        header = json.loads(header_line)
    except json.JSONDecodeError:
        return Skipped(path, "not-ips", "first line is not a JSON header")
    if not isinstance(header, dict):
        return Skipped(path, "not-ips", "first line is JSON but not an object")

    raw_bug_type = header.get("bug_type")
    if raw_bug_type is None:
        return Skipped(path, "non-crash", "header has no bug_type (e.g. a panic summary)")
    bug_type = str(raw_bug_type)
    if bug_type in LEGACY_CRASH_BUG_TYPES:
        return Skipped(path, "legacy", f"bug_type {bug_type}: legacy text crash format is not supported")
    if bug_type not in CRASH_BUG_TYPES:
        label = NON_CRASH_LABELS.get(bug_type, "not a crash report")
        return Skipped(path, "non-crash", f"bug_type {bug_type} ({label})")

    if not body_text.strip():
        return Skipped(path, "malformed", "crash header but the body is empty")
    try:
        body = json.loads(body_text)
    except json.JSONDecodeError as exc:
        return Skipped(path, "malformed", f"body is not valid JSON: {exc.msg} at line {exc.lineno + 1} column {exc.colno}")
    if not isinstance(body, dict):
        return Skipped(path, "malformed", "body is JSON but not an object")

    try:
        return _build(header, body, bug_type, sha256, warnings)
    except _Malformed as exc:
        return Skipped(path, "malformed", str(exc))
    except (TypeError, ValueError, AttributeError, KeyError, IndexError) as exc:
        # Defensive net: a shape the typed getters did not anticipate.
        return Skipped(path, "malformed", f"unexpected structure: {type(exc).__name__}: {exc}")


# --- typed getters -----------------------------------------------------------


def _str(obj: dict[str, Any], key: str) -> str | None:
    """A string field. Empty strings mean "unknown" (dotnet's app_version is "")."""
    value = obj.get(key)
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    raise _Malformed(f"{key} should be a string, got {type(value).__name__}")


def _int(obj: dict[str, Any], key: str) -> int | None:
    value = obj.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        raise _Malformed(f"{key} should be an integer, got bool")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    raise _Malformed(f"{key} should be an integer, got {type(value).__name__}")


def _dict(obj: dict[str, Any], key: str) -> dict[str, Any]:
    value = obj.get(key)
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    raise _Malformed(f"{key} should be an object, got {type(value).__name__}")


def _list(obj: dict[str, Any], key: str) -> list[Any]:
    value = obj.get(key)
    if value is None:
        return []
    if isinstance(value, list):
        return value
    raise _Malformed(f"{key} should be a list, got {type(value).__name__}")


def _object(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _Malformed(f"{what} should be an object, got {type(value).__name__}")
    return value


# --- field helpers ------------------------------------------------------------

_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z")


def parse_timestamp(raw: str) -> str | None:
    """'2026-10-26 18:25:55.00 -0400' -> '2026-10-26T22:25:55Z' (UTC, whole seconds)."""
    for fmt in _TIME_FORMATS:
        try:
            moment = datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
        return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


_OS_VERSION = re.compile(r"^(?P<train>.+?)\s*\((?:Build\s+)?(?P<build>[0-9A-Za-z]+)\)\s*$")


def _os_fields(header: dict[str, Any], body: dict[str, Any]) -> tuple[str | None, str | None]:
    os_body = _dict(body, "osVersion")
    train, build = _str(os_body, "train"), _str(os_body, "build")
    if train and build:
        return train, build
    header_os = _str(header, "os_version")
    if header_os:
        match = _OS_VERSION.match(header_os)
        if match:
            return train or match["train"], build or match["build"]
        return train or header_os, build
    return train, build


def _build(
    header: dict[str, Any],
    body: dict[str, Any],
    bug_type: str,
    sha256: str,
    warnings: list[str],
) -> CrashReport:
    incident_id = _str(header, "incident_id") or _str(body, "incident")
    if incident_id is None:
        incident_id = f"sha256-{sha256[:32]}"
        warnings.append("no incident id; using a hash of the file contents")
    else:
        body_incident = _str(body, "incident")
        if body_incident is not None and body_incident.lower() != incident_id.lower():
            warnings.append("header incident_id and body incident differ; using the header")

    process_name = _str(body, "procName") or _str(header, "app_name") or _str(header, "name")
    if process_name is None:
        raise _Malformed("no process name (procName, app_name and name are all missing)")

    # captureTime is when the process crashed; the header timestamp is when the
    # report was written, which can be many seconds later and is shared by
    # different crashes written in the same batch (seen with dotnet, see NOTES.md).
    timestamp_raw = _str(body, "captureTime") or _str(header, "timestamp")
    timestamp = parse_timestamp(timestamp_raw) if timestamp_raw else None
    if timestamp is None:
        warnings.append(f"unparseable or missing timestamp: {timestamp_raw!r}")

    bundle = _dict(body, "bundleInfo")
    exception = _dict(body, "exception")
    termination = _dict(body, "termination")
    os_version, os_build = _os_fields(header, body)

    images = tuple(_image(index, _object(raw, f"usedImages[{index}]")) for index, raw in enumerate(_list(body, "usedImages")))
    threads = tuple(
        _thread(index, _object(raw, f"threads[{index}]"), images, warnings)
        for index, raw in enumerate(_list(body, "threads"))
    )
    if not threads:
        warnings.append("report has no threads")

    faulting_thread = _int(body, "faultingThread")
    triggered = [t.index for t in threads if t.triggered]
    if faulting_thread is None:
        if len(triggered) == 1:
            faulting_thread = triggered[0]
            warnings.append("no faultingThread; using the thread marked triggered")
        else:
            warnings.append("no faultingThread")
    elif not 0 <= faulting_thread < len(threads):
        warnings.append(f"faultingThread {faulting_thread} is out of range ({len(threads)} threads)")
    elif triggered and faulting_thread not in triggered:
        warnings.append(f"faultingThread {faulting_thread} is not the triggered thread {triggered}")

    return CrashReport(
        incident_id=incident_id,
        timestamp=timestamp,
        timestamp_raw=timestamp_raw,
        process_name=process_name,
        process_version=_str(header, "app_version") or _str(bundle, "CFBundleShortVersionString"),
        build_version=_str(header, "build_version") or _str(bundle, "CFBundleVersion"),
        process_path=_str(body, "procPath"),
        pid=_int(body, "pid"),
        os_version=os_version,
        os_build=os_build,
        bug_type=bug_type,
        cpu_type=_str(body, "cpuType"),
        exception_type=_str(exception, "type"),
        signal=_str(exception, "signal"),
        exception_subtype=_str(exception, "subtype"),
        termination_namespace=_str(termination, "namespace"),
        termination_code=_int(termination, "code"),
        termination_indicator=_str(termination, "indicator"),
        faulting_thread=faulting_thread,
        threads=threads,
        images=images,
        source_sha256=sha256,
        warnings=tuple(warnings),
    )


def _image(index: int, raw: dict[str, Any]) -> Image:
    return Image(
        index=index,
        name=_str(raw, "name"),
        path=_str(raw, "path"),
        uuid=_str(raw, "uuid"),
        base=_int(raw, "base"),
        size=_int(raw, "size"),
        source=_str(raw, "source"),
        arch=_str(raw, "arch"),
        bundle_id=_str(raw, "CFBundleIdentifier"),
        version=_str(raw, "CFBundleShortVersionString"),
    )


def _thread(index: int, raw: dict[str, Any], images: tuple[Image, ...], warnings: list[str]) -> ThreadRec:
    frames = []
    for frame_index, frame_raw in enumerate(_list(raw, "frames")):
        frame_raw = _object(frame_raw, f"threads[{index}].frames[{frame_index}]")
        image_index = _int(frame_raw, "imageIndex")
        image_name = None
        if image_index is not None and 0 <= image_index < len(images):
            image_name = images[image_index].name
        else:
            warnings.append(f"thread {index} frame {frame_index}: imageIndex {image_index} does not match an image")
        offset = _int(frame_raw, "imageOffset")
        if offset is None:
            warnings.append(f"thread {index} frame {frame_index}: no imageOffset")
        frames.append(
            Frame(
                image_index=image_index,
                image_name=image_name,
                image_offset=offset,
                symbol=_str(frame_raw, "symbol"),
                symbol_location=_int(frame_raw, "symbolLocation"),
                source_file=_str(frame_raw, "sourceFile"),
                source_line=_int(frame_raw, "sourceLine"),
            )
        )
    return ThreadRec(
        index=index,
        thread_id=_int(raw, "id"),
        name=_str(raw, "name"),
        queue=_str(raw, "queue"),
        triggered=raw.get("triggered") is True,
        frames=tuple(frames),
        original_length=_int(raw, "originalLength"),
    )
