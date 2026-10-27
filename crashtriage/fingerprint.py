"""Crash fingerprints: one stable id per root cause.

The rule (version 1), in order:

1. Take the frames of the faulting thread.
2. Drop frames in anonymous memory (image `source` "A", no name and no path), such
   as JIT-compiled code. Their `imageOffset` is an absolute address that changes on
   every run, so they carry no identity.
3. Classify the rest. A frame is a *system* frame when its image lives under an OS
   prefix (paths.SYSTEM_PREFIXES), unless that image is the crashing process's own
   executable. Every other frame is an *app* frame: the executable, its bundled
   frameworks, and anything installed outside the OS (/usr/local, /opt, ~).
4. If there is at least one app frame, keep only app frames. The system frames on
   top of a crash (abort, pthread_kill, objc_exception_throw, swift
   _assertionFailure) say how the process died, not where the bug is, and they are
   the same for unrelated bugs. Otherwise (a crash entirely inside the OS), keep
   the system frames, and mark the basis "system-only".
5. Take the first TOP_N of them and turn each into a token: `image!symbol` when the
   frame is symbolicated, else `image+0x<offset>`. The token deliberately leaves
   out symbolLocation, image UUID, load address and app version, because those
   change between builds while the bug does not.
6. Hash "crashtriage-fp-v1", the process name, the exception type and the tokens
   with SHA-256 and keep the first 16 hex digits.

Known limitation: an unsymbolicated app frame is identified by its offset, which
moves between builds, so the same bug in two unsymbolicated versions gets two
fingerprints. `--symbolicate` (dSYM + atos) restores the symbol names.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .model import CrashReport, Frame
from .paths import is_system_path

FINGERPRINT_VERSION = "crashtriage-fp-v1"
TOP_N = 5


@dataclass(frozen=True, slots=True)
class Fingerprint:
    value: str  # 16 lowercase hex digits
    basis: str  # "app", "system-only" or "no-frames"
    tokens: tuple[str, ...]
    frame_indices: tuple[int, ...]  # positions in the faulting thread of the hashed frames

    @property
    def top_frame(self) -> str | None:
        return self.tokens[0] if self.tokens else None


def frame_token(frame: Frame) -> str:
    image = frame.image_name or "?"
    if frame.symbol:
        return f"{image}!{frame.symbol}"
    if frame.image_offset is not None:
        return f"{image}+0x{frame.image_offset:x}"
    return f"{image}+?"


def classify(frame: Frame, report: CrashReport) -> str:
    """'anonymous', 'system' or 'app'."""
    index = frame.image_index
    if index is None or not 0 <= index < len(report.images):
        return "anonymous"
    image = report.images[index]
    if image.is_anonymous:
        return "anonymous"
    main = report.main_image
    if main is not None and image.index == main.index:
        return "app"
    return "system" if is_system_path(image.path) else "app"


def fingerprint(report: CrashReport, top_n: int = TOP_N) -> Fingerprint:
    thread = report.faulting
    frames = thread.frames if thread is not None else ()
    kinds = [classify(frame, report) for frame in frames]
    app = [i for i, kind in enumerate(kinds) if kind == "app"]
    system = [i for i, kind in enumerate(kinds) if kind == "system"]
    if app:
        chosen, basis = app, "app"
    elif system:
        chosen, basis = system, "system-only"
    else:
        chosen, basis = [], "no-frames"
    chosen = chosen[:top_n]
    tokens = tuple(frame_token(frames[i]) for i in chosen)
    material = "\0".join([FINGERPRINT_VERSION, report.process_name, report.exception_type or "", "\n".join(tokens)])
    value = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return Fingerprint(value=value, basis=basis, tokens=tokens, frame_indices=tuple(chosen))
