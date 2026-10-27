"""Make a copy of a diagnostic report that is safe to commit as a test fixture.

Usage:
    python -m crashtriage.anonymize SRC DST [--salt HEX] [--max-list-items N]
                                            [--truncate-bytes N]

The source file is only read. What is removed or replaced (see NOTES.md for why):

* every UUID (incident ids, image UUIDs, boot/sleep session ids) -> a keyed hash
  of the form 00000000-0000-0000-XXXX-XXXXXXXXXXXX, consistent within one salt, so
  the header's incident_id still equals the body's incident
* device and account fields: crashReporterKey, userID, trialInfo,
  codeSigningTeamID, logWritingSignature, anything with "serial" in its key
* home folders (/Users/<name>), the login name, the full name and the hostname
* absolute paths outside the OS (see paths.SYSTEM_PREFIXES) -> /REDACTED/<basename>
* MAC addresses, email addresses and token-like strings (GitHub/OpenAI/AWS/Slack
  tokens, JWTs, and long base64/hex runs outside symbol names)

The JSON documents are parsed, scrubbed value by value, and written back out. A
file that is not JSON is scrubbed as plain text with the same string rules.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import socket
import sys
from collections.abc import Iterable
from typing import Any

from .paths import is_system_path

REDACTED = "REDACTED"

_UUID = re.compile(r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b")
_ANON_UUID_PREFIX = "00000000-0000-0000-"
_MAC = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_TOKENS = [
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
]
# Long runs of base64/hex characters that mix letters and digits. Not applied to
# symbol names, where long mangled identifiers are normal and not secret. "/" is
# left out of the class so that long system paths are never mistaken for tokens.
_GENERIC_TOKEN = re.compile(r"(?<![A-Za-z0-9+=_])(?=[A-Za-z0-9+=_]*[0-9])(?=[A-Za-z0-9+=_]*[A-Za-z])[A-Za-z0-9+=_]{32,}(?![A-Za-z0-9+=_])")
_HOME = re.compile(r"/Users/(?!Shared(?:/|$))(?!USER(?:/|$))[^/\s\"']+")
# An absolute path inside free text: starts at a "/" that does not follow a word
# character (so "r-x/r-x" is not a path) and runs to the next whitespace or quote.
# It continues across a single space when the next word contains another "/", so
# "/Users/USER/Secret Project/app" is caught whole and "Secret Project" is removed.
_TEXT_PATH = re.compile(r"(?<![\w./*-])/[^\s\"'<>|]+(?: [^\s\"'<>|/]*/[^\s\"'<>|]*)*")

# The same kind of fields in the plain-text report formats ("Team ID:  ABC123").
_TEXT_FIELDS = re.compile(
    r"^(?P<label>[ \t]*(?:Team ID|Serial Number|Hardware UUID|Crash Reporter Key|CrashReporter Key"
    r"|Anonymous UUID|Sleep/Wake UUID|Boot Session UUID|Beta Identifier)[ \t]*:[ \t]*)\S.*$",
    re.MULTILINE | re.IGNORECASE,
)

# Keys whose values identify the device, the account or the signer.
_REPLACE_BY_KEY: dict[str, Any] = {
    "crashReporterKey": REDACTED,
    "userID": -1,
    "trialInfo": {},
    "codeSigningTeamID": REDACTED,
    "logWritingSignature": REDACTED,
}
_SYMBOL_KEYS = frozenset({"symbol"})


class Anonymizer:
    def __init__(
        self,
        salt: bytes,
        *,
        usernames: Iterable[str] | None = None,
        hostnames: Iterable[str] | None = None,
        real_names: Iterable[str] | None = None,
    ) -> None:
        self._salt = salt
        self._usernames = sorted({u for u in (usernames if usernames is not None else _local_usernames()) if len(u) >= 2}, key=len, reverse=True)
        self._hostnames = sorted({h for h in (hostnames if hostnames is not None else _local_hostnames()) if len(h) >= 2}, key=len, reverse=True)
        self._real_names = sorted({n for n in (real_names if real_names is not None else _local_real_names()) if len(n) >= 3}, key=len, reverse=True)

    # --- documents --------------------------------------------------------------

    def anonymize_bytes(self, raw: bytes) -> bytes:
        text = raw.decode("utf-8", errors="replace").removeprefix("\ufeff")
        header_line, newline, body_text = text.partition("\n")
        try:
            header = json.loads(header_line)
        except json.JSONDecodeError:
            return self.scrub_text(text).encode("utf-8")

        out = [json.dumps(self.scrub_value(header), ensure_ascii=False, separators=(",", ":"))]
        if newline:
            try:
                body = json.loads(body_text)
            except json.JSONDecodeError:
                out.append(self.scrub_text(body_text))
            else:
                out.append(json.dumps(self.scrub_value(body), ensure_ascii=False, indent=2) + "\n")
        return "\n".join(out).encode("utf-8")

    # --- values -----------------------------------------------------------------

    def scrub_value(self, value: Any, key: str | None = None) -> Any:
        if key is not None:
            if key in _REPLACE_BY_KEY and value not in (None, ""):
                return _REPLACE_BY_KEY[key]
            if "serial" in key.lower() and value not in (None, ""):
                return REDACTED
        if isinstance(value, dict):
            return {k: self.scrub_value(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub_value(item, key) for item in value]
        if isinstance(value, str):
            if value.startswith("/") and "\n" not in value:
                return self._scrub_whole_path(value)
            return self.scrub_text(value, symbol=key in _SYMBOL_KEYS)
        return value

    def _scrub_whole_path(self, path: str) -> str:
        if is_system_path(path):
            return self.scrub_text(path)
        basename = path.rstrip("/").rsplit("/", 1)[-1]
        return "/REDACTED/" + self.scrub_text(basename)

    def scrub_text(self, text: str, *, symbol: bool = False) -> str:
        text = _TEXT_FIELDS.sub(lambda m: m.group("label") + REDACTED, text)
        text = _HOME.sub("/Users/USER", text)
        text = _TEXT_PATH.sub(lambda m: self._scrub_text_path(m.group(0)), text)
        for name in self._real_names:
            text = re.sub(re.escape(name), "REAL_NAME", text, flags=re.IGNORECASE)
        for host in self._hostnames:
            text = re.sub(rf"(?<![A-Za-z0-9-]){re.escape(host)}(?![A-Za-z0-9-])", "HOST", text, flags=re.IGNORECASE)
        for user in self._usernames:
            text = re.sub(rf"(?<![A-Za-z0-9]){re.escape(user)}(?![A-Za-z0-9])", "USER", text)
        text = _EMAIL.sub("user@example.invalid", text)
        for pattern in _TOKENS:
            text = pattern.sub("REDACTED_TOKEN", text)
        text = _MAC.sub(lambda m: m.group(1).join(["XX"] * 6), text)
        text = _UUID.sub(lambda m: self.fake_uuid(m.group(0)), text)
        if not symbol:
            text = _GENERIC_TOKEN.sub("REDACTED_TOKEN", text)
        return text

    def _scrub_text_path(self, path: str) -> str:
        if is_system_path(path):
            return path
        basename = path.rstrip("/").rsplit("/", 1)[-1]
        return "/REDACTED/" + basename

    def fake_uuid(self, original: str) -> str:
        if original.startswith(_ANON_UUID_PREFIX):
            return original
        digest = hmac.new(self._salt, original.lower().encode(), hashlib.sha256).hexdigest()
        fake = f"{_ANON_UUID_PREFIX}{digest[:4]}-{digest[4:16]}"
        return fake.lower() if original == original.lower() else fake.upper()


# --- facts about the local machine, read at run time, never stored --------------


def _local_usernames() -> set[str]:
    names = {getpass.getuser(), os.path.basename(os.path.expanduser("~"))}
    return {n for n in names if n and n not in ("root", "USER")}


def _local_hostnames() -> set[str]:
    full = socket.gethostname()
    names = {full, full.split(".")[0]}
    return {n for n in names if n and n.lower() not in ("localhost", "host")}


def _local_real_names() -> set[str]:
    try:
        gecos = pwd.getpwuid(os.getuid()).pw_gecos
    except KeyError:
        return set()
    return {gecos.split(",")[0].strip()} - {""}


# --- fixture helpers ------------------------------------------------------------


def trim_lists(raw: bytes, max_items: int) -> bytes:
    """Keep only the first `max_items` entries of every list in the body (used to
    shrink large non-crash reports, e.g. a JetsamEvent's process table)."""
    header_line, _, body_text = raw.decode("utf-8").partition("\n")

    def trim(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: trim(v) for k, v in value.items()}
        if isinstance(value, list):
            return [trim(v) for v in value[:max_items]]
        return value

    body = trim(json.loads(body_text))
    return (header_line + "\n" + json.dumps(body, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m crashtriage.anonymize", description=__doc__.split("\n\n")[0])
    parser.add_argument("src", help="report to copy (read-only)")
    parser.add_argument("dst", help="where to write the anonymized copy")
    parser.add_argument("--salt", help="hex salt for the UUID hash (default: random per run)")
    parser.add_argument("--max-list-items", type=int, help="after anonymizing, keep only the first N entries of every body list")
    parser.add_argument("--truncate-bytes", type=int, help="after anonymizing, keep only the first N bytes (to make a malformed fixture)")
    args = parser.parse_args(argv)

    if os.path.abspath(args.src) == os.path.abspath(args.dst):
        parser.error("refusing to overwrite the source file")
    salt = bytes.fromhex(args.salt) if args.salt else secrets.token_bytes(16)
    with open(args.src, "rb") as fh:
        raw = fh.read()
    out = Anonymizer(salt).anonymize_bytes(raw)
    if args.max_list_items is not None:
        out = trim_lists(out, args.max_list_items)
    if args.truncate_bytes is not None:
        out = out[: args.truncate_bytes]
    try:
        with open(args.dst, "xb") as fh:  # never overwrite an existing file
            fh.write(out)
    except FileExistsError:
        parser.error(f"{args.dst} already exists; refusing to overwrite it")
    print(f"wrote {len(out)} bytes to {args.dst}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
