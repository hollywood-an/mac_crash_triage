"""Which file system locations belong to the operating system."""

from __future__ import annotations

# Images under these prefixes ship with macOS. /usr/local and /opt are not here on
# purpose: they hold software the user installed (Homebrew, the .NET SDK, ...).
SYSTEM_PREFIXES: tuple[str, ...] = (
    "/System/",
    "/usr/lib/",
    "/usr/libexec/",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/Library/Apple/",
)


def is_system_path(path: str | None) -> bool:
    return bool(path) and path.startswith(SYSTEM_PREFIXES)
