"""Break the code that handles each injected defect and confirm the tests notice.

For each mutation: copy crashtriage/ and tests/ to a temporary folder, apply one
textual change, run the whole test suite there, and record which tests fail. A
mutation that no test catches is a gap. The repo itself is never modified.

    .venv/bin/python scripts/mutation_check.py
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (defect it relates to, file, original text, replacement)
MUTATIONS = [
    ("frame with a missing offset", "crashtriage/parser.py",
     'offset = _int(frame_raw, "imageOffset")', 'offset = int(frame_raw["imageOffset"])'),
    ("duplicate incident", "crashtriage/store.py",
     "INSERT OR IGNORE INTO incidents", "INSERT OR REPLACE INTO incidents"),
    ("same bug, naive hash splits (build details hashed)", "crashtriage/fingerprint.py",
     'return f"{image}!{frame.symbol}"', 'return f"{image}!{frame.symbol}+{frame.symbol_location}"'),
    ("same bug, naive hash splits (JIT frames hashed)", "crashtriage/fingerprint.py",
     'if image.is_anonymous:\n        return "anonymous"', 'if False:\n        return "anonymous"'),
    ("all system frames (no fallback)", "crashtriage/fingerprint.py",
     "elif system:", "elif False:"),
    ("system frames on top not skipped", "crashtriage/fingerprint.py",
     'return "system" if is_system_path(image.path) else "app"', 'return "app"'),
    ("non-UTF-8 byte", "crashtriage/parser.py",
     'text = data.decode("utf-8", errors="replace")', 'text = data.decode("utf-8")'),
    ("empty body", "crashtriage/parser.py",
     "if not body_text.strip():", "if False:"),
    ("inputs opened for writing", "crashtriage/parser.py",
     'with open(path, "rb") as fh:', 'with open(path, "r+b") as fh:'),
    ("atos output that does not line up (symbolication)", "crashtriage/symbolicate.py",
     "if len(lines) != len(offsets):", "if False:"),
    ("dSYM used without a UUID match (symbolication)", "crashtriage/symbolicate.py",
     "or image.uuid.lower() not in dsyms:", "or not dsyms:"),
]


def run_suite(root: Path) -> tuple[int, list[str]]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "addopts="],
        cwd=root,
        capture_output=True,
        text=True,
    )
    failed = sorted(set(re.findall(r"^(?:FAILED|ERROR) (\S+)", result.stdout, re.MULTILINE)))
    return result.returncode, failed


def main() -> int:
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for index, (defect, file, old, new) in enumerate([("baseline (no change)", None, None, None)] + MUTATIONS):
            root = Path(tmp) / f"m{index}"
            for part in ("crashtriage", "tests", "pyproject.toml"):
                source = REPO / part
                (shutil.copytree if source.is_dir() else shutil.copy)(source, root / part)
            if file is not None:
                target = root / file
                text = target.read_text()
                if text.count(old) != 1:
                    print(f"mutation for {defect!r} does not apply cleanly to {file}", file=sys.stderr)
                    return 2
                target.write_text(text.replace(old, new))
            code, failed = run_suite(root)
            rows.append((defect, file, code, failed))

    print("| Mutation (breaks the handling of ...) | File | Suite | Failing tests |")
    print("|---|---|---|---|")
    gaps = 0
    for defect, file, code, failed in rows:
        if file is None:
            status = "passes" if code == 0 else f"FAILS ({code})"
        else:
            status = "caught" if code != 0 else "NOT CAUGHT"
            gaps += code == 0
        defect_tests = [f.split("::")[1] for f in failed if "test_defects.py" in f]
        detail = f"{len(failed)}" + (f" (incl. {', '.join(defect_tests)})" if defect_tests else "")
        print(f"| {defect} | {file or '-'} | {status} | {detail if file else '-'} |")
    baseline_ok = rows[0][2] == 0
    return 0 if baseline_ok and gaps == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
