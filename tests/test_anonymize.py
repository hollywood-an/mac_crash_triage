"""The anonymizer must remove every planted canary and keep the report parseable."""

from __future__ import annotations

import json
import os

import pytest

from conftest import fixture_bytes, fixture_path
from crashtriage.anonymize import Anonymizer, main, trim_lists
from crashtriage.model import CrashReport
from crashtriage.parser import parse_bytes

INCIDENT = "4C0FFEE0-1234-4ABC-9DEF-0123456789AB"
SYSTEM_PATH_WITH_DIGITS = "/System/Library/Extensions/AGXMetalG15G_C0.bundle/Contents/MacOS/AGXMetalG15G_C0"
LONG_SYMBOL = "_ZN7example6Parser12parse_recordERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE"

CANARIES = [
    "alice",
    "Alice Example",
    "alices-macbook",
    INCIDENT,
    INCIDENT.lower(),
    "a1b2c3d4-0000-4000-8000-00000000beef",
    "DEADBEEF-0000-4000-8000-0000000000AA",
    "02:00:5e:aa:bb:cc",
    "02-00-5E-10-AB-CD",
    "alice@example.com",
    "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl",
    "Secret Project",
    "SERIAL0TEST1",
    "AB12CD34EF",
    "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
]


def _canary_report() -> bytes:
    header = {
        "app_name": "demo",
        "name": "demo",
        "bug_type": "309",
        "incident_id": INCIDENT,
        "slice_uuid": "a1b2c3d4-0000-4000-8000-00000000beef",
        "timestamp": "2026-10-26 18:25:55.00 -0400",
    }
    body = {
        "procName": "demo",
        "procPath": "/Users/alice/Secret Project/build/demo",
        "incident": INCIDENT.lower(),
        "crashReporterKey": "DEADBEEF-0000-4000-8000-0000000000AA",
        "userID": 501,
        "codeSigningTeamID": "AB12CD34EF",
        "logWritingSignature": "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12",
        "hardwareSerialNumber": "SERIAL0TEST1",
        "trialInfo": {"rollouts": [{"rolloutId": "r1"}]},
        "captureTime": "2026-10-26 18:25:39.1157 -0400",
        "exception": {"type": "EXC_CRASH", "signal": "SIGABRT"},
        "asi": {"libsystem_c.dylib": ["opened /Users/alice/notes.txt for alice@example.com on alices-macbook.local"]},
        "note": "token ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8 and AKIAABCDEFGHIJKLMNOP and "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlLXZhbHVl, owner Alice Example",
        "vmregioninfo": "__TEXT  104c34000-104c58000 [ 144K] r-x/r-x SM=COW  /Users/alice/Secret Project/demo\n"
        "__TEXT  1-2 [ 1K] r-x/r-x SM=COW  /usr/lib/dyld",
        "faultingThread": 0,
        "threads": [
            {
                "id": 1,
                "triggered": True,
                "queue": "com.apple.audio.device.02-00-5E-10-AB-CD:output.event",
                "name": "worker for 02:00:5e:aa:bb:cc",
                "frames": [
                    {"imageIndex": 0, "imageOffset": 100, "symbol": LONG_SYMBOL, "symbolLocation": 4},
                    {"imageIndex": 1, "imageOffset": 200, "symbol": "abort", "symbolLocation": 8},
                    {"imageIndex": 2, "imageOffset": 300},
                ],
            }
        ],
        "usedImages": [
            {"source": "P", "name": "demo", "path": "/Users/alice/Secret Project/build/demo", "uuid": "a1b2c3d4-0000-4000-8000-00000000beef"},
            {"source": "P", "name": "libsystem_c.dylib", "path": "/usr/lib/system/libsystem_c.dylib", "uuid": "11111111-2222-3333-4444-555555555555"},
            {"source": "P", "name": "AGXMetalG15G_C0", "path": SYSTEM_PATH_WITH_DIGITS},
        ],
    }
    return (json.dumps(header, separators=(",", ":")) + "\n" + json.dumps(body, indent=2)).encode()


def _anonymizer(salt: bytes = b"test-salt") -> Anonymizer:
    return Anonymizer(salt, usernames=["alice"], hostnames=["alices-macbook"], real_names=["Alice Example"])


@pytest.fixture
def anonymized() -> bytes:
    return _anonymizer().anonymize_bytes(_canary_report())


def test_planted_canaries_are_gone(anonymized: bytes) -> None:
    text = anonymized.decode()
    lower = text.lower()
    for canary in CANARIES:
        assert canary.lower() not in lower, canary
    assert "/Users/" not in text


def test_report_still_parses_with_the_same_meaning(anonymized: bytes) -> None:
    before = parse_bytes(_canary_report())
    after = parse_bytes(anonymized)
    assert isinstance(after, CrashReport)
    for field in ("process_name", "timestamp", "exception_type", "signal", "faulting_thread", "bug_type"):
        assert getattr(after, field) == getattr(before, field), field
    assert [(f.image_name, f.image_offset, f.symbol) for f in after.faulting.frames] == [
        (f.image_name, f.image_offset, f.symbol) for f in before.faulting.frames
    ]
    # header incident_id and body incident were the same UUID in two cases; they
    # must still match, or the parser would warn.
    assert after.warnings == ()
    assert after.incident_id.startswith("00000000-0000-0000-")


def test_system_paths_and_symbols_are_kept(anonymized: bytes) -> None:
    after = parse_bytes(anonymized)
    paths = [image.path for image in after.images]
    assert paths == ["/REDACTED/demo", "/usr/lib/system/libsystem_c.dylib", SYSTEM_PATH_WITH_DIGITS]
    assert after.process_path == "/REDACTED/demo"
    assert after.faulting.frames[0].symbol == LONG_SYMBOL


def test_specific_replacements(anonymized: bytes) -> None:
    body = json.loads(anonymized.decode().split("\n", 1)[1])
    assert body["crashReporterKey"] == "REDACTED"
    assert body["userID"] == -1
    assert body["codeSigningTeamID"] == "REDACTED"
    assert body["hardwareSerialNumber"] == "REDACTED"
    assert body["trialInfo"] == {}
    assert body["threads"][0]["queue"] == "com.apple.audio.device.XX-XX-XX-XX-XX-XX:output.event"
    assert body["threads"][0]["name"] == "worker for XX:XX:XX:XX:XX:XX"
    assert body["asi"]["libsystem_c.dylib"] == ["opened /REDACTED/notes.txt for user@example.invalid on HOST.local"]
    assert body["vmregioninfo"].endswith("/usr/lib/dyld")
    assert "r-x/r-x" in body["vmregioninfo"]


def test_uuid_mapping_is_keyed_consistent_and_case_preserving() -> None:
    a = _anonymizer(b"one")
    fake = a.fake_uuid(INCIDENT)
    assert fake == a.fake_uuid(INCIDENT)
    assert fake.startswith("00000000-0000-0000-") and len(fake) == 36
    assert fake == fake.upper()
    assert a.fake_uuid(INCIDENT.lower()) == fake.lower()
    assert fake != _anonymizer(b"two").fake_uuid(INCIDENT)
    assert a.fake_uuid(INCIDENT) != a.fake_uuid("11111111-2222-3333-4444-555555555555")


def test_output_is_deterministic_for_a_salt_and_idempotent(anonymized: bytes) -> None:
    assert _anonymizer().anonymize_bytes(_canary_report()) == anonymized
    assert _anonymizer().anonymize_bytes(anonymized) == anonymized


def test_plain_text_reports_are_scrubbed_too() -> None:
    text = (
        "Incident Identifier: 4C0FFEE0-1234-4ABC-9DEF-0123456789AB\n"
        "Path:             /Users/alice/Applications/Tool.app/Contents/MacOS/Tool\n"
        "Team ID:          AB12CD34EF\n"
        "Serial Number:    SERIAL0TEST1\n"
        "Host:             alices-macbook\n"
    ).encode()
    out = _anonymizer().anonymize_bytes(text).decode()
    for canary in ("4C0FFEE0", "alice", "AB12CD34EF", "SERIAL0TEST1"):
        assert canary not in out
    assert "Path:             /REDACTED/Tool\n" in out
    assert "Team ID:          REDACTED\n" in out


def test_trim_lists_keeps_the_first_items() -> None:
    raw = b'{"bug_type":"298"}\n{"processes": [1, 2, 3, 4], "nested": {"x": [[1, 2, 3], 4, 5]}}'
    body = json.loads(trim_lists(raw, 2).decode().split("\n", 1)[1])
    assert body == {"processes": [1, 2], "nested": {"x": [[1, 2], 4]}}


def test_cli_reads_source_and_never_overwrites(tmp_path) -> None:
    src = tmp_path / "src.ips"
    src.write_bytes(_canary_report())
    before = (src.read_bytes(), os.stat(src).st_mtime_ns)
    dst = tmp_path / "out.ips"
    assert main([str(src), str(dst), "--salt", "00ff"]) == 0
    assert (src.read_bytes(), os.stat(src).st_mtime_ns) == before
    out = dst.read_text()
    assert "/Users/alice" not in out and "Secret Project" not in out and INCIDENT not in out
    with pytest.raises(SystemExit):
        main([str(src), str(dst)])  # dst exists
    with pytest.raises(SystemExit):
        main([str(src), str(src)])  # would overwrite the source


def test_cli_truncate_makes_a_malformed_copy(tmp_path) -> None:
    dst = tmp_path / "cut.ips"
    main([str(fixture_path("crasher-segv.ips")), str(dst), "--truncate-bytes", "1000"])
    assert len(dst.read_bytes()) == 1000
    assert parse_bytes(dst.read_bytes()).kind == "malformed"


def test_anonymizing_a_real_fixture_again_changes_nothing_that_matters() -> None:
    raw = fixture_bytes("dotnet-abort-a.ips")
    again = Anonymizer(b"x", usernames=[], hostnames=[], real_names=[]).anonymize_bytes(raw)
    before, after = parse_bytes(raw), parse_bytes(again)
    assert before.incident_id == after.incident_id
    assert [(f.image_name, f.image_offset, f.symbol) for f in before.faulting.frames] == [
        (f.image_name, f.image_offset, f.symbol) for f in after.faulting.frames
    ]
