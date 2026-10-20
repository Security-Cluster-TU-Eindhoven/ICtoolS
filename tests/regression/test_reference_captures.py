"""Runs ICtoolS on the reference captures in fingerprints/<protocol>/ and compares the results with
tests/expected/<protocol>.json.

Every matcher runs on every capture, so the expected results also cover matches on other tools'
captures (overlaps). Set UPDATE_EXPECTED=1 to rewrite the expected results from the current run.
"""
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ICTOOLS_DIR

PROTOCOL = os.environ.get("REGRESSION_PROTOCOL", "ENIP")
ZEEK_SCRIPTS = shlex.split(os.environ.get("ZEEK_SCRIPTS", "icsnpp-modbus znpa-umas"))
UPDATE = os.environ.get("UPDATE_EXPECTED") == "1"
EXPECTED_FILE = Path(__file__).parent.parent / "expected" / f"{PROTOCOL}.json"
EXPECTED = json.loads(EXPECTED_FILE.read_text()) if EXPECTED_FILE.exists() else {}

FINGERPRINT_DIR = ICTOOLS_DIR / "fingerprints" / PROTOCOL
CAPTURE_DIRS = {
    d.name: d for d in sorted(FINGERPRINT_DIR.iterdir())
    if d.is_dir() and (any(d.glob("*.pcap")) or any(d.glob("*.pcapng")))
}

results = {}


def captures(directory: Path) -> list[Path]:
    return sorted(list(directory.glob("*.pcap")) + list(directory.glob("*.pcapng")))


def prepare_input(name: str, work_dir: Path) -> Path:
    """Returns a directory ICtoolS can read: the pcaps for ENIP, Zeek logs for Modbus."""
    input_dir = work_dir / "input"
    for capture in captures(CAPTURE_DIRS[name]):
        if PROTOCOL == "Modbus":
            log_dir = input_dir / capture.stem
            log_dir.mkdir(parents=True)
            subprocess.run(["zeek", "-C", "-r", str(capture), *ZEEK_SCRIPTS], cwd=log_dir, check=True)
        else:
            input_dir.mkdir(exist_ok=True)
            shutil.copy(capture, input_dir)
    return input_dir


def run_ictools(input_dir: Path, output: Path) -> list[str]:
    """Runs ICtoolS and summarizes each interaction as '<coverage> | <matched tools>'."""
    subprocess.run([sys.executable, "main.py", "--input_dir", str(input_dir), "--output", str(output)],
                   cwd=ICTOOLS_DIR, check=True)
    interactions = json.loads(output.read_text())
    return sorted({
        f"{i['coverage']} | {', '.join(sorted({t for p in i['packets'] for t in p['tool_matches']}))}"
        for i in interactions
    })


@pytest.mark.parametrize("name", sorted(set(CAPTURE_DIRS) | set(EXPECTED)))
def test_reference_capture(name, tmp_path):
    if name not in CAPTURE_DIRS:
        pytest.fail(f"{name} is in {EXPECTED_FILE.name}, but fingerprints/{PROTOCOL}/{name} has no capture")

    actual = run_ictools(prepare_input(name, tmp_path), tmp_path / "result.json")
    results[name] = actual

    if UPDATE:
        return
    assert name in EXPECTED, f"New capture: add fingerprints/{PROTOCOL}/{name} to {EXPECTED_FILE.name} (run with UPDATE_EXPECTED=1)"
    assert actual == EXPECTED[name]


@pytest.mark.skipif(PROTOCOL != "Modbus", reason="Modbus only")
def test_redpoint_schneider_electric(tmp_path):
    """Real Schneider PLCs report 'Schneider Electric'; the reference capture only reports 'Schneider'."""
    input_dir = prepare_input("digitalBond_Redpoint-modicon_info", tmp_path)
    [log] = input_dir.rglob("modbus_read_device_identification.log")
    content = log.read_text()
    assert "VendorName\tSchneider\n" in content
    log.write_text(content.replace("VendorName\tSchneider\n", "VendorName\tSchneider Electric\n"))

    assert run_ictools(input_dir, tmp_path / "result.json") == [
        "Single Tool Match; Complete Identification | Digital Bond - Redpoint - Modicon"]


def teardown_module():
    if UPDATE and results:
        EXPECTED_FILE.parent.mkdir(parents=True, exist_ok=True)
        EXPECTED_FILE.write_text(json.dumps(dict(sorted({**EXPECTED, **results}.items())), indent=2) + "\n")
