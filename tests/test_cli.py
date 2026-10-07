"""CLI eval tests (step 13)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from containment.cli import main
from containment.eval_runner import run_eval

ROOT = Path(__file__).resolve().parents[1]


def test_run_eval_policy_on_vs_off_control() -> None:
    on, _ = run_eval(policy_enabled=True)
    off, _ = run_eval(policy_enabled=False)
    assert on.n_attack >= 1
    assert on.n_benign >= 1
    assert isinstance(on.asr, float)
    assert isinstance(on.fpr, float)
    assert isinstance(on.utility, float)
    # Control: disabling policy must raise ASR (security worsens).
    assert off.asr > on.asr
    assert off.asr == pytest.approx(1.0)
    assert on.asr < 1.0


def test_cli_eval_prints_metrics(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["eval", "--suite", "fixtures"])
    assert code == 0
    out = capsys.readouterr().out
    assert "ASR:" in out
    assert "FPR:" in out
    assert "utility:" in out
    assert "policy ON" in out


def test_cli_eval_json_and_no_policy(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["eval", "--suite", "fixtures", "--no-policy", "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["policy_enabled"] is False
    assert data["asr"] == 1.0
    assert "fpr" in data and "utility" in data


def test_module_and_console_script() -> None:
    import os

    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    mod = subprocess.run(
        [
            sys.executable,
            "-m",
            "containment.cli",
            "eval",
            "--suite",
            "fixtures",
            "--json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert mod.returncode == 0, mod.stderr
    data = json.loads(mod.stdout)
    assert data["n_attack"] >= 1
