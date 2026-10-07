"""Stage-0 rules tests (step 6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.detectors.rules import Finding, RulesDetector, Stage0Result, scan_stage0

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = ROOT / "fixtures" / "attacks"
BENIGN = ROOT / "fixtures" / "benign"


def test_nfkc_normalization_finding() -> None:
    # Fullwidth ASCII normalizes under NFKC.
    text = "ｉｇｎｏｒｅ instructions"
    result = scan_stage0(text)
    assert result.normalized_text == "ignore instructions"
    kinds = {f.kind for f in result.findings}
    assert "unicode_normalization" in kinds
    assert result.original_sha256


def test_invisible_zwsp_fixture() -> None:
    text = (ATTACKS / "hidden_zwsp.txt").read_text(encoding="utf-8")
    result = scan_stage0(text)
    invisible = [f for f in result.findings if f.kind == "invisible_char"]
    assert len(invisible) >= 3
    assert all(f.offset is not None for f in invisible)
    assert result.risk_score > 0.0


def test_invisible_rlo_fixture() -> None:
    text = (ATTACKS / "hidden_rlo.txt").read_text(encoding="utf-8")
    result = scan_stage0(text)
    assert any(f.kind == "invisible_char" for f in result.findings)
    assert any("U+202E" in f.message for f in result.findings)


def test_base64_marker_fixture() -> None:
    text = (ATTACKS / "base64_marker.txt").read_text(encoding="utf-8")
    result = scan_stage0(text)
    blobs = [f for f in result.findings if f.kind == "base64_blob"]
    assert len(blobs) >= 1
    assert blobs[0].offset is not None
    assert result.risk_score >= 0.45


def test_benign_plain_low_risk() -> None:
    text = (BENIGN / "plain_ascii.txt").read_text(encoding="utf-8")
    result = scan_stage0(text)
    assert result.findings == ()
    assert result.risk_score == 0.0
    assert result.normalized_text == text
    assert not result.exceeded_size_limit


def test_size_limit() -> None:
    text = "a" * 100
    result = scan_stage0(text, max_bytes=50)
    assert result.exceeded_size_limit is True
    assert any(f.kind == "size_limit" for f in result.findings)
    assert result.risk_score == 1.0


def test_control_char_null() -> None:
    text = "hello\x00world"
    result = scan_stage0(text)
    assert any(f.kind == "control_char" for f in result.findings)


def test_rules_detector_adapter() -> None:
    det = RulesDetector(max_bytes=10_000)
    result = det.scan("safe text")
    assert isinstance(result, Stage0Result)
    assert result.risk_score == 0.0


def test_finding_rejects_empty_kind() -> None:
    with pytest.raises(ValueError):
        Finding(kind="", message="x")
