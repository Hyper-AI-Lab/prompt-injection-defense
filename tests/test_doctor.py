"""containment doctor: behavior via run_doctor and the CLI (hermetic, literal values)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from containment import __version__
from containment.cli import main
from containment.doctor import DoctorConfig, config_from_env, format_report, run_doctor

REQUIRED_HOST_IDS = [
    "install.package",
    "install.policy",
    "host.isolation",
    "host.secret_provider",
    "host.egress",
    "host.audit_shipper",
    "host.secrets",
    "host.compose",
]


@pytest.fixture(autouse=True)
def _no_egress_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONTAINMENT_EGRESS_PROXY", raising=False)
    monkeypatch.delenv("CONTAINMENT_EGRESS_PINNED", raising=False)


@pytest.fixture
def secrets_dir(tmp_path: Path) -> Path:
    d = tmp_path / "secrets"
    d.mkdir()
    (d / "capability").write_text("c" * 64 + "\n")
    (d / "intent").write_text("i" * 64 + "\n")
    return d


def _ready(tmp_path: Path, secrets_dir: Path, **over: object) -> DoctorConfig:
    values: dict[str, object] = {
        "secrets_dir": secrets_dir,
        "isolation_declared": True,
        "egress_pinned": True,
        "audit_ship_destination": tmp_path / "ship" / "audit-shipped.jsonl",
    }
    values.update(over)
    return DoctorConfig(**values)  # type: ignore[arg-type]


def _status(report, check_id: str) -> tuple[str, str]:
    check = next(c for c in report.checks if c.id == check_id)
    return check.status, check.detail


def _required_ids(report) -> list[str]:
    return [c.id for c in report.checks if c.required]


def test_install_only_passes_on_this_checkout() -> None:
    report = run_doctor(DoctorConfig(install_only=True))
    assert report.ok is True
    assert report.exit_code == 0
    assert report.scope == "install"
    assert _required_ids(report) == ["install.package", "install.policy"]
    assert _status(report, "install.policy")[1].endswith("default_deny.yaml: 4 rules")
    assert report.checklist_failures == ()
    assert report.residuals == ()
    assert report.as_dict()["residuals"] == []


def test_extra_hint_never_points_at_pypi() -> None:
    from containment.doctor import extra_install_hint

    assert extra_install_hint("crypto") == (
        'pip install "containment[crypto] @ '
        f'git+https://github.com/Hyper-AI-Lab/prompt-injection-defense.git@v{__version__}"'
    )


def test_unconfigured_host_reports_every_checklist_code() -> None:
    report = run_doctor(DoctorConfig())
    assert report.ok is False
    assert report.exit_code == 1
    assert _required_ids(report) == REQUIRED_HOST_IDS
    assert len(report.residuals) == 6
    assert report.checklist_failures == (
        "isolation_not_declared",
        "secret_provider_missing",
        "egress_not_configured",
        "audit_shipper_missing",
    )
    assert _status(report, "host.isolation") == ("fail", "isolation_not_declared")
    assert _status(report, "host.secrets") == ("skip", "no secret provider")
    assert _status(report, "host.compose") == (
        "skip",
        "not attempted until the checks above pass",
    )


def test_fully_declared_host_composes(tmp_path: Path, secrets_dir: Path) -> None:
    report = run_doctor(_ready(tmp_path, secrets_dir))
    assert report.ok is True
    assert [c.status for c in report.checks if c.required] == ["pass"] * 8
    assert _status(report, "host.egress") == ("pass", "pinned (resolve-pin client)")
    assert _status(report, "host.secrets") == (
        "pass",
        "loaded: capability, intent (values not shown)",
    )
    assert _status(report, "host.compose") == (
        "pass",
        "build_enterprise_host OK (HostGate on, signed intents, egress=pinned)",
    )
    # compose must not create the ship destination (hermetic, no side effects)
    assert not (tmp_path / "ship").exists()


def test_missing_intent_secret_fails_and_skips_compose(tmp_path: Path, secrets_dir: Path) -> None:
    (secrets_dir / "intent").unlink()
    report = run_doctor(_ready(tmp_path, secrets_dir))
    assert report.exit_code == 1
    assert _status(report, "host.secrets") == ("fail", "missing secret file: intent")
    assert _status(report, "host.compose")[0] == "skip"


def test_secret_values_never_appear_in_output(tmp_path: Path, secrets_dir: Path) -> None:
    report = run_doctor(_ready(tmp_path, secrets_dir))
    text = format_report(report) + json.dumps(report.as_dict())
    assert "c" * 64 not in text
    assert "i" * 64 not in text


def test_secrets_dir_must_exist(tmp_path: Path) -> None:
    report = run_doctor(_ready(tmp_path, tmp_path / "nope"))
    assert _status(report, "host.secret_provider") == (
        "fail",
        f"file:{tmp_path / 'nope'}: not a directory",
    )


def test_malformed_proxy_url_fails(tmp_path: Path, secrets_dir: Path) -> None:
    cfg = _ready(tmp_path, secrets_dir, egress_pinned=False, egress_proxy_url="127.0.0.1:8899")
    report = run_doctor(cfg)
    assert _status(report, "host.egress") == ("fail", "proxy: malformed URL '127.0.0.1:8899'")
    assert report.exit_code == 1


def test_proxy_url_passes_and_composes(tmp_path: Path, secrets_dir: Path) -> None:
    cfg = _ready(
        tmp_path, secrets_dir, egress_pinned=False, egress_proxy_url="http://127.0.0.1:8899"
    )
    report = run_doctor(cfg)
    assert _status(report, "host.egress") == ("pass", "proxy http://127.0.0.1:8899")
    assert _status(report, "host.compose")[1].endswith("egress=proxy)")
    assert report.ok is True


def test_unwritable_audit_destination_fails(tmp_path: Path, secrets_dir: Path) -> None:
    ro = tmp_path / "ro"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        report = run_doctor(_ready(tmp_path, secrets_dir, audit_ship_destination=ro / "a.jsonl"))
    finally:
        ro.chmod(0o700)
    status, detail = _status(report, "host.audit_shipper")
    if status == "pass":  # running as root ignores directory modes
        pytest.skip("filesystem permissions not enforced for this user")
    assert (status, detail) == ("fail", f"{ro / 'a.jsonl'}: not writable")


def test_bad_policy_fails_install(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just a list\n")
    report = run_doctor(DoctorConfig(install_only=True, policy_path=bad))
    assert _status(report, "install.policy") == ("fail", f"{bad}: policy root must be a mapping")
    assert report.exit_code == 1


def test_env_egress_defaults() -> None:
    base = DoctorConfig()
    assert config_from_env(base, {"CONTAINMENT_EGRESS_PINNED": "1"}).egress_pinned is True
    assert (
        config_from_env(base, {"CONTAINMENT_EGRESS_PROXY": " http://p:1 "}).egress_proxy_url
        == "http://p:1"
    )
    assert config_from_env(base, {"CONTAINMENT_EGRESS_PINNED": "yes"}) == base
    explicit = DoctorConfig(egress_proxy_url="http://q:2")
    assert config_from_env(explicit, {"CONTAINMENT_EGRESS_PINNED": "1"}) == explicit


def test_config_rejects_conflicting_settings(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="only one of secrets_dir, secrets_env_prefix"):
        DoctorConfig(secrets_dir=tmp_path, secrets_env_prefix="X_")
    with pytest.raises(ValueError, match="only one of egress_proxy_url, egress_pinned"):
        DoctorConfig(egress_proxy_url="http://p:1", egress_pinned=True)


def test_env_secret_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DOCTOR_T_CAPABILITY", "x" * 40)
    monkeypatch.setenv("DOCTOR_T_INTENT", "y" * 40)
    cfg = DoctorConfig(
        secrets_env_prefix="DOCTOR_T_",
        isolation_declared=True,
        egress_pinned=True,
        audit_ship_destination=tmp_path / "s.jsonl",
    )
    report = run_doctor(cfg)
    assert _status(report, "host.secret_provider") == ("pass", "env:DOCTOR_T_*")
    assert report.ok is True


def test_cli_json_and_exit_codes(
    tmp_path: Path, secrets_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["doctor", "--install-only", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["scope"] == "install"
    assert payload["version"] == __version__

    assert main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert out.splitlines()[-1] == "NOT READY — 2/8 required checks passed"

    rc = main([
        "doctor",
        "--secrets-dir", str(secrets_dir),
        "--isolation-declared",
        "--egress-pinned",
        "--audit-ship", str(tmp_path / "ship.jsonl"),
    ])
    assert rc == 0
    assert capsys.readouterr().out.splitlines()[-1] == "OK — 8/8 required checks passed"


def test_cli_conflicting_flags_exit_2() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["doctor", "--egress-pinned", "--egress-proxy", "http://p:1"])
    assert exc.value.code == 2
