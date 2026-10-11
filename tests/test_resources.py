"""containment.resources resolves shipped data in a checkout and in a built wheel."""

from __future__ import annotations

from pathlib import Path

from containment import resources
from containment.eval_runner import default_fixtures_root
from containment.eval_runner import default_policy_path as eval_policy_path
from containment.reference_host import default_policy_path as ref_policy_path

REPO = Path(__file__).resolve().parents[1]


def test_checkout_paths_resolve_to_repo_root() -> None:
    assert resources.default_policy_path() == REPO / "policies" / "default_deny.yaml"
    assert resources.default_fixtures_root() == REPO / "fixtures"
    assert eval_policy_path() == REPO / "policies" / "default_deny.yaml"
    assert ref_policy_path() == REPO / "policies" / "default_deny.yaml"
    assert default_fixtures_root() == REPO / "fixtures"


def test_packaged_data_wins_when_present(tmp_path: Path, monkeypatch) -> None:
    packaged = tmp_path / "_data"
    (packaged / "policies").mkdir(parents=True)
    (packaged / "policies" / "default_deny.yaml").write_text("rules: []\n")
    monkeypatch.setattr(resources, "_PACKAGED", packaged)
    assert resources.default_policy_path() == packaged / "policies" / "default_deny.yaml"
    # fixtures/ not packaged in this fake → checkout fallback
    assert resources.default_fixtures_root() == REPO / "fixtures"


def test_wheel_config_ships_policies_and_fixtures() -> None:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    assert '"policies" = "containment/_data/policies"' in text
    assert '"fixtures" = "containment/_data/fixtures"' in text
