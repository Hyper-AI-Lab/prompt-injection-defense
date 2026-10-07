"""Reference host demo: enterprise compose + BrokeredRegistry end-to-end."""

from containment.reference_host.host import (
    APPROVED_HOST,
    APPROVED_RECIPIENT,
    PRINCIPAL,
    STEP_EMAIL,
    STEP_FETCH,
    TASK_ID,
    TENANT,
    ReferenceHost,
    ReferenceHostConfig,
    build_reference_host,
    default_policy_path,
    fixture_dir,
    load_fixture,
)
from containment.reference_host.scenarios import (
    ScenarioResult,
    run_all,
    run_attack,
    run_benign,
    run_human,
)

__all__ = [
    "APPROVED_HOST",
    "APPROVED_RECIPIENT",
    "PRINCIPAL",
    "STEP_EMAIL",
    "STEP_FETCH",
    "TASK_ID",
    "TENANT",
    "ReferenceHost",
    "ReferenceHostConfig",
    "ScenarioResult",
    "build_reference_host",
    "default_policy_path",
    "fixture_dir",
    "load_fixture",
    "run_all",
    "run_attack",
    "run_benign",
    "run_human",
]
