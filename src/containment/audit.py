"""Append-only JSONL audit log (best-effort hash chain; not WORM)."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from collections.abc import Mapping
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from containment.actions import PolicyDecision, ProposedAction, TraceEvent

_GENESIS_HASH = "0" * 64


class AuditLog:
    """Thread-safe append-only JSONL writer/reader for TraceEvent records.

    Each line may include ``prev_hash`` / ``event_hash`` (SHA-256 over the
    previous hash + canonical event body). This is tamper-*evidence* only —
    a filesystem writer can still truncate or replace the file (see
    ``docs/THREAT_MODEL.md``). Not WORM.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
        self._lock = threading.Lock()
        self._last_hash = self._load_tip_hash()

    def _load_tip_hash(self) -> str:
        text = self.path.read_text(encoding="utf-8")
        last = _GENESIS_HASH
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue
            last = str(raw.get("event_hash") or last)
        return last

    def append_event(self, event: TraceEvent) -> TraceEvent:
        body = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "kind": event.kind,
            "task_id": event.task_id,
            "detail": dict(event.detail),
        }
        with self._lock:
            prev = self._last_hash
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
            event_hash = hashlib.sha256(
                (prev + canonical).encode("utf-8")
            ).hexdigest()
            record = {**body, "prev_hash": prev, "event_hash": event_hash}
            line = json.dumps(record, sort_keys=True, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            self._last_hash = event_hash
        return event

    def append_decision(
        self,
        action: ProposedAction,
        decision: PolicyDecision,
        *,
        timestamp: str | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> TraceEvent:
        ts = timestamp or _utc_now_iso()
        detail: dict[str, Any] = {
            "tool": action.tool,
            "principal": action.principal,
            "plan_step": action.plan_step,
            "reason_code": action.reason_code,
            "arguments": dict(action.arguments),
            "input_labels": [asdict(label) for label in action.input_labels],
            "decision": {
                "effect": decision.effect,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "requires_mfa": decision.requires_mfa,
            },
        }
        if extra:
            detail["extra"] = dict(extra)
        event = TraceEvent(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            kind="policy_decision",
            task_id=action.task_id,
            detail=detail,
        )
        return self.append_event(event)

    def read_all(self) -> list[TraceEvent]:
        events: list[TraceEvent] = []
        with self._lock:
            text = self.path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            events.append(
                TraceEvent(
                    event_id=raw["event_id"],
                    timestamp=raw["timestamp"],
                    kind=raw["kind"],
                    task_id=raw["task_id"],
                    detail=raw.get("detail") or {},
                )
            )
        return events


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()
