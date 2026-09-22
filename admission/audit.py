"""准入判定审计记录：事件模型与可插拔后端。

契约：
- 每个被处理的请求都先写 decision 审计，再写 completion 审计；
- 后端不可用时 record 抛 AuditUnavailableError，由引擎按明确策略处理
  （默认 fail-closed：拒绝请求，绝不“已放行却无记录”）；
- 事件是不可变值对象，写入后不可篡改。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum


class AuditStage(str, Enum):
    DECISION = "decision"
    COMPLETION = "completion"


class Outcome(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    DOWNSTREAM_ERROR = "downstream_error"


@dataclass(frozen=True)
class AuditEvent:
    request_id: str
    stage: AuditStage
    outcome: Outcome
    reason_code: str
    reason: str
    rule_id: str
    user: str
    resource_type: str
    resource: str
    action: str
    policy_version: int
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "request_id": self.request_id,
            "stage": self.stage.value,
            "outcome": self.outcome.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "user": self.user,
            "resource_type": self.resource_type,
            "resource": self.resource,
            "action": self.action,
            "policy_version": self.policy_version,
            "detail": self.detail,
        }


class Auditor:
    """审计后端接口。record 失败必须抛 AuditUnavailableError。"""

    def record(self, event: AuditEvent) -> None:
        raise NotImplementedError


class InMemoryAuditor(Auditor):
    """线程安全的本地内存审计后端；可被切换为故障模式以模拟审计不可用。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[AuditEvent] = []
        self._failed = False

    def set_failed(self, failed: bool) -> None:
        with self._lock:
            self._failed = failed

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            if self._failed:
                from admission.errors import AuditUnavailableError

                raise AuditUnavailableError(
                    f"审计后端不可用，事件未落盘: request_id={event.request_id} stage={event.stage.value}"
                )
            self._events.append(event)

    def events(self) -> list[AuditEvent]:
        with self._lock:
            return list(self._events)
