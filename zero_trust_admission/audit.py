"""审计记录落地。

- 每条记录以 JSON Lines 形式追加写入，写入后立即 flush + fsync，
  保证"已放行即有记录"且写入顺序与判定顺序一致。
- 任何 sink 失败统一抛出 :class:`AuditUnavailableError`，由准入层根据
  显式配置的失败模式（fail_closed / fail_open）处理，绝不静默吞掉。
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import threading
from collections import deque
from typing import Any

from .model import AuditRecord, Decision, DenyReason


class AuditFailureMode:
    """审计不可用时的处理策略。"""

    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"

    VALID = (FAIL_CLOSED, FAIL_OPEN)


class AuditUnavailableError(RuntimeError):
    """审计写入失败。"""

    code = "audit_unavailable"


def _record_to_dict(record: AuditRecord) -> dict[str, Any]:
    data = dataclasses.asdict(record)
    data["decision"] = record.decision.value
    data["reason"] = record.reason.value if record.reason is not None else None
    if record.rate_layers:
        # 分层模式：保留各配额层明细（含拦截层阈值与当时用量）
        data["rate_layers"] = [
            dataclasses.asdict(layer) for layer in record.rate_layers
        ]
    else:
        # 老策略兼容路径：输出结构与分层能力上线前完全一致
        data.pop("rate_layers", None)
    return data


class AuditSink:
    """审计 sink 接口。"""

    def write(self, record: AuditRecord) -> None:
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover - 接口默认无操作
        pass


class JsonlAuditSink(AuditSink):
    """JSON Lines 文件 sink；每条记录 fsync，写入失败抛出审计不可用。"""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        try:
            os.makedirs(parent, exist_ok=True)
            # sink 生命周期内持续追加写入，文件句柄刻意保持长开并在 close() 关闭
            self._fh = open(path, "a", encoding="utf-8")  # noqa: SIM115
        except OSError as exc:
            raise AuditUnavailableError(
                f"无法打开审计文件 {path!r}: {exc}"
            ) from exc

    def write(self, record: AuditRecord) -> None:
        line = json.dumps(_record_to_dict(record), ensure_ascii=False, sort_keys=True)
        try:
            with self._lock:
                self._fh.write(line + "\n")
                self._fh.flush()
                os.fsync(self._fh.fileno())
        except OSError as exc:
            raise AuditUnavailableError(
                f"写入审计文件失败 {self.path!r}: {exc}"
            ) from exc

    def close(self) -> None:
        with self._lock, contextlib.suppress(OSError):
            self._fh.close()


class InMemoryAuditSink(AuditSink):
    """内存 sink，用于测试与本地验证。"""

    def __init__(self) -> None:
        self._records: deque[AuditRecord] = deque()
        self._lock = threading.Lock()

    def write(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)

    @property
    def records(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)

    def decisions(self) -> list[tuple[str, Decision, DenyReason | None]]:
        with self._lock:
            return [(r.phase, r.decision, r.reason) for r in self._records]

    def close(self) -> None:
        pass


class FailingAuditSink(AuditSink):
    """始终写入失败的 sink，用于确定性模拟"审计不可用"。"""

    def __init__(self, message: str = "audit backend down") -> None:
        self.message = message
        self.attempts = 0

    def write(self, record: AuditRecord) -> None:
        self.attempts += 1
        raise AuditUnavailableError(self.message)

    def close(self) -> None:
        pass


__all__ = [
    "AuditFailureMode",
    "AuditSink",
    "AuditUnavailableError",
    "FailingAuditSink",
    "InMemoryAuditSink",
    "JsonlAuditSink",
]
