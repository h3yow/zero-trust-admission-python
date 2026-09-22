"""策略仓库：保存当前生效策略，支持稳定的整体替换与版本递增。

生效语义：解析、版本检查、冲突检测全部通过后才原子替换当前策略；
任何一步失败，旧策略保持不变并继续生效（不会出现半成品策略）。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from admission.errors import PolicyNotFoundError
from admission.model import Policy
from admission.parser import check_conflict, check_version_sequence, parse_policy


@dataclass
class PolicyStore:
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _policy: Policy | None = None

    def load_dict(
        self, raw: object, *, expected_current_version: int | None = None
    ) -> Policy:
        """解析并校验策略，通过后原子生效。

        expected_current_version 提供乐观并发控制：更新时若当前版本不匹配则
        以 POLICY_VERSION_INCOMPATIBLE 拒绝，保证多客户端更新可复现。
        """
        # 先在锁外完成重解析（纯函数），缩短临界区
        candidate = parse_policy(raw)
        with self._lock:
            current = self._policy
            if expected_current_version is not None and (
                current is None or current.version != expected_current_version
            ):
                from admission.errors import PolicyVersionError

                raise PolicyVersionError(
                    f"乐观版本检查失败: 期望当前版本 {expected_current_version}，"
                    f"实际 {'无策略' if current is None else current.version}"
                )
            check_version_sequence(candidate, current)
            check_conflict(candidate, current)
            self._policy = candidate  # 原子发布
            return candidate

    def get(self) -> Policy | None:
        with self._lock:
            return self._policy

    def require(self) -> Policy:
        policy = self.get()
        if policy is None:
            raise PolicyNotFoundError("尚无生效策略，拒绝判定（fail-closed）")
        return policy
