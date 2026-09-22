"""领域模型：身份、资源、动作、策略文档与判定结果的类型定义。"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Action(str, Enum):
    """受准入控制的动作。"""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"


class Effect(str, Enum):
    """单条规则命中后的效果。"""

    ALLOW = "allow"
    DENY = "deny"


class Decision(str, Enum):
    """最终判定结果。"""

    ALLOW = "allow"
    DENY = "deny"


class DenyReason(str, Enum):
    """可区分的拒绝原因。"""

    NO_MATCHING_POLICY = "no_matching_policy"
    EXPLICIT_DENY = "explicit_deny"
    RATE_LIMITED = "rate_limited"
    CONCURRENCY_LIMITED = "concurrency_limited"
    POLICY_INVALID = "policy_invalid"
    AUDIT_UNAVAILABLE = "audit_unavailable"


@dataclass(frozen=True, slots=True)
class Principal:
    """请求发起方身份。"""

    identity: str
    groups: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AccessRequest:
    """一次准入评估请求。"""

    principal: Principal
    resource: str
    action: Action


@dataclass(frozen=True, slots=True)
class Rule:
    """一条声明式准入规则。

    身份/资源支持精确匹配与 ``*`` 通配；动作支持具体动作或 ``"*"``。
    """

    name: str
    effect: Effect
    identities: tuple[str, ...]
    groups: tuple[str, ...]
    resources: tuple[str, ...]
    actions: tuple[str, ...]
    priority: int = 0


@dataclass(frozen=True, slots=True)
class RateLimitPolicy:
    """按 (身份, 资源) 维度的限流/并发约束。"""

    name: str
    identities: tuple[str, ...]
    groups: tuple[str, ...]
    resources: tuple[str, ...]
    rate_limit: int | None = None
    rate_window_seconds: float | None = None
    concurrency: int | None = None


@dataclass(frozen=True, slots=True)
class PolicyDocument:
    """一份策略文档：版本、准入规则与限流规则。"""

    schema_version: str
    rules: tuple[Rule, ...] = ()
    rate_limits: tuple[RateLimitPolicy, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """命中规则的可解释信息。"""

    rule_name: str
    effect: Effect
    priority: int


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    """准入 + 限流的综合判定结果。"""

    decision: Decision
    reason: DenyReason | None
    request_summary: dict[str, Any]
    matched_rule: MatchedRule | None = None
    rate_limit: RateLimitPolicy | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """审计记录：与最终判定结果、拒绝原因、下游异常链路保持一致。"""

    audit_id: str
    timestamp: float
    phase: str
    decision: Decision
    reason: DenyReason | None
    request_summary: dict[str, Any]
    matched_rule_name: str | None
    rate_limit_name: str | None
    detail: str
    downstream_error: str | None = None
