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


class QuotaMode:
    """配额约束的生效模式。

    - ``single``（默认，老策略语义）：一个请求只命中一条最具体的限流策略；
    - ``layered``：所有命中的限流策略作为多个配额层**同时**生效，
      任一层不过即拒绝，全部通过才放行。
    """

    SINGLE = "single"
    LAYERED = "layered"

    VALID = (SINGLE, LAYERED)


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
    """一份策略文档：版本、准入规则与限流规则。

    ``quota_mode`` 缺省为 :attr:`QuotaMode.SINGLE`，保证不显式开启分层时
    行为与老策略完全一致。
    """

    schema_version: str
    rules: tuple[Rule, ...] = ()
    rate_limits: tuple[RateLimitPolicy, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    quota_mode: str = QuotaMode.SINGLE


@dataclass(frozen=True, slots=True)
class QuotaLayerResult:
    """单条配额层在一次判定中的可解释结果。

    - ``order``：该层在固定判定顺序中的序号（0 起，最具体的层最先判定）；
    - ``allowed``：True 放行；False 该层拦截；None 短路时尚未判定到该层；
    - ``used`` / ``threshold``：判定时该层窗口内用量与阈值；
    - ``in_flight`` / ``concurrency``：判定时在途并发数与并发上限；
    - ``scope``：该层计数归属的人类可读标识（身份 / 组 / 资源全域）。
    """

    order: int
    policy_name: str
    allowed: bool | None
    scope: str
    used: int | None = None
    threshold: int | None = None
    in_flight: int | None = None
    concurrency: int | None = None


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """命中规则的可解释信息。"""

    rule_name: str
    effect: Effect
    priority: int


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    """准入 + 限流的综合判定结果。

    ``rate_limit``/``detail`` 等字段在两种模式下保持稳定：老策略
    （single 模式）下 ``quota_layers`` 恒为空元组，对外载荷与历史一致；
    layered 模式下被拒时 ``rate_limit`` 指向第一个拦截层，``quota_layers``
    携带按固定顺序排列的各层用量、阈值与判定情况。
    """

    decision: Decision
    reason: DenyReason | None
    request_summary: dict[str, Any]
    matched_rule: MatchedRule | None = None
    rate_limit: RateLimitPolicy | None = None
    detail: str = ""
    quota_layers: tuple[QuotaLayerResult, ...] = ()

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
