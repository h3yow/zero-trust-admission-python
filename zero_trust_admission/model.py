"""领域模型：身份、资源、动作、策略文档与判定结果的类型定义。"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
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


class RateLimitMode:
    """限流策略的叠加模式。

    - ``MOST_SPECIFIC``（默认）：一个请求只受命中策略中"最具体的一条"
      约束，行为与分层能力上线前完全一致（老策略兼容路径）。
    - ``LAYERED``：所有命中的策略各自成为一层配额，请求必须同时通过
      每一层；任一层拒绝即整体拒绝。
    """

    MOST_SPECIFIC = "most_specific"
    LAYERED = "layered"

    VALID = (MOST_SPECIFIC, LAYERED)


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
    rate_limit_mode: str = RateLimitMode.MOST_SPECIFIC


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """命中规则的可解释信息。"""

    rule_name: str
    effect: Effect
    priority: int


@dataclass(frozen=True, slots=True)
class RateLayerResult:
    """单层配额的检查结果（可解释、顺序固定）。

    每一层对应一条命中的 :class:`RateLimitPolicy`；``order`` 为该层在
    本次判定中的固定序号（从 0 开始），阈值与用量字段在该层不设对应
    约束时为 ``None``。
    """

    order: int
    policy_name: str
    allowed: bool
    denied_at: str | None = None
    rate_count: int | None = None
    rate_threshold: int | None = None
    concurrency_active: int | None = None
    concurrency_limit: int | None = None


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    """准入 + 限流的综合判定结果。

    ``rate_limit`` 沿用单策略（最具体一条）语义：老模式下即命中的那条
    策略；分层模式拒绝时指向第一个拦下请求的层，便于老消费方解释。
    ``rate_layers`` 仅在分层模式下填充，按固定检查顺序排列。
    """

    decision: Decision
    reason: DenyReason | None
    request_summary: dict[str, Any]
    matched_rule: MatchedRule | None = None
    rate_limit: RateLimitPolicy | None = None
    detail: str = ""
    rate_layers: tuple[RateLayerResult, ...] = ()
    # 分层模式下各层策略本体的快照，仅供并发槽释放时精确定位信号量；
    # 不参与对外判定展示，to_dict 时剔除
    layer_policies: tuple[RateLimitPolicy, ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("layer_policies", None)
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
    # 分层模式下各配额层的判定明细（含拦截层的阈值与当时用量）；
    # 老模式恒为空，不进入对外 JSONL 序列化
    rate_layers: tuple[RateLayerResult, ...] = ()
