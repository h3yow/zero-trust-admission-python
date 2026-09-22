"""策略与判定领域模型（仅类型定义）。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Subject:
    users: frozenset[str] = frozenset()
    roles: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Resource:
    type: str = ""
    patterns: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Action:
    methods: frozenset[str] = frozenset()


@dataclass(frozen=True)
class RateLimit:
    max_requests: int = 0
    window_seconds: float = 0.0


@dataclass(frozen=True)
class ConcurrencyLimit:
    max_in_flight: int = 0


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    effect: Effect
    subject: Subject
    resource: Resource
    action: Action
    rate_limit: RateLimit | None = None
    concurrency_limit: ConcurrencyLimit | None = None


@dataclass(frozen=True)
class Policy:
    api_version: str
    kind: str
    name: str
    version: int
    rules: tuple[Rule, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Identity:
    user: str = ""
    roles: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Request:
    identity: Identity
    resource_type: str
    resource: str
    action: str
    request_id: str = ""


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: str
    reason_code: str
    reason: str
