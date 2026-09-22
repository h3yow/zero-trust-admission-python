"""声明式策略（JSON）解析、校验、版本检查与冲突检测。

策略文档格式见 docs/policy.md。校验失败一律抛出携带可区分原因码的
PolicyValidationError / PolicyVersionError / PolicyConflictError，
绝不静默忽略非法字段。
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from admission.errors import (
    PolicyConflictError,
    PolicyValidationError,
    PolicyVersionError,
)
from admission.model import (
    Action,
    ConcurrencyLimit,
    Effect,
    Policy,
    RateLimit,
    Resource,
    Rule,
    Subject,
)

SUPPORTED_API_VERSION = "zero-trust-admission/v1"
SUPPORTED_KIND = "AdmissionPolicy"


def _require_type(raw: Any, typ: type, path: str) -> Any:
    if not isinstance(raw, typ):
        raise PolicyValidationError(f"字段 {path} 类型非法：期望 {typ.__name__}")
    return raw


def _str_set(raw: Any, path: str, *, allow_empty: bool = True) -> frozenset[str]:
    if raw is None:
        return frozenset()
    _require_type(raw, list, path)
    result: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, str) or not item.strip():
            raise PolicyValidationError(f"字段 {path}[{i}] 必须是非空字符串")
        result.add(item.strip())
    if not result and not allow_empty:
        raise PolicyValidationError(f"字段 {path} 不允许为空")
    return frozenset(result)


def _parse_subject(raw: Any, path: str) -> Subject:
    raw = _require_type(raw, dict, path)
    unknown = set(raw) - {"users", "roles", "groups"}
    if unknown:
        raise PolicyValidationError(f"字段 {path} 含未知字段: {sorted(unknown)}")
    return Subject(
        users=_str_set(raw.get("users"), f"{path}.users"),
        roles=_str_set(raw.get("roles"), f"{path}.roles"),
        groups=_str_set(raw.get("groups"), f"{path}.groups"),
    )


def _parse_resource(raw: Any, path: str) -> Resource:
    raw = _require_type(raw, dict, path)
    unknown = set(raw) - {"type", "patterns"}
    if unknown:
        raise PolicyValidationError(f"字段 {path} 含未知字段: {sorted(unknown)}")
    rtype = raw.get("type")
    if not isinstance(rtype, str) or not rtype.strip():
        raise PolicyValidationError(f"字段 {path}.type 必须是非空字符串")
    return Resource(
        type=rtype.strip(), patterns=_str_set(raw.get("patterns"), f"{path}.patterns")
    )


def _parse_action(raw: Any, path: str) -> Action:
    raw = _require_type(raw, dict, path)
    unknown = set(raw) - {"methods"}
    if unknown:
        raise PolicyValidationError(f"字段 {path} 含未知字段: {sorted(unknown)}")
    methods = {m.upper() for m in _str_set(raw.get("methods"), f"{path}.methods")}
    return Action(methods=frozenset(methods))


def _parse_rate_limit(raw: Any, path: str) -> RateLimit | None:
    if raw is None:
        return None
    raw = _require_type(raw, dict, path)
    unknown = set(raw) - {"maxRequests", "windowSeconds"}
    if unknown:
        raise PolicyValidationError(f"字段 {path} 含未知字段: {sorted(unknown)}")
    max_requests = raw.get("maxRequests")
    window = raw.get("windowSeconds")
    if (
        not isinstance(max_requests, int)
        or isinstance(max_requests, bool)
        or max_requests <= 0
    ):
        raise PolicyValidationError(f"字段 {path}.maxRequests 必须是正整数")
    if not isinstance(window, (int, float)) or isinstance(window, bool) or window <= 0:
        raise PolicyValidationError(f"字段 {path}.windowSeconds 必须是正数")
    return RateLimit(max_requests=max_requests, window_seconds=float(window))


def _parse_concurrency_limit(raw: Any, path: str) -> ConcurrencyLimit | None:
    if raw is None:
        return None
    raw = _require_type(raw, dict, path)
    unknown = set(raw) - {"maxInFlight"}
    if unknown:
        raise PolicyValidationError(f"字段 {path} 含未知字段: {sorted(unknown)}")
    limit = raw.get("maxInFlight")
    if not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise PolicyValidationError(f"字段 {path}.maxInFlight 必须是正整数")
    return ConcurrencyLimit(max_in_flight=limit)


def _parse_rule(raw: Any, index: int) -> Rule:
    path = f"rules[{index}]"
    raw = _require_type(raw, dict, path)
    unknown = set(raw) - {
        "id",
        "description",
        "effect",
        "subject",
        "resource",
        "action",
        "rateLimit",
        "concurrencyLimit",
    }
    if unknown:
        raise PolicyValidationError(f"字段 {path} 含未知字段: {sorted(unknown)}")

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise PolicyValidationError(f"字段 {path}.id 必须是非空字符串")
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise PolicyValidationError(f"字段 {path}.description 必须是字符串")

    effect_raw = raw.get("effect")
    if effect_raw not in (Effect.ALLOW.value, Effect.DENY.value):
        raise PolicyValidationError(
            f"字段 {path}.effect 非法: {effect_raw!r}，只允许 allow / deny"
        )

    return Rule(
        id=rule_id.strip(),
        description=description,
        effect=Effect(effect_raw),
        subject=_parse_subject(raw.get("subject"), f"{path}.subject"),
        resource=_parse_resource(raw.get("resource"), f"{path}.resource"),
        action=_parse_action(raw.get("action"), f"{path}.action"),
        rate_limit=_parse_rate_limit(raw.get("rateLimit"), f"{path}.rateLimit"),
        concurrency_limit=_parse_concurrency_limit(
            raw.get("concurrencyLimit"), f"{path}.concurrencyLimit"
        ),
    )


def _version_compatible(raw: dict[str, Any]) -> str:
    api_version = raw.get("apiVersion")
    if api_version != SUPPORTED_API_VERSION:
        raise PolicyVersionError(
            f"apiVersion 不兼容: {api_version!r}，本服务仅支持 {SUPPORTED_API_VERSION}"
        )
    kind = raw.get("kind")
    if kind != SUPPORTED_KIND:
        raise PolicyVersionError(
            f"kind 不兼容: {kind!r}，本服务仅支持 {SUPPORTED_KIND}"
        )
    return api_version


def parse_policy(raw: object) -> Policy:
    """把 JSON 兼容的 dict 解析为 Policy。

    顺序：结构校验（POLICY_INVALID）→ 版本/类型兼容（POLICY_VERSION_INCOMPATIBLE）
    → 规则内部唯一性（POLICY_INVALID）。与既有规则的冲突由 check_conflict 负责。
    """
    _require_type(raw, dict, "$")
    doc: dict[str, Any] = raw  # type: ignore[assignment]
    unknown = set(doc) - {"apiVersion", "kind", "metadata", "rules"}
    if unknown:
        raise PolicyValidationError(f"策略文档含未知顶层字段: {sorted(unknown)}")

    _version_compatible(doc)

    metadata = _require_type(doc.get("metadata"), dict, "metadata")
    meta_unknown = set(metadata) - {"name", "version"}
    if meta_unknown:
        raise PolicyValidationError(f"字段 metadata 含未知字段: {sorted(meta_unknown)}")
    name = metadata.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PolicyValidationError("字段 metadata.name 必须是非空字符串")
    version = metadata.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise PolicyValidationError("字段 metadata.version 必须是 >=1 的整数")

    rules_raw = _require_type(doc.get("rules"), list, "rules")
    rules = tuple(_parse_rule(item, i) for i, item in enumerate(rules_raw))

    seen_ids: set[str] = set()
    for rule in rules:
        if rule.id in seen_ids:
            raise PolicyValidationError(f"规则 id 重复: {rule.id}")
        seen_ids.add(rule.id)

    return Policy(
        api_version=SUPPORTED_API_VERSION,
        kind=SUPPORTED_KIND,
        name=name.strip(),
        version=version,
        rules=rules,
    )


def selector_key(rule: Rule) -> tuple:
    """规则选择器的规范化标识：subject×resource×action。"""
    return (
        ("u", tuple(sorted(rule.subject.users))),
        ("r", tuple(sorted(rule.subject.roles))),
        ("g", tuple(sorted(rule.subject.groups))),
        rule.resource.type,
        tuple(sorted(rule.resource.patterns)),
        tuple(sorted(rule.action.methods)),
    )


def _limits_key(rule: Rule) -> tuple:
    rl = rule.rate_limit
    cl = rule.concurrency_limit
    return (
        (rl.max_requests, rl.window_seconds) if rl else None,
        cl.max_in_flight if cl else None,
    )


def check_conflict(new: Policy, existing: Policy | None) -> None:
    """检测新策略内部及与既有策略之间的规则冲突。

    冲突定义：相同选择器（subject/resource/action 完全一致）但
      1. effect 不同；或
      2. 限流/并发约束不同。
    完全相同的规则（同 effect 同约束）视为幂等重传，允许通过。
    """

    def _check_pairs(
        rules_a: Iterable[Rule], rules_b: Iterable[Rule], scope: str
    ) -> None:
        index: dict[tuple, Rule] = {}
        for rule in rules_a:
            index[selector_key(rule)] = rule
        for candidate in rules_b:
            prior = index.get(selector_key(candidate))
            if prior is None:
                continue
            if prior.effect != candidate.effect:
                raise PolicyConflictError(
                    f"规则冲突（{scope}）: {candidate.id} 与 {prior.id} 选择器相同但 effect 不同 "
                    f"({candidate.effect.value} vs {prior.effect.value})"
                )
            if _limits_key(prior) != _limits_key(candidate):
                raise PolicyConflictError(
                    f"规则冲突（{scope}）: {candidate.id} 与 {prior.id} 选择器相同但限流/并发约束不同"
                )

    # 新策略内部：同选择器且语义不一致即冲突
    seen: dict[tuple, Rule] = {}
    for rule in new.rules:
        key = selector_key(rule)
        prior = seen.get(key)
        if prior is not None:
            if prior.effect != rule.effect or _limits_key(prior) != _limits_key(rule):
                raise PolicyConflictError(
                    f"规则冲突（新策略内部）: {rule.id} 与 {prior.id} 选择器相同但语义不一致"
                )
        else:
            seen[key] = rule

    if existing is not None:
        _check_pairs(existing.rules, new.rules, "与既有策略")


def check_version_sequence(new: Policy, existing: Policy | None) -> None:
    """版本必须单调递增且连续：首次为任意 >=1，之后必须正好 +1。"""
    if existing is None:
        return
    expected = existing.version + 1
    if new.version != expected:
        raise PolicyVersionError(
            f"策略版本不连续: 期望 {expected}，收到 {new.version}（当前生效版本 {existing.version}）"
        )
