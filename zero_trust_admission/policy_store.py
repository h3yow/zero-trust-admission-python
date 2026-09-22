"""策略文档的解析、校验、冲突检测与版本化存储。

设计要点：
- 全部输入在生效前完成结构/语义校验，任何非法内容都抛出带有可区分 ``code``
  的 :class:`PolicyError` 子类，绝不静默放行；
- 规则冲突在同优先级、效果相反且匹配空间相交时被检测出来（文档内冲突与
  与既有规则合并时的跨文档冲突都会被拒绝）；
- 存储更新在锁内完成引用原子替换，生效结果稳定可复现。
"""

from __future__ import annotations

import json
import threading
from typing import Any

from .errors import (
    PolicyConflictError,
    PolicyError,
    PolicyFormatError,
    PolicySchemaVersionError,
    PolicyValidationError,
)
from .model import (
    Action,
    Effect,
    PolicyDocument,
    RateLimitPolicy,
    Rule,
)

_VALID_ACTIONS = {a.value for a in Action} | {"*"}


def _require_str_list(value: Any, field: str, *, min_len: int = 0) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(x, str) and x for x in value):
        raise PolicyFormatError(f"字段 {field!r} 必须是非空字符串的列表")
    if len(value) < min_len:
        raise PolicyValidationError(f"字段 {field!r} 至少需要 {min_len} 个元素")
    return tuple(value)


def _parse_rule(data: Any, index: int) -> Rule:
    if not isinstance(data, dict):
        raise PolicyFormatError(f"rules[{index}] 必须是对象")
    where = f"rules[{index}]"

    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyFormatError(f"{where}.name 必须是非空字符串")

    effect_raw = data.get("effect")
    if effect_raw not in (Effect.ALLOW.value, Effect.DENY.value):
        raise PolicyFormatError(
            f"{where}.effect 必须是 {Effect.ALLOW.value!r} 或 {Effect.DENY.value!r}"
        )
    effect = Effect(effect_raw)

    identities = _require_str_list(data.get("identities"), f"{where}.identities", min_len=1)
    resources = _require_str_list(data.get("resources"), f"{where}.resources", min_len=1)
    actions = _require_str_list(data.get("actions"), f"{where}.actions", min_len=1)
    for act in actions:
        if act not in _VALID_ACTIONS:
            raise PolicyValidationError(
                f"{where}.actions 包含非法动作 {act!r}，合法值: read/write/delete/*"
            )
    groups = _require_str_list(data.get("groups", []), f"{where}.groups")

    priority = data.get("priority", 0)
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise PolicyFormatError(f"{where}.priority 必须是整数")

    return Rule(
        name=name,
        effect=effect,
        identities=identities,
        groups=groups,
        resources=resources,
        actions=actions,
        priority=priority,
    )


def _parse_rate_limit(data: Any, index: int) -> RateLimitPolicy:
    if not isinstance(data, dict):
        raise PolicyFormatError(f"rate_limits[{index}] 必须是对象")
    where = f"rate_limits[{index}]"

    name = data.get("name")
    if not isinstance(name, str) or not name:
        raise PolicyFormatError(f"{where}.name 必须是非空字符串")

    identities = _require_str_list(
        data.get("identities", ["*"]), f"{where}.identities", min_len=1
    )
    groups = _require_str_list(data.get("groups", []), f"{where}.groups")
    resources = _require_str_list(data.get("resources"), f"{where}.resources", min_len=1)

    rate_limit = data.get("rate_limit")
    if rate_limit is not None and (
        isinstance(rate_limit, bool) or not isinstance(rate_limit, int) or rate_limit < 1
    ):
        raise PolicyValidationError(f"{where}.rate_limit 必须是 >= 1 的整数或 null")

    window = data.get("rate_window_seconds")
    if window is not None and (
        isinstance(window, bool) or not isinstance(window, (int, float)) or window <= 0
    ):
        raise PolicyValidationError(f"{where}.rate_window_seconds 必须是正数或 null")

    if (rate_limit is None) != (window is None):
        raise PolicyValidationError(
            f"{where} 的 rate_limit 与 rate_window_seconds 必须同时提供"
        )

    concurrency = data.get("concurrency")
    if concurrency is not None and (
        isinstance(concurrency, bool)
        or not isinstance(concurrency, int)
        or concurrency < 1
    ):
        raise PolicyValidationError(f"{where}.concurrency 必须是 >= 1 的整数或 null")

    if rate_limit is None and concurrency is None:
        raise PolicyValidationError(
            f"{where} 必须至少设置 rate_limit 或 concurrency 之一"
        )

    return RateLimitPolicy(
        name=name,
        identities=identities,
        groups=groups,
        resources=resources,
        rate_limit=rate_limit,
        rate_window_seconds=float(window) if window is not None else None,
        concurrency=concurrency,
    )


def _patterns_overlap(a: tuple[str, ...], b: tuple[str, ...]) -> bool:
    """两个匹配模式集合是否存在交集（``*`` 与任意集合相交）。"""
    if "*" in a or "*" in b:
        return True
    return bool(set(a) & set(b))


def find_conflict(
    rules_a: tuple[Rule, ...], rules_b: tuple[Rule, ...]
) -> tuple[Rule, Rule] | None:
    """返回一对同优先级、效果相反、匹配空间相交的规则；无冲突返回 None。"""
    for r1 in rules_a:
        for r2 in rules_b:
            if r1 is r2:
                continue
            if r1.priority != r2.priority or r1.effect == r2.effect:
                continue
            if not _patterns_overlap(r1.identities, r2.identities):
                continue
            # 组维度：双方都限定了组时才要求相交；任一方不限组（含 * 身份）视为重叠。
            if r1.groups and r2.groups and not (set(r1.groups) & set(r2.groups)):
                continue
            if not _patterns_overlap(r1.resources, r2.resources):
                continue
            if not _patterns_overlap(r1.actions, r2.actions):
                continue
            return r1, r2
    return None


def parse_policy_dict(data: object) -> PolicyDocument:
    """把已解析的 JSON 数据校验并转换为 :class:`PolicyDocument`。

    本函数只做解析与校验，不改变任何既有状态。
    """
    if not isinstance(data, dict):
        raise PolicyFormatError("策略文档必须是 JSON 对象")

    version = data.get("schema_version")
    if not isinstance(version, str):
        raise PolicyFormatError("字段 schema_version 必须是字符串")
    if version not in PolicyStore.SUPPORTED_SCHEMA_VERSIONS:
        raise PolicySchemaVersionError(
            f"不支持的策略 schema 版本 {version!r}，"
            f"支持的版本: {', '.join(PolicyStore.SUPPORTED_SCHEMA_VERSIONS)}"
        )

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyFormatError("字段 rules 必须是列表")
    rules = tuple(_parse_rule(item, i) for i, item in enumerate(raw_rules))

    raw_limits = data.get("rate_limits", [])
    if not isinstance(raw_limits, list):
        raise PolicyFormatError("字段 rate_limits 必须是列表")
    rate_limits = tuple(
        _parse_rate_limit(item, i) for i, item in enumerate(raw_limits)
    )

    names = [r.name for r in rules]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        raise PolicyValidationError(f"规则名称重复: {', '.join(sorted(dup))}")

    limit_names = [p.name for p in rate_limits]
    dup_l = {n for n in limit_names if limit_names.count(n) > 1}
    if dup_l:
        raise PolicyValidationError(
            f"限流策略名称重复: {', '.join(sorted(dup_l))}"
        )

    doc = PolicyDocument(
        schema_version=version,
        rules=rules,
        rate_limits=rate_limits,
        metadata=data.get("metadata", {}) if isinstance(data.get("metadata", {}), dict) else {},
    )
    # 文档内部冲突检测
    conflict = find_conflict(doc.rules, doc.rules)
    if conflict is not None:
        r1, r2 = conflict
        raise PolicyConflictError(
            f"规则冲突: {r1.name}({r1.effect.value}) 与 {r2.name}"
            f"({r2.effect.value}) 优先级相同且匹配空间相交"
        )
    return doc


class PolicyStore:
    """保存当前生效策略文档，支持原子替换、合并与失败安全的更新。"""

    SUPPORTED_SCHEMA_VERSIONS = ("1.0",)

    def __init__(self, initial: PolicyDocument | None = None) -> None:
        self._lock = threading.RLock()
        self._document: PolicyDocument | None = initial
        self._previous: PolicyDocument | None = None

    def current(self) -> PolicyDocument:
        with self._lock:
            if self._document is None:
                raise PolicyError("当前没有已生效的策略文档")
            return self._document

    def validate_document(self, document: PolicyDocument) -> None:
        """对构造好的文档再次执行语义/冲突校验（供外部构造时复用）。"""
        conflict = find_conflict(document.rules, document.rules)
        if conflict is not None:
            r1, r2 = conflict
            raise PolicyConflictError(
                f"规则冲突: {r1.name}({r1.effect.value}) 与 {r2.name}"
                f"({r2.effect.value}) 优先级相同且匹配空间相交"
            )

    def replace(self, document: PolicyDocument) -> PolicyDocument:
        """校验通过后原子替换整个策略文档，返回新生效文档。"""
        self.validate_document(document)
        with self._lock:
            self._previous = self._document
            self._document = document
            return self._document

    def merge(self, document: PolicyDocument) -> PolicyDocument:
        """把新文档中的规则合并进既有文档；名称重复或与既有规则冲突则拒绝。"""
        self.validate_document(document)
        with self._lock:
            base = self._document
            base_rules = base.rules if base is not None else ()
            base_limits = base.rate_limits if base is not None else ()

            existing_names = {r.name for r in base_rules}
            overlap = existing_names & {r.name for r in document.rules}
            if overlap:
                raise PolicyConflictError(
                    f"新增规则与既有规则同名: {', '.join(sorted(overlap))}"
                )

            existing_limit_names = {p.name for p in base_limits}
            overlap_l = existing_limit_names & {p.name for p in document.rate_limits}
            if overlap_l:
                raise PolicyConflictError(
                    f"新增限流策略与既有策略同名: {', '.join(sorted(overlap_l))}"
                )

            cross = find_conflict(base_rules, document.rules)
            if cross is not None:
                r1, r2 = cross
                raise PolicyConflictError(
                    f"新规则与既有规则冲突: {r1.name}({r1.effect.value}) 与 "
                    f"{r2.name}({r2.effect.value}) 优先级相同且匹配空间相交"
                )

            version = document.schema_version
            if base is not None:
                version = base.schema_version
            merged = PolicyDocument(
                schema_version=version,
                rules=base_rules + document.rules,
                rate_limits=base_limits + document.rate_limits,
                metadata={**(base.metadata if base is not None else {}), **document.metadata},
            )
            self._previous = self._document
            self._document = merged
            return merged

    def load_dict(self, data: object) -> PolicyDocument:
        document = parse_policy_dict(data)
        return self.replace(document)

    def load_json(self, text: str) -> PolicyDocument:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyFormatError(f"策略不是合法 JSON: {exc.msg}") from exc
        return self.load_dict(data)

    def load_json_file(self, path: str) -> PolicyDocument:
        with open(path, "r", encoding="utf-8") as fh:
            return self.load_json(fh.read())

    def merge_json(self, text: str) -> PolicyDocument:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise PolicyFormatError(f"策略不是合法 JSON: {exc.msg}") from exc
        return self.merge(parse_policy_dict(data))


__all__ = ["PolicyStore", "PolicyError", "parse_policy_dict", "find_conflict"]
