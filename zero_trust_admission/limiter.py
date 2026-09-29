"""按身份与资源维度的限流与并发约束。

- 限流使用滑动日志窗口，每个 ``(身份, 资源)`` 键拥有独立的时间戳队列与独立锁；
  过期时间戳被惰性清理，突发流量下计数只属于自己的键，不跨身份串号。
- 并发使用每键信号量，获取/释放严格配对；下游异常时由调用方在 finally 中释放。
- 时间来源可注入（``now``），保证判定在测试中确定且可复现。
"""

from __future__ import annotations

import itertools
import threading
import time
from collections import deque
from dataclasses import dataclass

from .model import (
    AccessRequest,
    Principal,
    RateLimitPolicy,
    Rule,
)

# 每次登记的全局唯一令牌：真实时钟下并发线程可能拿到完全相同的时间戳，
# 撤回时必须按令牌精确撤自己的登记，不能按时间戳值误撤同桶其他请求。
_token_counter = itertools.count(1)


@dataclass(frozen=True, slots=True)
class _Event:
    """一次限流登记：时间戳 + 唯一令牌。"""

    timestamp: float
    token: int


def _pattern_match(patterns: tuple[str, ...], value: str) -> bool:
    """值匹配模式集合：精确匹配或 ``*`` 全匹配。"""
    return "*" in patterns or value in patterns


def principal_matches_rule(principal: Principal, rule: Rule | RateLimitPolicy) -> bool:
    """身份是否命中某条规则/限流策略的身份与组维度。"""
    if not _pattern_match(rule.identities, principal.identity):
        return False
    # 策略限定了组时，身份必须至少属于其中一个组
    if rule.groups and not (set(rule.groups) & set(principal.groups)):
        return False
    return True


def request_matches_rule(req: AccessRequest, rule: Rule) -> bool:
    if not principal_matches_rule(req.principal, rule):
        return False
    if not _pattern_match(rule.resources, req.resource):
        return False
    return _pattern_match(rule.actions, req.action.value)


def rate_limit_matches_request(
    req: AccessRequest, policy: RateLimitPolicy
) -> bool:
    if not principal_matches_rule(req.principal, policy):
        return False
    return _pattern_match(policy.resources, req.resource)


def _specificity(policy: RateLimitPolicy, principal: Principal) -> int:
    """策略选择优先级：显式身份 > 组匹配 > 通配；显式资源 > 通配资源。"""
    score = 0
    if principal.identity in policy.identities:
        score += 4
    elif policy.groups and (set(policy.groups) & set(principal.groups)):
        score += 2
    # 其余情况只能是 * 身份
    score += 1 if "*" not in policy.resources else 0
    return score


def select_rate_limit_policy(
    req: AccessRequest, policies: tuple[RateLimitPolicy, ...]
) -> RateLimitPolicy | None:
    """从命中的限流策略中选择约束最具体的一条；同分时取名称较小者保证确定性。"""
    candidates = [p for p in policies if rate_limit_matches_request(req, p)]
    if not candidates:
        return None
    return max(candidates, key=lambda p: (_specificity(p, req.principal), _neg_name(p.name)))


def _neg_name(name: str) -> str:
    # 仅用于让 max 在 specificity 同分时稳定（名称字典序最小者胜出）
    return "".join(chr(0x10FFFF - ord(ch)) for ch in name)


def layer_binding(policy: RateLimitPolicy, principal: Principal) -> tuple[str, str]:
    """分层模式下某条策略对某身份的配额桶绑定 ``(桶维度, 桶值)``。

    - 显式列出身份 -> ``("identity", 身份名)``：每个身份各自独立一层计数；
    - 否则按组限定 -> ``("group", 组名)``：同组共享一层计数；身份同时
      命中策略列出的多个组时取字典序最小者，保证绑定确定、不随并发漂移；
    - 其余（``*`` 身份且未限定组）-> ``("global", "*")``：资源整体一档。
    """
    if principal.identity in policy.identities:
        return "identity", principal.identity
    if policy.groups:
        matched = set(policy.groups) & set(principal.groups)
        return "group", min(matched)
    return "global", "*"


def _layer_key(policy: RateLimitPolicy, req: AccessRequest) -> tuple[str, str, str, str]:
    scope, value = layer_binding(policy, req.principal)
    return policy.name, scope, value, req.resource


def select_rate_limit_layers(
    req: AccessRequest, policies: tuple[RateLimitPolicy, ...]
) -> tuple[tuple[int, RateLimitPolicy], ...]:
    """分层模式：返回所有命中策略及其在文档中的声明序号。

    判定/展示顺序固定为：层特异性（显式身份 > 组 > 全局，显式资源 >
    通配资源）降序，同分按文档声明顺序升序。该顺序只依赖策略内容与
    声明位置，不依赖名称字典序与运行时并发。
    """
    matched = [
        (index, policy)
        for index, policy in enumerate(policies)
        if rate_limit_matches_request(req, policy)
    ]
    matched.sort(
        key=lambda item: (
            -_specificity(item[1], req.principal),
            item[0],
        )
    )
    return tuple(matched)


@dataclass
class _KeyGuard:
    """单个限流键的状态。"""

    events: deque[_Event]
    lock: threading.Lock


class SlidingWindowRateLimiter:
    """滑动日志窗口限流器。"""

    def __init__(self) -> None:
        self._guards: dict[tuple[str, str], _KeyGuard] = {}
        # 分层模式计数桶：键为 (策略名, 桶维度, 桶值, 资源)
        self._layer_guards: dict[tuple[str, str, str, str], _KeyGuard] = {}
        self._registry_lock = threading.Lock()

    def _guard_for(self, identity: str, resource: str) -> _KeyGuard:
        key = (identity, resource)
        guard = self._guards.get(key)
        if guard is not None:
            return guard
        with self._registry_lock:
            guard = self._guards.get(key)
            if guard is None:
                guard = _KeyGuard(events=deque(), lock=threading.Lock())
                self._guards[key] = guard
            return guard

    def check(
        self,
        req: AccessRequest,
        policy: RateLimitPolicy,
        *,
        now: float | None = None,
    ) -> tuple[bool, int, int, int | None]:
        """检查并登记一次请求。

        返回 ``(是否允许, 窗口内当前计数, 阈值, 登记令牌)``。
        超限时本次**不登记**且令牌为 None，保证被拒请求不占配额；
        调用方凭令牌 :meth:`retract` 精确退回。
        """
        if policy.rate_limit is None or policy.rate_window_seconds is None:
            return True, 0, 0, None
        current = time.monotonic() if now is None else now
        guard = self._guard_for(req.principal.identity, req.resource)
        return self._check_guard(
            guard, current, policy.rate_limit, policy.rate_window_seconds
        )

    def retract(
        self,
        req: AccessRequest,
        policy: RateLimitPolicy,
        token: int | float,
    ) -> bool:
        """撤回此前登记：优先按唯一令牌，老调用方传时间戳也兼容。"""
        guard = self._guards.get((req.principal.identity, req.resource))
        if guard is None:
            return False
        return self._retract_guard(guard, token)

    @staticmethod
    def _check_guard(
        guard: _KeyGuard,
        current: float,
        limit: int,
        window: float,
    ) -> tuple[bool, int, int, int | None]:
        """在指定桶锁内做滑动窗口检查；放行时登记并返回唯一令牌。"""
        with guard.lock:
            horizon = current - window
            events = guard.events
            while events and events[0].timestamp <= horizon:
                events.popleft()
            if len(events) >= limit:
                return False, len(events), limit, None
            token = next(_token_counter)
            events.append(_Event(current, token))
            return True, len(events), limit, token

    @staticmethod
    def _retract_guard(guard: _KeyGuard, marker: float | int) -> bool:
        """按登记令牌（int）或时间戳（float，仅老路径）精确撤回一次登记。"""
        with guard.lock:
            if isinstance(marker, int):
                for index in range(len(guard.events) - 1, -1, -1):
                    if guard.events[index].token == marker:
                        del guard.events[index]
                        return True
                return False
            # 老路径兼容：按队尾时间戳精确匹配，避免误撤并发下其他登记
            if guard.events and guard.events[-1].timestamp == marker:
                guard.events.pop()
                return True
            try:
                token_to_remove = next(
                    event.token for event in guard.events if event.timestamp == marker
                )
            except StopIteration:
                return False
            guard.events = deque(
                event for event in guard.events if event.token != token_to_remove
            )
            return True

    def current_count(
        self,
        identity: str,
        resource: str,
        window: float,
        *,
        now: float | None = None,
    ) -> int:
        """只读查看当前窗口计数，不登记、不修改状态。"""
        current = time.monotonic() if now is None else now
        guard = self._guards.get((identity, resource))
        if guard is None:
            return 0
        with guard.lock:
            horizon = current - window
            return sum(1 for event in guard.events if event.timestamp > horizon)

    # ---- 分层模式：按 (策略, 绑定桶, 资源) 独立计数 --------------------

    def check_layer(
        self,
        req: AccessRequest,
        policy: RateLimitPolicy,
        *,
        now: float | None = None,
    ) -> tuple[bool, int, int, int | None]:
        """在某一配额层上检查并登记（计数键含策略名与绑定桶，层间不串号）。

        返回 ``(是否允许, 窗口计数, 阈值, 登记令牌)``；被拒时令牌为 None，
        调用方应凭令牌 :meth:`retract_layer` 精确退回。
        """
        if policy.rate_limit is None or policy.rate_window_seconds is None:
            return True, 0, 0, None
        current = time.monotonic() if now is None else now
        guard = self._guard_for_layer(_layer_key(policy, req))
        return self._check_guard(
            guard, current, policy.rate_limit, policy.rate_window_seconds
        )

    def _guard_for_layer(self, key: tuple[str, str, str, str]) -> _KeyGuard:
        guard = self._layer_guards.get(key)
        if guard is not None:
            return guard
        with self._registry_lock:
            guard = self._layer_guards.get(key)
            if guard is None:
                guard = _KeyGuard(events=deque(), lock=threading.Lock())
                self._layer_guards[key] = guard
            return guard

    def retract_layer(
        self,
        req: AccessRequest,
        policy: RateLimitPolicy,
        token: int,
    ) -> bool:
        """在某一配额层上按登记令牌精确撤回本次登记（不碰其他请求）。"""
        guard = self._layer_guards.get(_layer_key(policy, req))
        if guard is None:
            return False
        return self._retract_guard(guard, token)

    def current_layer_count(
        self,
        policy_name: str,
        scope: str,
        scope_value: str,
        resource: str,
        window: float,
        *,
        now: float | None = None,
    ) -> int:
        """只读查看某个配额层桶的当前窗口计数，不登记、不修改状态。"""
        current = time.monotonic() if now is None else now
        guard = self._layer_guards.get((policy_name, scope, scope_value, resource))
        if guard is None:
            return 0
        with guard.lock:
            horizon = current - window
            return sum(1 for event in guard.events if event.timestamp > horizon)

    def reset(self) -> None:
        with self._registry_lock:
            self._guards.clear()
            self._layer_guards.clear()


class ConcurrencyLimiter:
    """每键信号量并发限制器。"""

    def __init__(self) -> None:
        self._semaphores: dict[tuple[str, str], threading.BoundedSemaphore] = {}
        # 分层模式信号量：键为 (策略名, 桶维度, 桶值, 资源)
        self._layer_semaphores: dict[
            tuple[str, str, str, str], threading.BoundedSemaphore
        ] = {}
        self._registry_lock = threading.Lock()

    def _semaphore_for(
        self, identity: str, resource: str, limit: int
    ) -> threading.BoundedSemaphore:
        key = (identity, resource)
        sem = self._semaphores.get(key)
        if sem is not None:
            return sem
        with self._registry_lock:
            sem = self._semaphores.get(key)
            if sem is None:
                sem = threading.BoundedSemaphore(limit)
                self._semaphores[key] = sem
            return sem

    def acquire(
        self, req: AccessRequest, policy: RateLimitPolicy, *, blocking: bool = False
    ) -> bool:
        if policy.concurrency is None:
            return True
        sem = self._semaphore_for(
            req.principal.identity, req.resource, policy.concurrency
        )
        return sem.acquire(blocking=blocking)

    def release(self, req: AccessRequest, policy: RateLimitPolicy) -> None:
        if policy.concurrency is None:
            return
        sem = self._semaphores.get((req.principal.identity, req.resource))
        if sem is not None:
            try:
                sem.release()
            except ValueError:
                # 未配对释放属于编程错误，显式暴露而不是静默吞掉
                raise RuntimeError("并发信号量释放次数超过获取次数")

    def active(self, req: AccessRequest, policy: RateLimitPolicy) -> int:
        if policy.concurrency is None:
            return 0
        sem = self._semaphores.get((req.principal.identity, req.resource))
        if sem is None:
            return 0
        return policy.concurrency - sem._value  # type: ignore[attr-defined]

    # ---- 分层模式：按 (策略, 绑定桶, 资源) 独立信号量 ------------------

    def _layer_semaphore_for(
        self,
        key: tuple[str, str, str, str],
        limit: int,
    ) -> threading.BoundedSemaphore:
        sem = self._layer_semaphores.get(key)
        if sem is not None:
            return sem
        with self._registry_lock:
            sem = self._layer_semaphores.get(key)
            if sem is None:
                sem = threading.BoundedSemaphore(limit)
                self._layer_semaphores[key] = sem
            return sem

    def acquire_layer(
        self, req: AccessRequest, policy: RateLimitPolicy, *, blocking: bool = False
    ) -> tuple[bool, int]:
        """在某一配额层尝试获取并发槽，返回 ``(是否成功, 当前在途数)``。"""
        if policy.concurrency is None:
            return True, 0
        key = _layer_key(policy, req)
        sem = self._layer_semaphore_for(key, policy.concurrency)
        acquired = sem.acquire(blocking=blocking)
        active = policy.concurrency - sem._value  # type: ignore[attr-defined]
        return acquired, active

    def release_layer(self, req: AccessRequest, policy: RateLimitPolicy) -> None:
        if policy.concurrency is None:
            return
        sem = self._layer_semaphores.get(_layer_key(policy, req))
        if sem is not None:
            try:
                sem.release()
            except ValueError:
                # 未配对释放属于编程错误，显式暴露而不是静默吞掉
                raise RuntimeError("分层并发信号量释放次数超过获取次数")

    def active_layer(self, req: AccessRequest, policy: RateLimitPolicy) -> int:
        if policy.concurrency is None:
            return 0
        sem = self._layer_semaphores.get(_layer_key(policy, req))
        if sem is None:
            return 0
        return policy.concurrency - sem._value  # type: ignore[attr-defined]

    def reset(self) -> None:
        with self._registry_lock:
            self._semaphores.clear()
            self._layer_semaphores.clear()


__all__ = [
    "ConcurrencyLimiter",
    "SlidingWindowRateLimiter",
    "layer_binding",
    "principal_matches_rule",
    "rate_limit_matches_request",
    "request_matches_rule",
    "select_rate_limit_layers",
    "select_rate_limit_policy",
]
