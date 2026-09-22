"""按身份与资源维度的限流与并发约束。

- 限流使用滑动日志窗口，每个 ``(身份, 资源)`` 键拥有独立的时间戳队列与独立锁；
  过期时间戳被惰性清理，突发流量下计数只属于自己的键，不跨身份串号。
- 并发使用每键信号量，获取/释放严格配对；下游异常时由调用方在 finally 中释放。
- 时间来源可注入（``now``），保证判定在测试中确定且可复现。
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

from .model import (
    AccessRequest,
    Principal,
    RateLimitPolicy,
    Rule,
)


def _pattern_match(patterns: tuple[str, ...], value: str) -> bool:
    """值匹配模式集合：精确匹配或 ``*`` 全匹配。"""
    return "*" in patterns or value in patterns


def principal_matches_rule(principal: Principal, rule: Rule | RateLimitPolicy) -> bool:
    """身份是否命中某条规则/限流策略的身份与组维度。"""
    if not _pattern_match(rule.identities, principal.identity):
        return False
    if rule.groups:
        # 策略限定了组时，身份必须至少属于其中一个组
        if not (set(rule.groups) & set(principal.groups)):
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


@dataclass
class _KeyGuard:
    """单个限流键的状态。"""

    events: deque[float]
    lock: threading.Lock


class SlidingWindowRateLimiter:
    """滑动日志窗口限流器。"""

    def __init__(self) -> None:
        self._guards: dict[tuple[str, str], _KeyGuard] = {}
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
    ) -> tuple[bool, int, int]:
        """检查并登记一次请求。

        返回 ``(是否允许, 窗口内当前计数, 阈值)``。
        超限时本次时间戳**不登记**，保证被拒请求不会占用正常流量的配额。
        """
        if policy.rate_limit is None or policy.rate_window_seconds is None:
            return True, 0, 0
        current = time.monotonic() if now is None else now
        guard = self._guard_for(req.principal.identity, req.resource)
        with guard.lock:
            horizon = current - policy.rate_window_seconds
            events = guard.events
            while events and events[0] <= horizon:
                events.popleft()
            if len(events) >= policy.rate_limit:
                return False, len(events), policy.rate_limit
            events.append(current)
            return True, len(events), policy.rate_limit

    def retract(
        self,
        req: AccessRequest,
        policy: RateLimitPolicy,
        timestamp: float,
    ) -> bool:
        """精确撤回此前登记的时间戳（后续阶段拒绝时回滚配额）。

        仅当该键队尾时间戳与传入值完全相等时才移除，避免在并发下误撤
        其他请求的登记；返回是否成功撤回。
        """
        guard = self._guards.get((req.principal.identity, req.resource))
        if guard is None:
            return False
        with guard.lock:
            if guard.events and guard.events[-1] == timestamp:
                guard.events.pop()
                return True
            # 队尾不一致时，在队列中按值定位（同键串行登记，理论上不会发生）
            try:
                guard.events.remove(timestamp)
                return True
            except ValueError:
                return False

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
            return sum(1 for ts in guard.events if ts > horizon)

    def reset(self) -> None:
        with self._registry_lock:
            self._guards.clear()


class ConcurrencyLimiter:
    """每键信号量并发限制器。"""

    def __init__(self) -> None:
        self._semaphores: dict[tuple[str, str], threading.BoundedSemaphore] = {}
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

    def reset(self) -> None:
        with self._registry_lock:
            self._semaphores.clear()


__all__ = [
    "SlidingWindowRateLimiter",
    "ConcurrencyLimiter",
    "select_rate_limit_policy",
    "rate_limit_matches_request",
    "request_matches_rule",
    "principal_matches_rule",
]
