"""限流：滑动窗口、键隔离、被拒请求不占配额、确定性策略选择。"""

from __future__ import annotations

from zero_trust_admission.limiter import (
    ConcurrencyLimiter,
    SlidingWindowRateLimiter,
    select_rate_limit_policy,
)
from zero_trust_admission.model import (
    Action,
    AccessRequest,
    Principal,
    RateLimitPolicy,
)


def req(identity: str, resource: str = "docs", groups: tuple[str, ...] = ()):
    return AccessRequest(Principal(identity, groups), resource, Action.READ)


def policy(limit=3, window=10.0, concurrency=None, identities=("*",)):
    return RateLimitPolicy(
        name="p",
        identities=identities,
        groups=(),
        resources=("docs",),
        rate_limit=limit,
        rate_window_seconds=window,
        concurrency=concurrency,
    )


def test_sliding_window_allows_then_denies_then_recovers():
    limiter = SlidingWindowRateLimiter()
    p = policy(limit=3, window=10.0)
    r = req("alice")
    results = [limiter.check(r, p, now=100 + i)[0] for i in range(3)]
    assert results == [True, True, True]
    allowed, count, threshold = limiter.check(r, p, now=103)
    assert allowed is False and count == 3 and threshold == 3
    # 窗口滑过后恢复
    assert limiter.check(r, p, now=110.001)[0] is True
    # 此时窗口为 (100.001, 110.001]，旧请求 101/102 与新请求仍在窗内
    assert limiter.current_count("alice", "docs", 10.0, now=110.001) == 3
    # 再等到 112.002，旧请求全部滑出，只剩新请求
    assert limiter.current_count("alice", "docs", 10.0, now=112.002) == 1


def test_counts_do_not_cross_identities_or_resources():
    limiter = SlidingWindowRateLimiter()
    p = policy(limit=2)
    assert limiter.check(req("alice"), p, now=1)[0]
    assert limiter.check(req("alice"), p, now=1)[0]
    assert limiter.check(req("alice"), p, now=1)[0] is False
    # bob 独立键，不受 alice 超限影响
    assert limiter.check(req("bob"), p, now=1)[0]
    assert limiter.current_count("bob", "docs", 10.0, now=1) == 1
    # alice 访问另一资源也是独立键
    assert limiter.check(req("alice", "other"), p, now=1)[0]


def test_repeated_denied_requests_do_not_drift_count():
    limiter = SlidingWindowRateLimiter()
    p = policy(limit=1, window=10.0)
    r = req("alice")
    assert limiter.check(r, p, now=0)[0]
    for i in range(10):
        ok, count, _ = limiter.check(r, p, now=1 + i * 0.1)
        assert ok is False
        assert count == 1  # 重复超限请求不登记，计数不漂移
    # bob 的正常流量未被误伤
    ok, count, _ = limiter.check(req("bob"), p, now=1)
    assert ok and count == 1


def test_retract_restores_quota():
    limiter = SlidingWindowRateLimiter()
    p = policy(limit=1)
    r = req("alice")
    assert limiter.check(r, p, now=0)[0]
    assert limiter.check(r, p, now=0)[0] is False
    assert limiter.retract(r, p, 0.0) is True
    assert limiter.check(r, p, now=0)[0]


def test_concurrency_semaphore_isolated_and_released():
    cm = ConcurrencyLimiter()
    p = policy(limit=100, concurrency=2)
    ra, rb = req("alice"), req("bob")
    assert cm.acquire(ra, p) and cm.acquire(ra, p)
    assert cm.acquire(ra, p) is False
    assert cm.acquire(rb, p)  # 不同身份独立
    cm.release(ra, p)
    assert cm.active(ra, p) == 1
    cm.release(ra, p)
    assert cm.acquire(ra, p)


def test_select_most_specific_rate_limit_policy():
    generic = policy(identities=("*",))
    specific = RateLimitPolicy(
        name="alice-only",
        identities=("alice",),
        groups=(),
        resources=("docs",),
        rate_limit=1,
        rate_window_seconds=1.0,
    )
    assert select_rate_limit_policy(req("alice"), (generic, specific)).name == "alice-only"
    assert select_rate_limit_policy(req("bob"), (generic, specific)).name == "p"
