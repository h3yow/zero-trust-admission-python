"""限流与并发约束：突发、重复、多身份混合下的隔离与确定性测试。"""

from __future__ import annotations

import threading

from admission.ratelimit import ConcurrencyLimiter, RateLimiter


def key(user: str, resource: str = "docs/a", action: str = "GET") -> tuple:
    return ("rl", "rule-1", user, (), (), "document", resource, action)


def test_fixed_window_does_not_drift_under_burst() -> None:
    rl = RateLimiter()
    results = [rl.try_acquire(key("alice"), 10, 100.0, 1.0) for _ in range(10)]
    assert all(results)
    # 第 11 个必须拒绝，计数恰好 10（不漂移）
    assert rl.try_acquire(key("alice"), 10, 100.0, 1.0) is False
    assert rl.current_count(key("alice")) == 10


def test_concurrent_burst_admits_exactly_the_limit() -> None:
    rl = RateLimiter()
    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        ok = rl.try_acquire(key("burst"), 10, 100.0, 1.0)
        with lock:
            outcomes.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(outcomes) == 10
    assert rl.current_count(key("burst")) == 10


def test_identities_never_share_counters() -> None:
    rl = RateLimiter()
    # alice 打满
    for _ in range(3):
        assert rl.try_acquire(key("alice"), 3, 100.0, 1.0)
    assert rl.try_acquire(key("alice"), 3, 100.0, 1.0) is False
    # bob / 不同资源 / 不同动作 各自独立，绝不串号
    assert rl.try_acquire(key("bob"), 3, 100.0, 1.0) is True
    assert rl.try_acquire(key("alice", "docs/b"), 3, 100.0, 1.0) is True
    assert rl.try_acquire(key("alice", "docs/a", "POST"), 3, 100.0, 1.0) is True


def test_window_reset_does_not_punish_later_normal_traffic() -> None:
    rl = RateLimiter()
    for _ in range(3):
        rl.try_acquire(key("carol"), 3, 1.0, 100.0)
    assert rl.try_acquire(key("carol"), 3, 1.0, 100.5) is False
    # 窗口过后正常流量必须恢复
    assert rl.try_acquire(key("carol"), 3, 1.0, 101.0) is True
    assert rl.current_count(key("carol")) == 1


def test_release_never_goes_negative_or_cross_window() -> None:
    rl = RateLimiter()
    rl.try_acquire(key("dave"), 2, 1.0, 0.0)
    rl.release(key("dave"), 2, 1.0, 0.1)
    assert rl.current_count(key("dave")) == 0
    rl.release(key("dave"), 2, 1.0, 0.2)  # 多还一次不得变负
    assert rl.current_count(key("dave")) == 0
    # 新窗口开启后，归还旧窗口配额不得影响新计数
    rl.try_acquire(key("dave"), 2, 1.0, 2.0)  # 新窗口计数=1
    rl.release(key("dave"), 2, 1.0, 2.1)  # 仍在新窗口，正常归还
    assert rl.current_count(key("dave")) == 0
    rl.try_acquire(key("dave"), 2, 1.0, 10.0)  # 又一个新窗口
    assert rl.current_count(key("dave")) == 1


def test_concurrency_slots_are_isolated_and_released() -> None:
    cl = ConcurrencyLimiter()
    assert cl.try_acquire(("c", "alice"), 1)
    assert not cl.try_acquire(("c", "alice"), 1)
    # 不同身份独立槽位
    assert cl.try_acquire(("c", "bob"), 1)
    cl.release(("c", "alice"), 1)
    assert cl.try_acquire(("c", "alice"), 1)


def test_expired_windows_are_purged(monkeypatch) -> None:
    from admission import ratelimit as rl_mod

    monkeypatch.setattr(rl_mod, "_PURGE_THRESHOLD", 2)
    rl = RateLimiter()
    rl.try_acquire(key("u1"), 1, 1.0, 0.0)
    rl.try_acquire(key("u2"), 1, 1.0, 0.0)
    assert rl.size() == 2
    # 第三次操作触发惰性清理：u1/u2 的窗口均已过期，应被删除
    rl.try_acquire(key("u3"), 1, 1.0, 5.0)
    assert rl.size() == 1
