"""并发场景：多身份混合突发流量下计数准确、不串号、拒绝原因可区分、审计完整。"""

from __future__ import annotations

import threading
from collections import Counter

from zero_trust_admission.admission import AdmissionGuard
from zero_trust_admission.audit import InMemoryAuditSink
from zero_trust_admission.model import (
    AccessRequest,
    Action,
    Decision,
    DenyReason,
    Effect,
    PolicyDocument,
    Principal,
    RateLimitPolicy,
    Rule,
)
from zero_trust_admission.policy_store import PolicyStore


def _doc(rate: int, window: float, concurrency: int) -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="allow",
                effect=Effect.ALLOW,
                identities=("*",),
                groups=(),
                resources=("docs",),
                actions=("read",),
            ),
        ),
        rate_limits=(
            RateLimitPolicy(
                name="rl",
                identities=("*",),
                groups=(),
                resources=("docs",),
                rate_limit=rate,
                rate_window_seconds=window,
                concurrency=concurrency,
            ),
        ),
    )


def test_concurrent_burst_rate_limit_count_is_exact():
    rate = 20
    threads_n = 16
    per_thread = 20  # 共 320 次突发，远超阈值
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(
        PolicyStore(_doc(rate=rate, window=100.0, concurrency=100_000)),
        sink,
    )
    request = AccessRequest(Principal("alice"), "docs", Action.READ)

    allowed = Counter()
    denied = Counter()
    lock = threading.Lock()

    def worker():
        local = Counter()
        for _ in range(per_thread):
            result = guard.evaluate(request, now=1000.0)
            local[result.decision.value] += 1
            if result.decision is Decision.ALLOW:
                guard.release(result)
        with lock:
            allowed.update(
                {Decision.ALLOW.value: local[Decision.ALLOW.value]}
            )
            denied.update({Decision.DENY.value: local[Decision.DENY.value]})

    pool = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in pool:
        t.start()
    for t in pool:
        t.join()

    total = threads_n * per_thread
    assert allowed[Decision.ALLOW.value] == rate, allowed
    assert denied[Decision.DENY.value] == total - rate
    # 所有拒绝都必须可区分地归因于限流，而非其他原因
    deny_records = [
        r for r in sink.records if r.decision is Decision.DENY
    ]
    assert deny_records, "应当存在被限流的审计记录"
    assert all(r.reason is DenyReason.RATE_LIMITED for r in deny_records)
    assert len(deny_records) == total - rate
    # 每次判定都有且只有一条 admission 审计
    assert len(sink.records) == total


def test_concurrent_multi_identity_counts_never_cross():
    rate = 10
    identities = ["alice", "bob", "carol"]
    rounds = 40
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(
        PolicyStore(_doc(rate=rate, window=100.0, concurrency=100_000)),
        sink,
    )

    per_identity_allow = Counter()
    barrier = threading.Barrier(len(identities))

    def worker(identity: str):
        request = AccessRequest(Principal(identity), "docs", Action.READ)
        barrier.wait()
        local = 0
        for _ in range(rounds):
            result = guard.evaluate(request, now=2000.0)
            if result.decision is Decision.ALLOW:
                local += 1
                guard.release(result)
        per_identity_allow[identity] = local

    pool = [threading.Thread(target=worker, args=(i,)) for i in identities]
    for t in pool:
        t.start()
    for t in pool:
        t.join()

    # 每个身份独立计数：恰好 rate 次放行，互不串号
    assert dict(per_identity_allow) == {i: rate for i in identities}
    for identity in identities:
        assert (
            guard._rate_limiter.current_count(  # type: ignore[attr-defined]
                identity, "docs", 100.0, now=2000.0
            )
            == rate
        )
def test_concurrent_concurrency_limit_distinct_reason_and_released():
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(
        PolicyStore(_doc(rate=1_000_000, window=100.0, concurrency=3)),
        sink,
    )
    request = AccessRequest(Principal("alice"), "docs", Action.READ)
    results: list = []
    results_lock = threading.Lock()
    start = threading.Event()
    release_gate = threading.Event()
    n_threads = 20

    def worker():
        start.wait()
        result = guard.evaluate(request, now=3000.0)
        with results_lock:
            results.append(result)
        # 两阶段：判定全部完成前持槽线程不释放，槽位不可循环使用
        release_gate.wait()
        if result.decision is Decision.ALLOW:
            guard.release(result)

    pool = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in pool:
        t.start()
    start.set()
    while len(results) < n_threads:
        pass
    allowed = [r for r in results if r.decision is Decision.ALLOW]
    denied = [r for r in results if r.decision is Decision.DENY]
    assert len(allowed) == 3, len(allowed)
    assert len(denied) == 17
    assert all(r.reason is DenyReason.CONCURRENCY_LIMITED for r in denied)
    release_gate.set()
    for t in pool:
        t.join()
    # 全部释放后可再次获取
    again = guard.evaluate(request, now=3000.1)
    assert again.decision is Decision.ALLOW
    guard.release(again)


def test_concurrent_mixed_deny_reasons_are_differentiated():
    """同一突发中：基线拒绝、显式删除拒绝、限流三类原因必须可区分。"""
    doc = PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="deny-all-default",
                effect=Effect.DENY,
                identities=("*",),
                groups=(),
                resources=("*",),
                actions=("*",),
                priority=0,
            ),
            Rule(
                name="allow-read",
                effect=Effect.ALLOW,
                identities=("alice", "bob"),
                groups=(),
                resources=("docs",),
                actions=("read",),
                priority=10,
            ),
            Rule(
                name="deny-delete",
                effect=Effect.DENY,
                identities=("*",),
                groups=(),
                resources=("docs",),
                actions=("delete",),
                priority=20,
            ),
        ),
        rate_limits=(
            RateLimitPolicy(
                name="rl",
                identities=("*",),
                groups=(),
                resources=("docs",),
                rate_limit=2,
                rate_window_seconds=100.0,
                concurrency=100_000,
            ),
        ),
    )
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(PolicyStore(doc), sink)

    outcomes: Counter = Counter()
    lock = threading.Lock()
    jobs: list[tuple[AccessRequest, bool]] = []
    # 2 个陌生人读 -> 无放行规则覆盖，落回基线 explicit_deny（不进入限流）
    for _ in range(2):
        jobs.append((AccessRequest(Principal("stranger"), "docs", Action.READ), False))
    # 2 个 alice 删除 -> 命中 deny-delete
    for _ in range(2):
        jobs.append((AccessRequest(Principal("alice"), "docs", Action.DELETE), False))
    # 5 个 alice 读：阈值 2 -> 2 放行、3 限流
    for _ in range(5):
        jobs.append((AccessRequest(Principal("alice"), "docs", Action.READ), True))

    barrier = threading.Barrier(len(jobs))

    def run(request: AccessRequest, releasable: bool):
        barrier.wait()
        result = guard.evaluate(request, now=5000.0)
        key = result.reason.value if result.reason else "allow"
        with lock:
            outcomes[key] += 1
        if releasable and result.decision is Decision.ALLOW:
            guard.release(result)

    pool = [threading.Thread(target=run, args=j) for j in jobs]
    for t in pool:
        t.start()
    for t in pool:
        t.join()

    assert outcomes["explicit_deny"] == 4, outcomes
    assert outcomes["rate_limited"] == 3, outcomes
    assert outcomes["allow"] == 2, outcomes
    assert len(sink.records) == len(jobs)
