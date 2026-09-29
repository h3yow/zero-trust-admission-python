"""分层配额在真实时钟（不注入 now）下的并发验收。

与线上验收方式一致：直接跑真实 monotonic 时钟 + 多线程突发，断言
- 被任一层拒掉的请求不占任何一层的名额；
- 多身份/多资源/多层混合时各层计数不漂、不串；
- 峰值过后每层按各自窗口恢复。
"""

from __future__ import annotations

import threading
import time
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


def _doc(rate_limits) -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="allow-all",
                effect=Effect.ALLOW,
                identities=("*",),
                groups=(),
                resources=("docs", "metrics"),
                actions=("*",),
                priority=0,
            ),
        ),
        rate_limits=tuple(rate_limits),
        rate_limit_mode="layered",
    )


def _ar(identity, groups=(), resource="docs"):
    return AccessRequest(Principal(identity, groups), resource, Action.READ)


def test_real_clock_burst_denied_requests_consume_no_layer_quota():
    # self 阈值远高于 global：突发必然先撞 global，
    # 被拒请求绝不能在 self/global 任一层留下登记
    doc = _doc(
        [
            RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 100_000, 300.0),
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 30, 300.0),
        ]
    )
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(PolicyStore(doc), sink)
    req = _ar("alice")

    outcomes = Counter()
    lock = threading.Lock()
    threads_n, per_thread = 16, 20
    start = threading.Event()

    def worker():
        start.wait()
        local = Counter()
        for _ in range(per_thread):
            result = guard.evaluate(req)  # 真实时钟，不注入 now
            local[result.decision.value] += 1
            if result.decision is Decision.ALLOW:
                guard.release(result)
        with lock:
            outcomes.update(local)

    pool = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in pool:
        t.start()
    start.set()
    for t in pool:
        t.join()

    total = threads_n * per_thread
    assert outcomes[Decision.ALLOW.value] == 30, outcomes
    assert outcomes[Decision.DENY.value] == total - 30
    # 被 global 限流拒掉的请求，self 层计数必须恰好等于放行数（30），
    # global 层窗口计数也是 30：没有任何被拒请求占名额
    assert (
        guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
            "rl-self", "identity", "alice", "docs", 300.0
        )
        == 30
    )
    assert (
        guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
            "rl-global", "global", "*", "docs", 300.0
        )
        == 30
    )
    denies = [r for r in sink.records if r.decision is Decision.DENY]
    assert len(denies) == total - 30
    assert all(r.reason is DenyReason.RATE_LIMITED for r in denies)
    # 每条拒绝审计都能定位拦截层及其阈值/用量
    for rec in denies:
        blocking = [c for c in rec.rate_layers if not c.allowed and c.denied_at == "rate_limit"]
        assert len(blocking) == 1
        assert blocking[0].policy_name == "rl-global"
        assert blocking[0].rate_threshold == 30
        assert blocking[0].rate_count == 30


def test_real_clock_multi_identity_layer_counts_never_cross():
    # 每身份 self=5；dev 组 group=15（三个 dev 成员共享，恰好不先于 self 触顶）；
    # global=100。瓶颈只可能落在各自身份层，分布因此确定
    doc = _doc(
        [
            RateLimitPolicy(
                "rl-self",
                ("alice", "bob", "carol"),
                (),
                ("docs",),
                5,
                300.0,
            ),
            RateLimitPolicy("rl-group", ("*",), ("dev",), ("docs",), 15, 300.0),
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 100, 300.0),
        ]
    )
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(PolicyStore(doc), sink)

    identities = ["alice", "bob", "carol"]
    rounds = 30
    allow_per_identity: Counter = Counter()
    deny_reasons: Counter = Counter()
    counter_lock = threading.Lock()
    barrier = threading.Barrier(len(identities))

    def worker(identity: str):
        req = _ar(identity, groups=("dev",))
        barrier.wait()
        local_allow = 0
        local_deny = Counter()
        for _ in range(rounds):
            result = guard.evaluate(req)
            if result.decision is Decision.ALLOW:
                local_allow += 1
                guard.release(result)
            else:
                local_deny[result.reason] += 1
        with counter_lock:
            allow_per_identity[identity] = local_allow
            deny_reasons.update(local_deny)

    pool = [threading.Thread(target=worker, args=(i,)) for i in identities]
    for t in pool:
        t.start()
    for t in pool:
        t.join()

    # 每层都不超过自身阈值：self 每层恰好 5；组层 15；global 15（总放行数）
    assert dict(allow_per_identity) == {i: 5 for i in identities}
    total_allow = sum(allow_per_identity.values())
    assert total_allow == 15
    assert sum(deny_reasons.values()) == len(identities) * rounds - total_allow
    # group=15、global=100 均未触顶，拒绝全部来自各自身份层
    assert set(deny_reasons) == {DenyReason.RATE_LIMITED}
    for ident in identities:
        assert (
            guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
                "rl-self", "identity", ident, "docs", 300.0
            )
            == 5
        )
    assert (
        guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
            "rl-group", "group", "dev", "docs", 300.0
        )
        == 15
    )
    assert (
        guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
            "rl-global", "global", "*", "docs", 300.0
        )
        == 15
    )
    # 每次判定恰好一条 admission 审计
    assert len(sink.records) == len(identities) * rounds


def test_real_clock_resources_do_not_share_layer_buckets():
    # global 层按资源分桶：docs 打满不影响 metrics
    doc = _doc(
        [RateLimitPolicy("rl-global", ("*",), (), ("docs", "metrics"), 5, 300.0)]
    )
    guard = AdmissionGuard(PolicyStore(doc), InMemoryAuditSink())
    docs_req = _ar("alice", resource="docs")
    for _ in range(5):
        r = guard.evaluate(docs_req)
        assert r.decision is Decision.ALLOW
        guard.release(r)
    assert guard.evaluate(docs_req).reason is DenyReason.RATE_LIMITED
    metrics_req = _ar("alice", resource="metrics")
    r = guard.evaluate(metrics_req)
    assert r.decision is Decision.ALLOW, r.detail
    guard.release(r)


def test_real_clock_layers_recover_after_peak_passes():
    # 短窗口：峰值过后每层各自恢复
    doc = _doc(
        [
            RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 2, 0.2),
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 3, 0.2),
        ]
    )
    guard = AdmissionGuard(PolicyStore(doc), InMemoryAuditSink())
    req = _ar("alice")

    allowed = 0
    while True:
        r = guard.evaluate(req)
        if r.decision is Decision.DENY:
            break
        allowed += 1
        guard.release(r)
    assert allowed == 2  # self 层先到顶
    # 等 self 窗口滑过（窗口各自独立恢复）
    time.sleep(0.35)
    r = guard.evaluate(req)
    assert r.decision is Decision.ALLOW, r.detail
    guard.release(r)


def test_real_clock_concurrency_deny_returns_all_prior_layer_slots():
    # self 并发很宽，global 并发=1：被 global 并发拒掉的线程，
    # 必须把 self 层槽位精确退回，峰值后 self 在途归零
    doc = _doc(
        [
            RateLimitPolicy(
                "rl-self", ("alice",), (), ("docs",), 100_000, 300.0, concurrency=64
            ),
            RateLimitPolicy(
                "rl-global", ("*",), (), ("docs",), 100_000, 300.0, concurrency=1
            ),
        ]
    )
    guard = AdmissionGuard(PolicyStore(doc), InMemoryAuditSink())
    req = _ar("alice")
    n_threads = 32
    results: list = []
    results_lock = threading.Lock()
    start = threading.Event()
    release_gate = threading.Event()

    def worker():
        start.wait()
        result = guard.evaluate(req)
        with results_lock:
            results.append(result)
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
    assert len(allowed) == 1
    assert len(denied) == n_threads - 1
    assert all(r.reason is DenyReason.CONCURRENCY_LIMITED for r in denied)
    # 被拒线程全部退回 self 槽后，self 在途只剩唯一持槽线程的 1 个
    time.sleep(0.05)  # 让被拒线程完成回滚
    self_policy = doc.rate_limits[0]
    assert guard._concurrency.active_layer(req, self_policy) == 1  # type: ignore[attr-defined]
    release_gate.set()
    for t in pool:
        t.join()
    # 全部释放后两层在途归零，可再次进入
    assert guard._concurrency.active_layer(req, self_policy) == 0  # type: ignore[attr-defined]
    again = guard.evaluate(req)
    assert again.decision is Decision.ALLOW
    guard.release(again)
