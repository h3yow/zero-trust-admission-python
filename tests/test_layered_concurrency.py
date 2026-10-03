"""真实时钟下的多层配额并发验收：不注入时间，直接压单调时钟。

与线上验收方式一致：多身份/多组/多资源混合突发，验证
- 被某层拒掉的请求不占任何一层名额（前层登记精确退回）；
- 各层计数不漂、不互相串，未超限的合规流量不被误伤；
- 允许/拒绝总数严格等于层阈值推导的期望。
"""

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
from zero_trust_admission.limiter import layer_scope

# 窗口取 300s，真实时钟下压测只占数秒，保证窗口内不存在时间戳滑出，
# 使"允许数 == 阈值"成为严格等式而不受时钟流逝影响。
WINDOW = 300.0


def _burst_doc() -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        quota_mode="layered",
        rules=(
            Rule("allow-all", Effect.ALLOW, ("*",), (), ("*",), ("*"), priority=10),
        ),
        rate_limits=(
            # 资源整体层：docs 全域只放 30
            RateLimitPolicy(
                "global-docs", ("*",), (), ("docs",),
                rate_limit=30, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
            # 组（租户）层：dev / ops 各自 12
            RateLimitPolicy(
                "tenant-dev", ("*",), ("dev",), ("docs",),
                rate_limit=12, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
            RateLimitPolicy(
                "tenant-ops", ("*",), ("ops",), ("docs",),
                rate_limit=12, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
            # 个人层：每人 5
            RateLimitPolicy(
                "self-a", ("alice",), (), ("docs",),
                rate_limit=5, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
            RateLimitPolicy(
                "self-b", ("bob",), (), ("docs",),
                rate_limit=5, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
            RateLimitPolicy(
                "self-c", ("carol",), (), ("docs",),
                rate_limit=5, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
            # 另一资源的整体层：与 docs 完全隔离
            RateLimitPolicy(
                "global-reports", ("*",), (), ("reports",),
                rate_limit=8, rate_window_seconds=WINDOW, concurrency=10_000,
            ),
        ),
    )


_IDENTITIES = [
    ("alice", "dev"),
    ("bob", "dev"),
    ("carol", "ops"),
]


def test_real_clock_burst_exact_allows_and_full_refund():
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(PolicyStore(_burst_doc()), sink)

    threads_n = 12
    per_thread = 20  # docs 共 240 次突发
    reports_per_thread = 5  # reports 共 60 次突发
    allow_counter: Counter = Counter()
    reports_allow_counter: Counter = Counter()
    reason_counter: Counter = Counter()
    block_layer_counter: Counter = Counter()
    lock = threading.Lock()
    barrier = threading.Barrier(2 * threads_n + 1)

    def worker(tid: int) -> None:
        local_allow: Counter = Counter()
        local_reason: Counter = Counter()
        local_block: Counter = Counter()
        # 各线程身份轮替，制造同身份/同组/全局的剧烈竞争
        docs_requests = []
        for i in range(per_thread):
            name, group = _IDENTITIES[(tid + i) % 3]
            docs_requests.append(
                AccessRequest(Principal(name, (group,)), "docs", Action.READ)
            )
        barrier.wait()
        for req in docs_requests:
            result = guard.evaluate(req)  # 真实时钟，不注入 now
            if result.decision is Decision.ALLOW:
                local_allow[req.principal.identity] += 1
                guard.release(result)
            else:
                local_reason[result.reason] += 1
                local_block[result.rate_limit.name] += 1
        with lock:
            allow_counter.update(local_allow)
            reason_counter.update(local_reason)
            block_layer_counter.update(local_block)

    def reports_worker(tid: int) -> None:
        identity, group = _IDENTITIES[tid % 3]
        req = AccessRequest(Principal(identity, (group,)), "reports", Action.READ)
        local = 0
        barrier.wait()
        for _ in range(reports_per_thread):
            result = guard.evaluate(req)
            if result.decision is Decision.ALLOW:
                local += 1
                guard.release(result)
        with lock:
            reports_allow_counter[group] += local

    pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads_n)]
    pool += [
        threading.Thread(target=reports_worker, args=(i,))
        for i in range(threads_n)
    ]
    for t in pool:
        t.start()
    barrier.wait()  # 所有线程同时起跑
    for t in pool:
        t.join()

    # ---- 精确等式：docs 个人层合计 5*3=15，组层 dev 12+ops 12=24，全局 30；
    #      最先打满的是个人层（合计 15），故 docs 总放行恰好 15 ----
    docs_allows = sum(allow_counter[i] for i in ("alice", "bob", "carol"))
    assert docs_allows == 15, allow_counter
    assert allow_counter["alice"] == 5
    assert allow_counter["bob"] == 5
    assert allow_counter["carol"] == 5

    total_docs = threads_n * per_thread
    assert sum(reason_counter.values()) == total_docs - 15
    # 所有拒绝都必须归因于限流（而非并发/审计/规则）
    assert set(reason_counter) == {DenyReason.RATE_LIMITED}, reason_counter
    # 拦截只能发生在个人层（最先耗尽）；组层与全局层不应误拒任何合规请求
    assert set(block_layer_counter) <= {"self-a", "self-b", "self-c"}, block_layer_counter

    # reports 独立资源：阈值 8，突发 60，恰好 8 放行
    reports_allows = sum(reports_allow_counter.values())
    assert reports_allows == 8, reports_allow_counter

    # ---- 名额精确退回：被个人层拒的请求绝不能占组层/全局层名额。
    #      反证：组层 dev 用量必须恰为其合规放行数 alice+bob=10，ops=carol=5；
    #      全局 docs 用量必须恰为 15。若有漂移/串号，下列等式会被打破。 ----
    rl = guard._rate_limiter  # type: ignore[attr-defined]

    def count(policy: RateLimitPolicy, identity: str, groups: tuple) -> int:
        req = AccessRequest(Principal(identity, groups), "docs", Action.READ)
        key, _ = layer_scope(req, policy)
        return rl.current_count_key(
            ("layer-rate", policy.name, key), WINDOW
        )

    policies = {p.name: p for p in guard._store.current().rate_limits}
    assert count(policies["tenant-dev"], "alice", ("dev",)) == 10
    assert count(policies["tenant-ops"], "carol", ("ops",)) == 5
    assert count(policies["global-docs"], "anyone", ()) == 15
    for name, identity in (("self-a", "alice"), ("self-b", "bob"), ("self-c", "carol")):
        assert count(policies[name], identity, ()) == 5

    # 每次判定一条 admission 审计，且记录与判定一致
    deny_records = [r for r in sink.records if r.decision is Decision.DENY]
    assert len(deny_records) == (total_docs - 15) + (
        threads_n * reports_per_thread - 8
    )
    assert all(r.reason is DenyReason.RATE_LIMITED for r in deny_records)
    assert len(sink.records) == total_docs + threads_n * reports_per_thread


def test_real_clock_concurrency_layer_refunds_in_burst():
    """真实时钟突发撞并发层：未获槽的请求退回此前所有层的限流登记。"""
    sink = InMemoryAuditSink()
    doc = PolicyDocument(
        schema_version="1.0",
        quota_mode="layered",
        rules=(Rule("a", Effect.ALLOW, ("*",), (), ("docs",), ("*"), priority=10),),
        rate_limits=(
            RateLimitPolicy("self", ("alice",), (), ("docs",),
                            rate_limit=1_000, rate_window_seconds=WINDOW),
            RateLimitPolicy("global", ("*",), (), ("docs",),
                            rate_limit=1_000, rate_window_seconds=WINDOW,
                            concurrency=4),
        ),
    )
    guard = AdmissionGuard(PolicyStore(doc), sink)
    req = AccessRequest(Principal("alice"), "docs", Action.READ)

    n_threads = 24
    results: list = []
    results_lock = threading.Lock()
    start = threading.Event()
    release_gate = threading.Event()

    def worker() -> None:
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
    # 等待全部判定完成（持槽线程在 gate 前等待，槽位不可循环使用）
    while len(results) < n_threads:
        pass
    allowed = [r for r in results if r.decision is Decision.ALLOW]
    denied = [r for r in results if r.decision is Decision.DENY]
    assert len(allowed) == 4
    assert len(denied) == n_threads - 4
    assert all(r.reason is DenyReason.CONCURRENCY_LIMITED for r in denied)

    # 被并发层拒掉的请求必须把 self 层限流名额精确退回：窗口内只剩 4
    self_p = doc.rate_limits[0]
    key, _ = layer_scope(req, self_p)
    assert (
        guard._rate_limiter.current_count_key(  # type: ignore[attr-defined]
            ("layer-rate", "self", key), WINDOW
        )
        == 4
    )

    release_gate.set()
    for t in pool:
        t.join()


def test_real_clock_same_specificity_order_stable_under_burst():
    """真实时钟突发下，同具体度多层的判定/展示顺序只认文件书写位置。

    两个组层都命中 dev：位置 0 阈值 8、位置 1 阈值 20。40 次并发突发下：
    - 每次判定（允许或拒绝）的层顺序都必须严格等于文件书写顺序；
    - 恰好 8 次放行、32 次被位置 0 的层以 rate_limited 拦截；
    - 改名（位置不动）后上述结论逐字不变；
    - 两层最终窗口计数都精确等于 8（被拒请求不占任何一层名额）。
    """

    def run(first_name: str, second_name: str) -> None:
        doc = PolicyDocument(
            schema_version="1.0",
            quota_mode="layered",
            rules=(
                Rule("allow-all", Effect.ALLOW, ("*",), (), ("*",), ("*"), priority=10),
            ),
            rate_limits=(
                RateLimitPolicy(
                    first_name, ("*",), ("dev",), ("docs",),
                    rate_limit=8, rate_window_seconds=WINDOW, concurrency=10_000,
                ),
                RateLimitPolicy(
                    second_name, ("*",), ("dev",), ("docs",),
                    rate_limit=20, rate_window_seconds=WINDOW, concurrency=10_000,
                ),
            ),
        )
        guard = AdmissionGuard(PolicyStore(doc), InMemoryAuditSink())
        threads_n, per_thread = 8, 5  # 共 40 次突发
        barrier = threading.Barrier(threads_n + 1)
        lock = threading.Lock()
        orders: set[tuple[str, ...]] = set()
        stats: Counter = Counter()

        def worker(tid: int) -> None:
            req = AccessRequest(
                Principal(f"user{tid % 3}", ("dev",)), "docs", Action.READ
            )
            local: Counter = Counter()
            local_orders: set[tuple[str, ...]] = set()
            barrier.wait()
            for _ in range(per_thread):
                result = guard.evaluate(req)  # 真实时钟，不注入 now
                local_orders.add(tuple(l.policy_name for l in result.quota_layers))
                if result.decision is Decision.ALLOW:
                    local["allow"] += 1
                    guard.release(result)
                else:
                    local["deny"] += 1
                    assert result.reason is DenyReason.RATE_LIMITED
                    assert result.rate_limit.name == first_name
                    local["blocked_" + result.rate_limit.name] += 1
            with lock:
                orders.update(local_orders)
                stats.update(local)

        pool = [threading.Thread(target=worker, args=(i,)) for i in range(threads_n)]
        for t in pool:
            t.start()
        barrier.wait()
        for t in pool:
            t.join()

        # 40 次判定、两种结局，层顺序有且只有文件书写顺序这一种
        assert orders == {(first_name, second_name)}
        assert stats["allow"] == 8
        assert stats["deny"] == 32
        assert stats["blocked_" + first_name] == 32

        # 各层计数精确：放行的 8 次在两层各登记一次，被拒的 32 次零登记
        req = AccessRequest(Principal("user0", ("dev",)), "docs", Action.READ)
        for name, threshold in ((first_name, 8), (second_name, 8)):
            policy = next(p for p in doc.rate_limits if p.name == name)
            sk, _ = layer_scope(req, policy)
            assert guard._rate_limiter.current_count_key(  # type: ignore[attr-defined]
                ("layer-rate", name, sk), WINDOW
            ) == threshold

    # 同一书写位置、两套完全不同且字典序相反的名字：结论必须逐字一致
    run("zzz-first", "aaa-second")
    run("aaa-first", "zzz-second")
