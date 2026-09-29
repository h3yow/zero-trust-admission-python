"""多层配额（layered quota mode）：层叠加、固定顺序、短路展示、精确退回。"""

from __future__ import annotations

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

ALLOW_ALL = Rule("allow-all", Effect.ALLOW, ("*",), (), ("*",), ("*"), priority=10)


def layered_doc(*policies: RateLimitPolicy) -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        quota_mode="layered",
        rules=(ALLOW_ALL,),
        rate_limits=tuple(policies),
    )


def p_self(identity: str = "alice", **kw) -> RateLimitPolicy:
    kw.setdefault("rate_limit", 100)
    kw.setdefault("rate_window_seconds", 100.0)
    return RateLimitPolicy(
        f"self-{identity}",
        (identity,),
        (),
        ("docs",),
        **kw,
    )


def p_group(group: str = "dev", name: str = "tenant-dev", **kw) -> RateLimitPolicy:
    kw.setdefault("rate_limit", 100)
    kw.setdefault("rate_window_seconds", 100.0)
    return RateLimitPolicy(name, ("*",), (group,), ("docs",), **kw)


def p_global(name: str = "global", **kw) -> RateLimitPolicy:
    kw.setdefault("rate_limit", 100)
    kw.setdefault("rate_window_seconds", 100.0)
    return RateLimitPolicy(name, ("*",), (), ("docs",), **kw)


def guard_for(doc: PolicyDocument) -> AdmissionGuard:
    return AdmissionGuard(PolicyStore(doc), InMemoryAuditSink())


def areq(identity="alice", groups=("dev",), resource="docs") -> AccessRequest:
    return AccessRequest(Principal(identity, groups), resource, Action.READ)


# ---------------------------------------------------------------------
# 1) 多层叠加：所有层同时约束、各自计数；固定顺序不随定义顺序/名字变化
# ---------------------------------------------------------------------


def test_all_layers_constrain_simultaneously_with_independent_counts():
    doc = layered_doc(
        p_global(rate_limit=3),
        p_group(rate_limit=5),
        p_self(rate_limit=2),
    )
    g = guard_for(doc)
    req = areq()

    r1 = g.evaluate(req, now=1000.0)
    assert r1.decision is Decision.ALLOW
    assert [l.policy_name for l in r1.quota_layers] == [
        "self-alice",
        "tenant-dev",
        "global",
    ]
    assert [(l.used, l.threshold, l.scope) for l in r1.quota_layers] == [
        (1, 2, "identity:alice@docs"),
        (1, 5, "group:dev@docs"),
        (1, 3, "resource:docs"),
    ]
    g.release(r1)

    r2 = g.evaluate(req, now=1000.1)
    assert r2.decision is Decision.ALLOW
    g.release(r2)

    # 第 3 次：个人层（阈值 2）先拦，组层/全局层未到阈值
    r3 = g.evaluate(req, now=1000.2)
    assert r3.decision is Decision.DENY
    assert r3.reason is DenyReason.RATE_LIMITED
    assert r3.rate_limit.name == "self-alice"
    names = [l.policy_name for l in r3.quota_layers]
    assert names == ["self-alice", "tenant-dev", "global"]
    blocker = r3.quota_layers[0]
    assert blocker.allowed is False and blocker.used == 2 and blocker.threshold == 2
    # 短路后的层明确标记"未判定"，但静态阈值仍可展示
    assert all(l.allowed is None for l in r3.quota_layers[1:])
    assert r3.quota_layers[1].threshold == 5
    assert r3.quota_layers[2].threshold == 3


def test_layer_order_is_stable_regardless_of_definition_order():
    policies = [
        p_global(rate_limit=10),
        p_group(rate_limit=10),
        p_self(rate_limit=10),
    ]
    # 以三种打乱顺序构造，判定/展示顺序必须一致
    orders_seen = set()
    for order in (policies, list(reversed(policies)), [policies[1], policies[2], policies[0]]):
        g = guard_for(layered_doc(*order))
        r = g.evaluate(areq(), now=1.0)
        orders_seen.add(tuple(l.policy_name for l in r.quota_layers))
        g.release(r)
    assert orders_seen == {("self-alice", "tenant-dev", "global")}


def test_tie_broken_by_policy_name_deterministically():
    # 同具体度（两个组层、都命中 dev）：按名称字典序
    doc = layered_doc(
        p_group("dev", name="zzz-layer", rate_limit=10),
        p_group("dev", name="aaa-layer", rate_limit=10),
    )
    g = guard_for(doc)
    r = g.evaluate(areq(), now=1.0)
    assert [l.policy_name for l in r.quota_layers] == ["aaa-layer", "zzz-layer"]
    g.release(r)


def test_middle_group_layer_blocks_and_identifies_itself():
    doc = layered_doc(
        p_self("alice", rate_limit=100),
        p_self("bob", rate_limit=100),
        p_group(rate_limit=2),
        p_global(rate_limit=100),
    )
    g = guard_for(doc)
    # alice 占满组层 2 个名额
    for _ in range(2):
        r = g.evaluate(areq("alice"), now=1.0)
        assert r.decision is Decision.ALLOW
        g.release(r)
    # bob 同组：个人层/组层都命中，被组层拦下
    blocked = g.evaluate(areq("bob"), now=1.1)
    assert blocked.reason is DenyReason.RATE_LIMITED
    assert blocked.rate_limit.name == "tenant-dev"
    by_name = {l.policy_name: l for l in blocked.quota_layers}
    assert by_name["self-bob"].allowed is True
    assert by_name["tenant-dev"].allowed is False
    assert by_name["tenant-dev"].used == 2
    assert by_name["global"].allowed is None
    assert "tenant-dev" in blocked.detail and "group:dev@docs" in blocked.detail

    # 组层拦截后 bob 个人层的登记必须被精确撤回（不占任何一层名额）
    sk, _ = layer_scope(areq("bob"), doc.rate_limits[1])
    assert g._rate_limiter.current_count_key(  # type: ignore[attr-defined]
        ("layer-rate", "self-bob", sk), 100.0, now=1.1
    ) == 0


def test_each_layer_recovers_with_its_own_window():
    doc = layered_doc(p_self(rate_limit=1, rate_window_seconds=1.0))
    g = guard_for(doc)
    req = areq()
    first = g.evaluate(req, now=100.0)
    assert first.decision is Decision.ALLOW
    g.release(first)
    blocked = g.evaluate(req, now=100.5)
    assert blocked.reason is DenyReason.RATE_LIMITED
    # 该层窗口滑过后独立恢复
    recovered = g.evaluate(req, now=101.1)
    assert recovered.decision is Decision.ALLOW
    g.release(recovered)


# ---------------------------------------------------------------------
# 2) 被拒不占名额：限流层 / 并发层 / 审计层拦截时此前各层登记精确退回
# ---------------------------------------------------------------------


def test_rate_layer_denial_does_not_consume_any_layer():
    doc = layered_doc(p_self(rate_limit=1), p_group(rate_limit=10), p_global(rate_limit=10))
    g = guard_for(doc)
    req = areq()
    first = g.evaluate(req, now=1.0)
    assert first.decision is Decision.ALLOW
    g.release(first)
    for _ in range(5):
        blocked = g.evaluate(req, now=1.5)
        assert blocked.reason is DenyReason.RATE_LIMITED
    # 被拦的是 self 层；组层与全局层在这些拒绝中一次都没有被登记
    group_p = next(p for p in doc.rate_limits if p.name == "tenant-dev")
    global_p = next(p for p in doc.rate_limits if p.name == "global")
    gk, _ = layer_scope(req, group_p)
    glob_k, _ = layer_scope(req, global_p)
    assert g._rate_limiter.current_count_key(  # type: ignore[attr-defined]
        ("layer-rate", "tenant-dev", gk), 100.0, now=1.5
    ) == 1
    assert g._rate_limiter.current_count_key(  # type: ignore[attr-defined]
        ("layer-rate", "global", glob_k), 100.0, now=1.5
    ) == 1


def test_concurrency_layer_denial_retracts_prior_rate_registrations():
    doc = layered_doc(
        p_self(rate_limit=100, concurrency=10),
        p_global(rate_limit=100, concurrency=1),
    )
    g = guard_for(doc)
    req = areq()
    hold = g.evaluate(req, now=1.0)
    assert hold.decision is Decision.ALLOW  # 占住 global 唯一并发槽
    blocked = g.evaluate(req, now=1.1)
    assert blocked.reason is DenyReason.CONCURRENCY_LIMITED
    self_p = doc.rate_limits[0]
    sk, _ = layer_scope(req, self_p)
    # self 层此前的限流登记必须已撤回，只剩 hold 的一次
    assert g._rate_limiter.current_count_key(  # type: ignore[attr-defined]
        ("layer-rate", "self-alice", sk), 100.0, now=1.1
    ) == 1
    g.release(hold)


def test_concurrency_layer_denial_releases_prior_layer_slots():
    doc = layered_doc(
        p_self(rate_limit=100, concurrency=1),
        p_group(rate_limit=100, concurrency=1),
        p_global(rate_limit=100, concurrency=1),
    )
    g = guard_for(doc)
    req = areq()
    hold = g.evaluate(req, now=1.0)
    assert hold.decision is Decision.ALLOW  # 三层槽各占一个
    blocked = g.evaluate(req, now=1.1)
    assert blocked.reason is DenyReason.CONCURRENCY_LIMITED
    g.release(hold)
    # 全部释放后三层并发都可再次完整进入
    again = g.evaluate(req, now=1.2)
    assert again.decision is Decision.ALLOW
    assert [l.in_flight for l in again.quota_layers] == [1, 1, 1]
    g.release(again)


def test_fail_closed_audit_denial_rolls_back_all_layers():
    from zero_trust_admission.audit import FailingAuditSink

    doc = layered_doc(p_self(rate_limit=10), p_global(rate_limit=10))
    g = AdmissionGuard(PolicyStore(doc), FailingAuditSink())
    req = areq()
    for _ in range(3):
        result = g.evaluate(req, now=1.0)
        assert result.reason is DenyReason.AUDIT_UNAVAILABLE
    self_p = doc.rate_limits[0]
    glob_p = doc.rate_limits[1]
    sk, _ = layer_scope(req, self_p)
    gk, _ = layer_scope(req, glob_p)
    # 三次审计拒绝后没有任何一层留下计数或占用槽位
    assert g._rate_limiter.current_count_key(  # type: ignore[attr-defined]
        ("layer-rate", "self-alice", sk), 100.0, now=1.0
    ) == 0
    assert g._rate_limiter.current_count_key(  # type: ignore[attr-defined]
        ("layer-rate", "global", gk), 100.0, now=1.0
    ) == 0


def test_no_matching_layer_still_allows_in_layered_mode():
    doc = layered_doc(
        RateLimitPolicy(
            "other-only", ("*",), (), ("other",), rate_limit=1, rate_window_seconds=1.0
        )
    )
    g = guard_for(doc)
    result = g.evaluate(areq(resource="docs"), now=1.0)
    assert result.decision is Decision.ALLOW
    assert result.quota_layers == ()
    g.release(result)


def test_concurrency_only_layer_does_not_require_rate_limit():
    doc = layered_doc(
        RateLimitPolicy("cap", ("*",), (), ("docs",), concurrency=1),
    )
    g = guard_for(doc)
    req = areq()
    hold = g.evaluate(req, now=1.0)
    assert hold.decision is Decision.ALLOW
    layer = hold.quota_layers[0]
    assert layer.used == 0 and layer.threshold is None
    assert layer.in_flight == 1 and layer.concurrency == 1
    blocked = g.evaluate(req, now=1.1)
    assert blocked.reason is DenyReason.CONCURRENCY_LIMITED
    assert blocked.quota_layers[0].in_flight == 1
    g.release(hold)


def test_identity_layer_is_isolated_per_resource():
    doc = PolicyDocument(
        schema_version="1.0",
        quota_mode="layered",
        rules=(ALLOW_ALL,),
        rate_limits=(
            RateLimitPolicy("self-a-docs", ("alice",), (), ("docs",),
                            rate_limit=1, rate_window_seconds=100.0),
            RateLimitPolicy("self-a-reports", ("alice",), (), ("reports",),
                            rate_limit=1, rate_window_seconds=100.0),
        ),
    )
    g = guard_for(doc)
    docs = areq(resource="docs")
    reports = areq(resource="reports")
    r1 = g.evaluate(docs, now=1.0)
    r2 = g.evaluate(reports, now=1.0)
    assert r1.decision is Decision.ALLOW and r2.decision is Decision.ALLOW
    g.release(r1)
    g.release(r2)
    # 两资源各自打满，不互相串
    assert g.evaluate(docs, now=1.1).reason is DenyReason.RATE_LIMITED
    assert g.evaluate(reports, now=1.1).reason is DenyReason.RATE_LIMITED
