"""准入编排：拒绝原因可区分、审计与判定一致、下游异常确定性释放。"""

from __future__ import annotations

import pytest

from zero_trust_admission.admission import AdmissionGuard
from zero_trust_admission.audit import (
    AuditFailureMode,
    FailingAuditSink,
    InMemoryAuditSink,
)
from zero_trust_admission.model import (
    AccessRequest,
    Action,
    Decision,
    DenyReason,
    Principal,
)
from zero_trust_admission.policy_store import PolicyStore


def ar(identity, action=Action.READ, resource="docs", groups=()):
    return AccessRequest(Principal(identity, groups), resource, action)


def test_zero_trust_default_deny_with_baseline(guard, caplog):
    # 默认策略含 deny-all 基线：未知身份得到可区分的显式拒绝
    result = guard.evaluate(ar("stranger"))
    assert result.decision is Decision.DENY
    assert result.reason is DenyReason.EXPLICIT_DENY
    assert result.matched_rule.rule_name == "deny-all-default"
    assert "准入判定输入" in caplog.text
    assert "准入判定依据" in caplog.text


def test_no_matching_policy_when_no_rule_covers_request():
    # 没有基线规则、也没有任何规则覆盖该资源 -> 零信任默认拒绝
    from zero_trust_admission.model import Effect, PolicyDocument, Rule

    narrow = PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="only-secret",
                effect=Effect.ALLOW,
                identities=("alice",),
                groups=(),
                resources=("secret"),
                actions=("read",),
                priority=1,
            ),
        ),
    )
    g = AdmissionGuard(PolicyStore(narrow), InMemoryAuditSink())
    result = g.evaluate(ar("alice", resource="other"))
    assert result.decision is Decision.DENY
    assert result.reason is DenyReason.NO_MATCHING_POLICY
    assert result.matched_rule is None


def test_group_membership_allows_dev_read(guard, bob):
    # bob 仅通过 dev 组成员身份命中 allow-dev-read
    result = guard.evaluate(ar("bob", groups=("dev",)))
    assert result.decision is Decision.ALLOW
    assert result.matched_rule.rule_name == "allow-dev-read"


def test_alice_hits_higher_priority_write_rule(guard, alice):
    result = guard.evaluate(ar("alice", groups=("dev",)))
    assert result.decision is Decision.ALLOW
    assert result.matched_rule.rule_name == "allow-alice-write"


def test_explicit_deny_has_distinct_reason(guard, alice):
    result = guard.evaluate(ar("alice", Action.DELETE))
    assert result.decision is Decision.DENY
    assert result.reason is DenyReason.EXPLICIT_DENY
    assert result.matched_rule.rule_name == "deny-delete"


def test_deny_reasons_are_all_distinct_strings(guard, alice):
    seen = set()

    # 1) 显式拒绝
    result = guard.evaluate(ar("alice", Action.DELETE))
    assert result.reason is DenyReason.EXPLICIT_DENY
    seen.add(result.reason.value)

    # 2) 限流拒绝：rl-alice rate=2/window=1，放行两次后第三次必被拒
    request = ar("alice", groups=("dev",))
    first = guard.evaluate(request, now=0.0)
    assert first.decision is Decision.ALLOW
    guard.release(first)
    second = guard.evaluate(request, now=0.1)
    assert second.decision is Decision.ALLOW
    guard.release(second)
    third = guard.evaluate(request, now=0.2)
    assert third.reason is DenyReason.RATE_LIMITED
    seen.add(third.reason.value)

    # 3) 并发拒绝：重置 guard 以清空限流窗口
    fresh = AdmissionGuard(
        PolicyStore(guard._store.current()), InMemoryAuditSink()
    )
    hold = fresh.evaluate(request, now=10.0)
    assert hold.decision is Decision.ALLOW
    blocked = fresh.evaluate(request, now=10.1)
    assert blocked.reason is DenyReason.CONCURRENCY_LIMITED
    seen.add(blocked.reason.value)
    fresh.release(hold)

    # 4) 无规则覆盖（窄策略）
    from zero_trust_admission.model import Effect, PolicyDocument, Rule

    narrow = PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="only-secret",
                effect=Effect.ALLOW,
                identities=("alice",),
                groups=(),
                resources=("secret"),
                actions=("read",),
            ),
        ),
    )
    g2 = AdmissionGuard(PolicyStore(narrow), InMemoryAuditSink())
    no_match = g2.evaluate(ar("alice", resource="other"))
    assert no_match.reason is DenyReason.NO_MATCHING_POLICY
    seen.add(no_match.reason.value)

    assert seen == {
        "no_matching_policy",
        "explicit_deny",
        "rate_limited",
        "concurrency_limited",
    }


def test_rate_limited_request_does_not_consume_quota(guard, alice):
    p = ar("alice", groups=("dev",))
    r1 = guard.evaluate(p, now=0.0)
    assert r1.decision is Decision.ALLOW  # rl-alice: rate=2, concurrency=1
    # 并发槽已满 -> 并发拒绝并回滚限流登记
    r2 = guard.evaluate(p, now=0.1)
    assert r2.reason is DenyReason.CONCURRENCY_LIMITED
    guard.release(r1)
    # 回滚生效：此时第二次尝试仍能成功（配额没有被并发拒绝误占）
    r3 = guard.evaluate(p, now=0.2)
    assert r3.decision is Decision.ALLOW, r3
    guard.release(r3)
    # 两次放行后第三次撞限流
    r4 = guard.evaluate(p, now=0.3)
    assert r4.reason is DenyReason.RATE_LIMITED, r4


def test_every_decision_has_audit_record_consistent_with_result(guard, alice, bob):
    guard.evaluate(ar("stranger"))
    allow = guard.evaluate(ar("bob", groups=("dev",)), now=1.0)
    guard.release(allow)
    records = guard._sink.records  # type: ignore[attr-defined]
    assert len(records) == 2
    by_decision = {r.decision: r for r in records}
    assert by_decision[Decision.DENY].reason is DenyReason.EXPLICIT_DENY
    assert by_decision[Decision.ALLOW].matched_rule_name == "allow-dev-read"
    assert by_decision[Decision.ALLOW].reason is None


def test_fail_closed_when_audit_unavailable(store):
    failing = FailingAuditSink()
    g = AdmissionGuard(store, failing)  # 默认 fail_closed
    result = g.evaluate(ar("bob", groups=("dev",)))
    assert result.decision is Decision.DENY
    assert result.reason is DenyReason.AUDIT_UNAVAILABLE
    assert g.audit_stats()["audit_write_failures"] == 1


def test_fail_closed_releases_concurrency_slot(store):
    failing = FailingAuditSink()
    g = AdmissionGuard(store, failing)
    # bob 走 rl-global concurrency=2；拒绝后槽位必须被释放
    for _ in range(3):
        result = g.evaluate(ar("bob", groups=("dev",)))
        assert result.reason is DenyReason.AUDIT_UNAVAILABLE
    # 并发未被占满（否则会先出现 concurrency_limited），证明已释放


def test_fail_open_explicitly_allows_and_buffers(store):
    failing = FailingAuditSink()
    g = AdmissionGuard(store, failing, audit_failure_mode=AuditFailureMode.FAIL_OPEN)
    result = g.evaluate(ar("bob", groups=("dev",)), now=1.0)
    assert result.decision is Decision.ALLOW
    assert g.audit_stats()["audit_write_failures"] == 1
    assert len(g.buffered_records()) == 1
    # 显式降级必须可解释
    assert "fail_open" in result.detail or g.failure_mode == "fail_open"


def test_invalid_failure_mode_rejected(store):
    with pytest.raises(ValueError):
        AdmissionGuard(store, InMemoryAuditSink(), audit_failure_mode="nope")


def test_downstream_error_recorded_and_slot_released(guard, bob):
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        raise ConnectionError("upstream timeout")

    request = ar("bob", groups=("dev",))
    outcome = guard.execute_guarded(request, flaky, now=5.0)
    assert outcome.value is None
    assert outcome.downstream_error == "ConnectionError: upstream timeout"
    assert outcome.result.decision is Decision.ALLOW  # 准入本身允许
    records = guard._sink.records  # type: ignore[attr-defined]
    assert [r.phase for r in records] == ["admission", "downstream"]
    assert records[-1].downstream_error == "ConnectionError: upstream timeout"
    assert records[0].decision is Decision.ALLOW
    assert guard.audit_stats()["downstream_errors"] == 1

    # 异常后并发槽确定性释放：后续请求可正常进入
    outcome2 = guard.execute_guarded(request, lambda: "ok", now=5.1)
    assert outcome2.value == "ok"
    assert outcome2.downstream_error is None


def test_denied_request_never_reaches_downstream(guard):
    reached = []
    outcome = guard.execute_guarded(
        ar("stranger"), lambda: reached.append(1) or "ok"
    )
    assert outcome.result.decision is Decision.DENY
    assert reached == []
    assert outcome.downstream_error is None


def test_policy_replace_takes_effect_atomically(guard, store):
    # 新策略：只允许 zoe，替换后 bob 立即被拒、zoe 立即放行
    new_doc_text = """
    {
      "schema_version": "1.0",
      "rules": [
        {"name": "deny", "effect": "deny", "identities": ["*"],
         "groups": [], "resources": ["*"], "actions": ["*"], "priority": 0},
        {"name": "zoe", "effect": "allow", "identities": ["zoe"],
         "groups": [], "resources": ["docs"], "actions": ["read"], "priority": 1}
      ]
    }
    """
    before = guard.evaluate(ar("bob", groups=("dev",)), now=9.0)
    assert before.decision is Decision.ALLOW
    guard.release(before)
    store.load_json(new_doc_text)
    result = guard.evaluate(ar("bob", groups=("dev",)), now=9.1)
    assert result.decision is Decision.DENY
    zoe = guard.evaluate(ar("zoe"), now=9.2)
    assert zoe.decision is Decision.ALLOW
