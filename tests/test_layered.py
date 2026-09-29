"""分层配额：多层叠加、固定顺序、拦截层阈值/用量可解释。"""

from __future__ import annotations

import pytest

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
from zero_trust_admission.policy_store import PolicyStore, parse_policy_dict


def _ar(identity="alice", groups=("dev",), resource="docs", action=Action.READ):
    return AccessRequest(Principal(identity, groups), resource, action)


def _layered_doc(rate_limits, *, identities=("*",)) -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="allow-all",
                effect=Effect.ALLOW,
                identities=identities,
                groups=(),
                resources=("*",),
                actions=("*",),
                priority=0,
            ),
        ),
        rate_limits=tuple(rate_limits),
        rate_limit_mode="layered",
    )


def _guard(doc: PolicyDocument) -> AdmissionGuard:
    return AdmissionGuard(PolicyStore(doc), InMemoryAuditSink())


def test_all_layers_must_pass_and_order_is_specificity_then_declaration():
    # 声明顺序刻意打乱：global 写在最前、self 写在最后；
    # 判定顺序仍必须是 self(身份) -> group(组) -> global(全局)
    doc = _layered_doc(
        [
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 100, 10.0),
            RateLimitPolicy("rl-group", ("*",), ("dev",), ("docs",), 100, 10.0),
            RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 100, 10.0),
        ]
    )
    guard = _guard(doc)
    result = guard.evaluate(_ar(), now=0.0)
    assert result.decision is Decision.ALLOW
    names = [c.policy_name for c in result.rate_layers]
    assert names == ["rl-self", "rl-group", "rl-global"]
    assert [c.order for c in result.rate_layers] == [0, 1, 2]
    assert all(c.allowed for c in result.rate_layers)
    guard.release(result)


def test_equal_specificity_uses_declaration_order_not_name_order():
    # 两个都是全局层（特异性相同），名字字典序与声明顺序相反时，
    # 顺序必须服从声明顺序，改名字不影响顺序
    doc = _layered_doc(
        [
            RateLimitPolicy("zzz-first", ("*",), (), ("docs",), 100, 10.0),
            RateLimitPolicy("aaa-second", ("*",), (), ("docs",), 100, 10.0),
        ]
    )
    guard = _guard(doc)
    result = guard.evaluate(_ar(), now=0.0)
    assert [c.policy_name for c in result.rate_layers] == [
        "zzz-first",
        "aaa-second",
    ]
    guard.release(result)


def test_self_layer_blocks_and_exposes_threshold_and_count():
    doc = _layered_doc(
        [
            RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 2, 10.0),
            RateLimitPolicy("rl-group", ("*",), ("dev",), ("docs",), 100, 10.0),
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 100, 10.0),
        ]
    )
    guard = _guard(doc)
    for i in range(2):
        r = guard.evaluate(_ar(), now=float(i) / 10)
        assert r.decision is Decision.ALLOW
        guard.release(r)
    blocked = guard.evaluate(_ar(), now=0.3)
    assert blocked.decision is Decision.DENY
    assert blocked.reason is DenyReason.RATE_LIMITED
    assert blocked.rate_limit.name == "rl-self"  # 老字段指向拦截层
    layers = {c.policy_name: c for c in blocked.rate_layers}
    self_layer = layers["rl-self"]
    assert self_layer.allowed is False
    assert self_layer.denied_at == "rate_limit"
    assert self_layer.rate_threshold == 2
    assert self_layer.rate_count == 2  # 拦截时窗口用量精确可见
    # 短路层标记固定且可解释
    assert layers["rl-group"].denied_at == "short_circuit"
    assert layers["rl-global"].denied_at == "short_circuit"
    assert blocked.detail.startswith("窗口内请求数 2 已达限流阈值 2")


def test_group_layer_blocks_and_self_registration_is_rolled_back():
    # self 阈值很高，group 阈值 2：被 group 拦时 self 层名额必须精确退回
    doc = _layered_doc(
        [
            RateLimitPolicy("rl-self", ("alice", "bob", "carol"), (), ("docs",), 100, 10.0),
            RateLimitPolicy("rl-group", ("*",), ("dev",), ("docs",), 2, 10.0),
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 1000, 10.0),
        ]
    )
    guard = _guard(doc)
    for i, ident in enumerate(("alice", "bob")):
        r = guard.evaluate(_ar(ident), now=float(i) / 10)
        assert r.decision is Decision.ALLOW
        guard.release(r)
    blocked = guard.evaluate(_ar("carol"), now=0.3)
    assert blocked.reason is DenyReason.RATE_LIMITED
    assert blocked.rate_limit.name == "rl-group"
    group_layer = next(c for c in blocked.rate_layers if c.policy_name == "rl-group")
    assert (group_layer.rate_count, group_layer.rate_threshold) == (2, 2)
    # 被拒请求未在 self 层留下名额
    assert (
        guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
            "rl-self", "identity", "carol", "docs", 10.0, now=0.4
        )
        == 0
    )
    # 组桶只统计了前两次成功，未被 carol 的被拒请求污染
    assert (
        guard._rate_limiter.current_layer_count(  # type: ignore[attr-defined]
            "rl-group", "group", "dev", "docs", 10.0, now=0.4
        )
        == 2
    )


def test_concurrency_layer_blocks_and_prior_layer_slots_are_released():
    doc = _layered_doc(
        [
            RateLimitPolicy(
                "rl-self", ("alice",), (), ("docs",), 1000, 10.0, concurrency=100
            ),
            RateLimitPolicy(
                "rl-global", ("*",), (), ("docs",), 1000, 10.0, concurrency=1
            ),
        ]
    )
    guard = _guard(doc)
    hold = guard.evaluate(_ar(), now=0.0)
    assert hold.decision is Decision.ALLOW
    blocked = guard.evaluate(_ar(), now=0.1)
    assert blocked.reason is DenyReason.CONCURRENCY_LIMITED
    assert blocked.rate_limit.name == "rl-global"
    gl = next(c for c in blocked.rate_layers if c.policy_name == "rl-global")
    assert gl.denied_at == "concurrency"
    assert gl.concurrency_active == 1
    assert gl.concurrency_limit == 1
    # 被拒请求在 self 层占的并发槽已退回：只剩 hold 持有的 1 个
    self_policy = doc.rate_limits[0]
    assert guard._concurrency.active_layer(_ar(), self_policy) == 1  # type: ignore[attr-defined]
    guard.release(hold)
    again = guard.evaluate(_ar(), now=0.2)
    assert again.decision is Decision.ALLOW
    guard.release(again)


def test_layered_mode_is_opt_in_via_document_field():
    # 不带 rate_limit_mode（默认 most_specific）：老行为，只命中最具体一条
    data = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "allow-all",
                "effect": "allow",
                "identities": ["*"],
                "groups": [],
                "resources": ["*"],
                "actions": ["*"],
            }
        ],
        "rate_limits": [
            {
                "name": "rl-global",
                "identities": ["*"],
                "groups": [],
                "resources": ["docs"],
                "rate_limit": 100,
                "rate_window_seconds": 10,
            },
            {
                "name": "rl-self",
                "identities": ["alice"],
                "groups": [],
                "resources": ["docs"],
                "rate_limit": 1,
                "rate_window_seconds": 10,
            },
        ],
    }
    doc = parse_policy_dict(data)
    assert doc.rate_limit_mode == "most_specific"
    guard = _guard(doc)
    r1 = guard.evaluate(_ar(), now=0.0)
    assert r1.decision is Decision.ALLOW
    assert r1.rate_layers == ()  # 老模式不产生分层明细
    guard.release(r1)
    r2 = guard.evaluate(_ar(), now=0.1)
    assert r2.reason is DenyReason.RATE_LIMITED
    assert r2.rate_limit.name == "rl-self"
    assert r2.rate_layers == ()
    # 老模式下 self 满了不影响 global 独立桶（各走各的老键）
    bob = guard.evaluate(_ar("bob", groups=()), now=0.2)
    assert bob.decision is Decision.ALLOW
    guard.release(bob)


def test_invalid_rate_limit_mode_rejected():
    with pytest.raises(Exception):
        parse_policy_dict(
            {
                "schema_version": "1.0",
                "rules": [],
                "rate_limit_mode": "nope",
            }
        )


def test_layered_records_appear_in_audit_jsonl():
    import dataclasses

    doc = _layered_doc(
        [RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 1, 10.0)]
    )
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(PolicyStore(doc), sink)
    r1 = guard.evaluate(_ar(), now=0.0)
    guard.release(r1)
    r2 = guard.evaluate(_ar(), now=0.1)
    assert r2.reason is DenyReason.RATE_LIMITED
    deny_record = [r for r in sink.records if r.decision is Decision.DENY][0]
    assert deny_record.rate_limit_name == "rl-self"
    layer = deny_record.rate_layers[0]
    assert dataclasses.asdict(layer)["rate_count"] == 1
    assert dataclasses.asdict(layer)["rate_threshold"] == 1


def test_legacy_most_specific_path_response_and_audit_unchanged(tmp_path):
    """老策略（不写 rate_limit_mode）对外结果、拒绝原因、审计结构与以前一致。"""
    import json

    from zero_trust_admission.audit import JsonlAuditSink

    doc = PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="allow-all",
                effect=Effect.ALLOW,
                identities=("*",),
                groups=(),
                resources=("*",),
                actions=("*",),
            ),
        ),
        rate_limits=(
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 100, 10.0),
            RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 1, 10.0),
        ),
        # 刻意不传 rate_limit_mode
    )
    assert doc.rate_limit_mode == "most_specific"

    path = str(tmp_path / "compat_audit.jsonl")
    sink = JsonlAuditSink(path)
    guard = AdmissionGuard(PolicyStore(doc), sink)
    r1 = guard.evaluate(_ar(), now=0.0)
    assert r1.decision is Decision.ALLOW
    assert r1.rate_limit.name == "rl-self"  # 只取最具体一条
    assert r1.rate_layers == ()
    guard.release(r1)
    r2 = guard.evaluate(_ar(), now=0.1)
    assert r2.reason is DenyReason.RATE_LIMITED
    assert r2.rate_limit.name == "rl-self"
    sink.close()

    with open(path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    # 老审计结构不含 rate_layers 字段，字段集合与分层能力上线前一致
    assert all("rate_layers" not in line for line in lines)
    deny_line = next(line for line in lines if line["decision"] == "deny")
    assert deny_line["rate_limit_name"] == "rl-self"
    assert set(deny_line) == {
        "audit_id",
        "timestamp",
        "phase",
        "decision",
        "reason",
        "request_summary",
        "matched_rule_name",
        "rate_limit_name",
        "detail",
        "downstream_error",
    }


def test_layered_mode_in_http_payload():
    """HTTP 装配层：分层拒绝响应包含 rate_layers，老模式响应不含该字段。"""
    from fastapi.testclient import TestClient

    from zero_trust_admission.app import create_app

    doc = _layered_doc(
        [
            RateLimitPolicy("rl-self", ("alice",), (), ("docs",), 1, 10.0),
            RateLimitPolicy("rl-global", ("*",), (), ("docs",), 100, 10.0),
        ]
    )
    guard = _guard(doc)
    client = TestClient(create_app(guard=guard))
    payload = {
        "principal": {"identity": "alice", "groups": []},
        "resource": "docs",
        "action": "read",
    }
    first = client.post("/api/v1/evaluate", json=payload)
    assert first.status_code == 200
    assert "rate_layers" in first.json()
    assert [layer["policy"] for layer in first.json()["rate_layers"]] == [
        "rl-self",
        "rl-global",
    ]
    second = client.post("/api/v1/evaluate", json=payload)
    assert second.status_code == 403
    body = second.json()
    assert body["reason"] == "rate_limited"
    blocking = next(layer for layer in body["rate_layers"] if not layer["allowed"])
    assert blocking["policy"] == "rl-self"
    assert blocking["rate_count"] == 1
    assert blocking["rate_threshold"] == 1
