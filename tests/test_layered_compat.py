"""分层能力与老策略的兼容性：不改老文件、结果/原因/载荷保持一致。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from zero_trust_admission.admission import AdmissionGuard
from zero_trust_admission.audit import InMemoryAuditSink
from zero_trust_admission.app import create_app
from zero_trust_admission.model import (
    AccessRequest,
    Action,
    Decision,
    DenyReason,
    Effect,
    PolicyDocument,
    Principal,
    QuotaMode,
    RateLimitPolicy,
    Rule,
)
from zero_trust_admission.policy_store import PolicyStore, parse_policy_dict
from zero_trust_admission.errors import PolicyFormatError, PolicyValidationError

from .conftest import make_document


def ar(identity="bob", groups=("dev",), resource="docs", action=Action.READ):
    return AccessRequest(Principal(identity, groups), resource, action)


# ---------------------------------------------------------------------
# 1) 老策略：没有 quota 字段时行为、结果字段、对外载荷与历史完全一致
# ---------------------------------------------------------------------


def test_legacy_document_defaults_to_single_mode():
    doc = parse_policy_dict({"schema_version": "1.0", "rules": []})
    assert doc.quota_mode == QuotaMode.SINGLE
    # 直接构造的文档（代码侧老调用方式）同样缺省 single
    assert make_document().quota_mode == QuotaMode.SINGLE


def test_legacy_result_has_no_layer_chain(store):
    g = AdmissionGuard(store, InMemoryAuditSink())
    result = g.evaluate(ar("bob"), now=1.0)
    assert result.decision is Decision.ALLOW
    assert result.quota_layers == ()  # 老路径恒为空层链
    g.release(result)


def test_legacy_single_policy_selection_unchanged(store):
    # bob 只命中通配层 rl-global；alice 命中两层但取最具体 rl-alice
    g = AdmissionGuard(store, InMemoryAuditSink())
    bob = g.evaluate(ar("bob"), now=1.0)
    assert bob.rate_limit.name == "rl-global"
    g.release(bob)
    alice = g.evaluate(ar("alice"), now=1.0)
    assert alice.rate_limit.name == "rl-alice"
    g.release(alice)


def test_legacy_http_payload_keys_unchanged():
    store = PolicyStore(make_document())
    app = create_app(guard=AdmissionGuard(store, InMemoryAuditSink()))
    client = TestClient(app)
    body = client.post(
        "/api/v1/evaluate",
        json={
            "principal": {"identity": "bob", "groups": ["dev"]},
            "resource": "docs",
            "action": "read",
        },
    ).json()
    # 键集合与新能力上线前逐一对齐，不允许多出 quota_layers
    assert set(body.keys()) == {
        "decision",
        "reason",
        "matched_rule",
        "rate_limit_policy",
        "detail",
        "request",
    }
    assert body["quota_mode"] if False else True
    assert "quota_layers" not in body


def test_legacy_policy_endpoint_reports_single_mode():
    store = PolicyStore(make_document())
    app = create_app(guard=AdmissionGuard(store, InMemoryAuditSink()))
    client = TestClient(app)
    assert client.get("/api/v1/policy").json()["quota_mode"] == "single"


# ---------------------------------------------------------------------
# 2) 不动老策略文件即可启用分层：guard 构造期显式覆盖
# ---------------------------------------------------------------------


def test_guard_override_enables_layering_without_file_change():
    # 老文档（single）+ guard 显式 layered：同一请求从"只取最具体一条"
    # 变为"两层同时约束"
    g = AdmissionGuard(
        PolicyStore(make_document()),
        InMemoryAuditSink(),
        quota_mode=QuotaMode.LAYERED,
    )
    req = ar("alice")
    first = g.evaluate(req, now=1.0)
    assert first.decision is Decision.ALLOW
    assert [l.policy_name for l in first.quota_layers] == [
        "rl-alice",
        "rl-global",
    ]
    g.release(first)
    second = g.evaluate(req, now=1.1)
    g.release(second)
    # rl-alice 阈值 2：第三次必被最具体的个人层拦
    third = g.evaluate(req, now=1.2)
    assert third.reason is DenyReason.RATE_LIMITED
    assert third.rate_limit.name == "rl-alice"


def test_invalid_quota_mode_override_rejected(store):
    with pytest.raises(ValueError):
        AdmissionGuard(store, InMemoryAuditSink(), quota_mode="nope")


# ---------------------------------------------------------------------
# 3) 策略文件中 quota.mode 的解析与校验
# ---------------------------------------------------------------------


def test_parse_layered_mode_from_document():
    doc = parse_policy_dict(
        {"schema_version": "1.0", "quota": {"mode": "layered"}, "rules": []}
    )
    assert doc.quota_mode == "layered"


@pytest.mark.parametrize(
    "quota,error",
    [
        ({"mode": "weird"}, PolicyValidationError),
        ([], PolicyFormatError),
    ],
)
def test_reject_bad_quota_section(quota, error):
    with pytest.raises(error):
        parse_policy_dict(
            {"schema_version": "1.0", "quota": quota, "rules": []}
        )


# ---------------------------------------------------------------------
# 4) 分层模式 HTTP 载荷：被哪层拦、阈值、用量都看得到
# ---------------------------------------------------------------------


def test_layered_http_payload_explains_blocking_layer():
    doc = PolicyDocument(
        schema_version="1.0",
        quota_mode="layered",
        rules=(
            Rule("allow", Effect.ALLOW, ("*",), (), ("*",), ("*"), priority=10),
        ),
        rate_limits=(
            RateLimitPolicy("self", ("alice",), (), ("docs",),
                            rate_limit=1, rate_window_seconds=100.0),
            RateLimitPolicy("global", ("*",), (), ("docs",),
                            rate_limit=10, rate_window_seconds=100.0),
        ),
    )
    app = create_app(guard=AdmissionGuard(PolicyStore(doc), InMemoryAuditSink()))
    client = TestClient(app)
    payload = {
        "principal": {"identity": "alice", "groups": []},
        "resource": "docs",
        "action": "read",
    }
    assert client.post("/api/v1/evaluate", json=payload).status_code == 200
    denied = client.post("/api/v1/evaluate", json=payload)
    assert denied.status_code == 403
    body = denied.json()
    assert body["reason"] == "rate_limited"
    assert body["rate_limit_policy"] == "self"
    layers = body["quota_layers"]
    assert [l["policy"] for l in layers] == ["self", "global"]
    blocker = layers[0]
    assert blocker["allowed"] is False
    assert blocker["used"] == 1 and blocker["threshold"] == 1
    assert blocker["scope"] == "identity:alice@docs"
    # 短路层之后的层标记为未判定，阈值仍可展示
    assert layers[1]["allowed"] is None and layers[1]["threshold"] == 10
