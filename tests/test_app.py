"""HTTP 装配层：根路由兼容、准入接口、策略热更新被拒绝时在运策略不变。"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from zero_trust_admission.admission import AdmissionGuard
from zero_trust_admission.app import create_app
from zero_trust_admission.audit import InMemoryAuditSink
from zero_trust_admission.policy_store import PolicyStore

from .conftest import make_document


@pytest.fixture
def client(tmp_path):
    store = PolicyStore(make_document())
    sink = InMemoryAuditSink()
    guard = AdmissionGuard(store, sink)
    app = create_app(guard=guard)
    return TestClient(app), guard


def test_root_route_stays_compatible(client):
    c, _ = client
    assert c.get("/").json() == {"Hello": "World"}


def test_evaluate_allow_and_deny(client):
    c, _ = client
    ok = c.post(
        "/api/v1/evaluate",
        json={
            "principal": {"identity": "bob", "groups": ["dev"]},
            "resource": "docs",
            "action": "read",
        },
    )
    assert ok.status_code == 200
    assert ok.json()["decision"] == "allow"

    denied = c.post(
        "/api/v1/evaluate",
        json={
            "principal": {"identity": "stranger", "groups": []},
            "resource": "docs",
            "action": "read",
        },
    )
    assert denied.status_code == 403
    body = denied.json()
    assert body["reason"] == "explicit_deny"
    assert body["matched_rule"] == "deny-all-default"


def test_rate_limit_endpoint_returns_distinct_reason(client):
    c, _ = client
    payload = {
        "principal": {"identity": "alice", "groups": ["dev"]},
        "resource": "docs",
        "action": "read",
    }
    statuses = [c.post("/api/v1/evaluate", json=payload).status_code for _ in range(5)]
    # alice: rate=2/s, concurrency=1，但 evaluate 探针立即释放并发槽，
    # 故仅限流生效：前 2 次 200，其余 429 语义由 403+rate_limited 表达
    assert statuses.count(200) == 2
    last = c.post("/api/v1/evaluate", json=payload).json()
    assert last["reason"] == "rate_limited"


def test_invalid_policy_rejected_without_touching_running_policy(client):
    c, guard = client
    before_rule_count = len(guard._store.current().rules)

    bad_version = c.put("/api/v1/policy", json={"schema_version": "2.0", "rules": []})
    assert bad_version.status_code == 422
    assert bad_version.json()["error_code"] == "policy_version_incompatible"

    bad_conflict = c.put(
        "/api/v1/policy",
        json={
            "schema_version": "1.0",
            "rules": [
                {
                    "name": "a",
                    "effect": "allow",
                    "identities": ["*"],
                    "resources": ["*"],
                    "actions": ["*"],
                },
                {
                    "name": "b",
                    "effect": "deny",
                    "identities": ["*"],
                    "resources": ["*"],
                    "actions": ["*"],
                },
            ],
        },
    )
    assert bad_conflict.status_code == 422
    assert bad_conflict.json()["error_code"] == "policy_conflict"

    assert len(guard._store.current().rules) == before_rule_count


def test_policy_replace_takes_effect(client):
    c, _ = client
    new_policy = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "only-zoe",
                "effect": "allow",
                "identities": ["zoe"],
                "groups": [],
                "resources": ["docs"],
                "actions": ["read"],
            }
        ],
    }
    assert c.put("/api/v1/policy", json=new_policy).status_code == 200
    allowed = c.post(
        "/api/v1/evaluate",
        json={
            "principal": {"identity": "zoe"},
            "resource": "docs",
            "action": "read",
        },
    )
    assert allowed.status_code == 200
    denied = c.post(
        "/api/v1/evaluate",
        json={
            "principal": {"identity": "bob", "groups": ["dev"]},
            "resource": "docs",
            "action": "read",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["reason"] == "no_matching_policy"


def test_protected_resource_and_stats(client):
    c, _ = client
    ok = c.get("/api/v1/resources/docs", params={"identity": "alice"})
    assert ok.status_code == 200 and ok.json()["payload"] == "ok"
    denied = c.get("/api/v1/resources/secret", params={"identity": "alice"})
    assert denied.status_code == 403
    stats = c.get("/api/v1/audit/stats").json()
    assert stats["total"] >= 2


def test_jsonl_audit_sink_persists_decisions(tmp_path):
    from zero_trust_admission.audit import JsonlAuditSink
    from zero_trust_admission.model import (
        AccessRequest,
        Action,
        Decision,
        DenyReason,
        Principal,
    )

    path = os.path.join(tmp_path, "audit.log")
    store = PolicyStore(make_document())
    guard = AdmissionGuard(store, JsonlAuditSink(path))
    guard.evaluate(AccessRequest(Principal("stranger"), "docs", Action.READ))
    guard._sink.close()
    with open(path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh if line.strip()]
    assert len(lines) == 1
    assert lines[0]["decision"] == Decision.DENY.value
    assert lines[0]["reason"] == DenyReason.EXPLICIT_DENY.value
    assert lines[0]["request_summary"]["identity"] == "stranger"
