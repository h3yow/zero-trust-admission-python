"""HTTP 层测试：行为兼容、身份头解析、可区分拒绝码、策略热更新。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from admission.audit import InMemoryAuditor
from admission.config import load_default_policy
from admission.engine import AdmissionEngine
from admission.store import PolicyStore
from main import app


@pytest.fixture
def client() -> TestClient:
    """每个用例使用全新的策略仓库/限流器/审计，互不污染。"""
    store = PolicyStore()
    load_default_policy(store)
    auditor = InMemoryAuditor()
    app.state.engine = AdmissionEngine(store=store, auditor=auditor)
    app.state.auditor = auditor
    return TestClient(app)


def test_legacy_root_endpoint_unchanged(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"Hello": "World"}


def test_anonymous_document_access_is_denied(client: TestClient) -> None:
    r = client.get("/api/resources/documents/a")
    assert r.status_code == 403
    assert r.json()["error"]["reasonCode"] == "DENY_NO_MATCHING_RULE"


def test_allowed_and_explicit_deny_have_distinct_codes(client: TestClient) -> None:
    ok = client.get("/api/resources/documents/a", headers={"X-User": "alice"})
    assert ok.status_code == 200

    deny = client.get("/api/resources/documents/a", headers={"X-User": "mallory"})
    assert deny.status_code == 403
    assert deny.json()["error"]["reasonCode"] == "DENY_EXPLICIT_RULE"


def test_rate_limit_returns_429_with_distinct_reason_code(client: TestClient) -> None:
    headers = {"X-User": "alice", "X-Roles": "admin"}
    statuses = [
        client.get("/api/resources/documents/a", headers=headers).status_code
        for _ in range(4)
    ]
    assert statuses == [200, 200, 200, 429]
    body = client.get("/api/resources/documents/a", headers=headers).json()
    assert body["error"]["reasonCode"] == "RATE_LIMIT_EXCEEDED"


def test_downstream_failure_returns_502_and_audited(client: TestClient) -> None:
    r = client.post(
        "/api/echo",
        headers={"X-User": "root", "X-Roles": "admin"},
        json={"fail": True, "message": "hi"},
    )
    assert r.status_code == 502
    assert r.json()["error"]["reasonCode"] == "DOWNSTREAM_ERROR"
    events = client.get("/admin/audit").json()["events"]
    assert events[-1]["reason_code"] == "DOWNSTREAM_ERROR"
    assert events[-1]["stage"] == "completion"


def test_policy_put_rejects_invalid_with_400(client: TestClient) -> None:
    r = client.put("/admin/policy", json={"apiVersion": "bad"})
    assert r.status_code in (400, 409)
    assert r.json()["error"]["reasonCode"] in (
        "POLICY_INVALID",
        "POLICY_VERSION_INCOMPATIBLE",
    )


def test_policy_put_requires_consecutive_version(client: TestClient) -> None:
    current = client.get("/admin/policy").json()
    v = current["metadata"]["version"]
    doc = {
        "apiVersion": "zero-trust-admission/v1",
        "kind": "AdmissionPolicy",
        "metadata": {"name": "default", "version": v + 5},
        "rules": [],
    }
    r = client.put("/admin/policy", json=doc)
    assert r.status_code == 409
    assert r.json()["error"]["reasonCode"] == "POLICY_VERSION_INCOMPATIBLE"


def test_policy_update_takes_effect_and_old_policy_survives_failure(
    client: TestClient,
) -> None:
    # 非法更新被拒，旧策略仍生效：alice 依然能读文档
    r = client.put(
        "/admin/policy",
        json={
            "apiVersion": "zero-trust-admission/v1",
            "kind": "AdmissionPolicy",
            "metadata": {"name": "default", "version": 99},
            "rules": [{"id": "bad"}],
        },
    )
    assert r.status_code in (400, 409)
    assert (
        client.get(
            "/api/resources/documents/a", headers={"X-User": "alice"}
        ).status_code
        == 200
    )

    # 合法的 v2：只保留 admin 角色（不再具名允许 alice）
    doc = {
        "apiVersion": "zero-trust-admission/v1",
        "kind": "AdmissionPolicy",
        "metadata": {"name": "default", "version": 2},
        "rules": [
            {
                "id": "docs-admin-only",
                "effect": "allow",
                "subject": {"roles": ["admin"]},
                "resource": {"type": "document", "patterns": ["docs/*"]},
                "action": {"methods": ["GET"]},
            }
        ],
    }
    r = client.put("/admin/policy?expected_current_version=1", json=doc)
    assert r.status_code == 200, r.json()
    # v1 中 alice 是具名允许；v2 只认 admin 角色 -> alice 默认拒绝
    assert (
        client.get(
            "/api/resources/documents/a", headers={"X-User": "alice"}
        ).status_code
        == 403
    )
    assert (
        client.get(
            "/api/resources/documents/a", headers={"X-User": "bob", "X-Roles": "admin"}
        ).status_code
        == 200
    )


def test_conflicting_policy_is_rejected_with_distinct_code(client: TestClient) -> None:
    doc = {
        "apiVersion": "zero-trust-admission/v1",
        "kind": "AdmissionPolicy",
        "metadata": {"name": "default", "version": 2},
        "rules": [
            {
                "id": "conflict-1",
                "effect": "deny",  # 与 v1 同选择器但 effect 相反
                "subject": {"roles": ["admin"], "users": ["alice"]},
                "resource": {"type": "document", "patterns": ["docs/*"]},
                "action": {"methods": ["GET"]},
            }
        ],
    }
    r = client.put("/admin/policy", json=doc)
    assert r.status_code == 409
    assert r.json()["error"]["reasonCode"] == "POLICY_CONFLICT"


def test_audit_events_align_with_decisions(client: TestClient) -> None:
    client.get(
        "/api/resources/documents/a",
        headers={"X-User": "alice", "X-Request-ID": "trace-1"},
    )
    client.get(
        "/api/resources/documents/a",
        headers={"X-User": "nobody", "X-Request-ID": "trace-2"},
    )
    events = client.get("/admin/audit").json()["events"]
    by_req: dict[str, list] = {}
    for e in events:
        by_req.setdefault(e["request_id"], []).append(e)
    assert by_req["trace-1"][-1]["outcome"] == "allowed"
    assert by_req["trace-2"][0]["outcome"] == "denied"
    assert by_req["trace-2"][0]["reason_code"] == "DENY_NO_MATCHING_RULE"


def test_mixed_identity_concurrent_burst_is_isolated(client: TestClient) -> None:
    """多身份混合突发：各自身份独立计数，超限可区分，正常流量不误伤。"""
    import threading

    outcomes: dict[str, list] = {"a": [], "b": []}
    lock = threading.Lock()

    def hit_role(user: str, roles: str, bucket: str) -> None:
        r = client.get(
            "/api/resources/documents/a", headers={"X-User": user, "X-Roles": roles}
        )
        with lock:
            outcomes[bucket].append(r.status_code)

    threads = [
        threading.Thread(target=hit_role, args=("alice", "", "a")) for _ in range(8)
    ]
    threads += [
        threading.Thread(target=hit_role, args=("bob", "admin", "b")) for _ in range(2)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sorted(outcomes["a"]).count(200) == 3
    assert sorted(outcomes["a"]).count(429) == 5
    assert outcomes["b"] == [200, 200]  # bob 未被 alice 的突发误伤
