"""策略解析、版本兼容与冲突检测测试。"""

from __future__ import annotations

import pytest
from conftest import make_policy_doc

from admission.errors import (
    PolicyConflictError,
    PolicyValidationError,
    PolicyVersionError,
)
from admission.model import Effect
from admission.parser import check_conflict, check_version_sequence, parse_policy

ALLOW_RULE = {
    "id": "r1",
    "description": "test rule",
    "effect": "allow",
    "subject": {"users": ["alice"], "roles": ["admin"]},
    "resource": {"type": "document", "patterns": ["docs/*"]},
    "action": {"methods": ["get"]},
    "rateLimit": {"maxRequests": 2, "windowSeconds": 1},
    "concurrencyLimit": {"maxInFlight": 1},
}


def test_parse_valid_policy_normalizes_method_case() -> None:
    policy = parse_policy(make_policy_doc(rules=[dict(ALLOW_RULE)]))
    assert policy.version == 1
    rule = policy.rules[0]
    assert rule.effect is Effect.ALLOW
    assert "GET" in rule.action.methods
    assert rule.rate_limit is not None and rule.rate_limit.max_requests == 2


def test_reject_bad_api_version_with_distinct_code() -> None:
    doc = make_policy_doc()
    doc["apiVersion"] = "zero-trust-admission/v999"
    with pytest.raises(PolicyVersionError) as ei:
        parse_policy(doc)
    assert ei.value.reason_code == "POLICY_VERSION_INCOMPATIBLE"


def test_reject_bad_kind_with_distinct_code() -> None:
    doc = make_policy_doc()
    doc["kind"] = "SomethingElse"
    with pytest.raises(PolicyVersionError) as ei:
        parse_policy(doc)
    assert ei.value.reason_code == "POLICY_VERSION_INCOMPATIBLE"


def test_reject_malformed_structure_with_distinct_code() -> None:
    bad_docs = [
        {
            "apiVersion": "zero-trust-admission/v1",
            "kind": "AdmissionPolicy",
        },  # 缺 metadata/rules
        make_policy_doc(version=0),
        make_policy_doc(rules=[{"id": "x", "effect": "allow"}]),  # 缺 resource
        make_policy_doc(rules=[{**ALLOW_RULE, "effect": "maybe"}]),
        make_policy_doc(
            rules=[{**ALLOW_RULE, "id": "a"}, {**ALLOW_RULE, "id": "a"}]
        ),  # id 重复
        make_policy_doc(
            rules=[{**ALLOW_RULE, "rateLimit": {"maxRequests": 0, "windowSeconds": 1}}]
        ),
        make_policy_doc(
            rules=[{**ALLOW_RULE, "rateLimit": {"maxRequests": 2, "windowSeconds": -1}}]
        ),
        make_policy_doc(rules=[{**ALLOW_RULE, "concurrencyLimit": {"maxInFlight": 0}}]),
        make_policy_doc(rules=[{**ALLOW_RULE, "unknownField": 1}]),
        make_policy_doc(rules=[{**ALLOW_RULE, "resource": {"type": ""}}]),
        make_policy_doc(rules=[{**ALLOW_RULE, "subject": {"what": ["x"]}}]),
    ]
    for doc in bad_docs:
        with pytest.raises(PolicyValidationError) as ei:
            parse_policy(doc)
        assert ei.value.reason_code == "POLICY_INVALID"


def test_version_must_be_incremented_by_one() -> None:
    v1 = parse_policy(make_policy_doc(version=1))
    check_version_sequence(parse_policy(make_policy_doc(version=2)), v1)  # 不抛
    with pytest.raises(PolicyVersionError):
        check_version_sequence(parse_policy(make_policy_doc(version=3)), v1)
    with pytest.raises(PolicyVersionError):
        check_version_sequence(parse_policy(make_policy_doc(version=1)), v1)


def test_conflict_same_selector_different_effect() -> None:
    allow = parse_policy(make_policy_doc(version=1, rules=[dict(ALLOW_RULE)]))
    deny_rule = {
        **ALLOW_RULE,
        "id": "r2",
        "effect": "deny",
        "rateLimit": None,
        "concurrencyLimit": None,
    }
    candidate = parse_policy(make_policy_doc(version=2, rules=[deny_rule]))
    with pytest.raises(PolicyConflictError) as ei:
        check_conflict(candidate, allow)
    assert ei.value.reason_code == "POLICY_CONFLICT"
    assert "effect" in str(ei.value)


def test_conflict_same_selector_different_limits() -> None:
    v1 = parse_policy(make_policy_doc(version=1, rules=[dict(ALLOW_RULE)]))
    changed = {
        **ALLOW_RULE,
        "id": "r2",
        "rateLimit": {"maxRequests": 99, "windowSeconds": 1},
    }
    candidate = parse_policy(make_policy_doc(version=2, rules=[changed]))
    with pytest.raises(PolicyConflictError):
        check_conflict(candidate, v1)


def test_identical_rule_is_idempotent_not_conflict() -> None:
    v1 = parse_policy(make_policy_doc(version=1, rules=[dict(ALLOW_RULE)]))
    candidate = parse_policy(make_policy_doc(version=2, rules=[dict(ALLOW_RULE)]))
    check_conflict(candidate, v1)  # 不抛
