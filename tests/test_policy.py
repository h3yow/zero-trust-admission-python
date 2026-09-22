"""策略装载：非法结构、版本不兼容、冲突必须以可区分原因被拒绝。"""

from __future__ import annotations

import pytest

from zero_trust_admission.errors import (
    PolicyConflictError,
    PolicyFormatError,
    PolicySchemaVersionError,
    PolicyValidationError,
)
from zero_trust_admission.policy_store import PolicyStore, parse_policy_dict


def test_load_valid_policy(store):
    doc = store.current()
    assert doc.schema_version == "1.0"
    assert {r.name for r in doc.rules} == {
        "deny-all-default",
        "allow-dev-read",
        "allow-alice-write",
        "deny-delete",
    }


@pytest.mark.parametrize(
    "payload,expected",
    [
        ("{", PolicyFormatError),  # JSON 非法
        ([], PolicyFormatError),  # 文档不是对象
        ({"rules": []}, PolicyFormatError),  # 缺 schema_version
        ({"schema_version": 1, "rules": []}, PolicyFormatError),
        ({"schema_version": "2.0", "rules": []}, PolicySchemaVersionError),
        ({"schema_version": "0.9", "rules": []}, PolicySchemaVersionError),
    ],
)
def test_reject_bad_document(payload, expected):
    store = PolicyStore()
    import json

    text = payload if isinstance(payload, str) else json.dumps(payload)
    with pytest.raises(expected):
        store.load_json(text)


def test_reject_illegal_effect_and_action():
    bad_effect = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "x",
                "effect": "maybe",
                "identities": ["a"],
                "resources": ["r"],
                "actions": ["read"],
            }
        ],
    }
    with pytest.raises(PolicyFormatError) as ei:
        parse_policy_dict(bad_effect)
    assert ei.value.code == "policy_format_error"

    bad_action = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "x",
                "effect": "allow",
                "identities": ["a"],
                "resources": ["r"],
                "actions": ["explode"],
            }
        ],
    }
    with pytest.raises(PolicyValidationError) as ei:
        parse_policy_dict(bad_action)
    assert ei.value.code == "policy_validation_error"


def test_reject_malformed_rate_limit():
    # 窗口与阈值必须同时提供
    doc = {
        "schema_version": "1.0",
        "rate_limits": [
            {"name": "p", "identities": ["*"], "resources": ["r"], "rate_limit": 5}
        ],
    }
    with pytest.raises(PolicyValidationError):
        parse_policy_dict(doc)

    doc2 = {
        "schema_version": "1.0",
        "rate_limits": [
            {
                "name": "p",
                "identities": ["*"],
                "resources": ["r"],
                "rate_limit": 0,
                "rate_window_seconds": 1,
            }
        ],
    }
    with pytest.raises(PolicyValidationError):
        parse_policy_dict(doc2)


def test_reject_duplicate_rule_names():
    doc = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "dup",
                "effect": "allow",
                "identities": ["a"],
                "resources": ["r"],
                "actions": ["read"],
            },
            {
                "name": "dup",
                "effect": "allow",
                "identities": ["b"],
                "resources": ["r"],
                "actions": ["read"],
            },
        ],
    }
    with pytest.raises(PolicyValidationError, match="重复"):
        parse_policy_dict(doc)


def test_reject_conflicting_rules_same_priority():
    doc = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "a",
                "effect": "allow",
                "identities": ["*"],
                "resources": ["r"],
                "actions": ["*"],
                "priority": 5,
            },
            {
                "name": "b",
                "effect": "deny",
                "identities": ["*"],
                "resources": ["r"],
                "actions": ["*"],
                "priority": 5,
            },
        ],
    }
    with pytest.raises(PolicyConflictError) as ei:
        parse_policy_dict(doc)
    assert ei.value.code == "policy_conflict"
    assert "a" in str(ei.value) and "b" in str(ei.value)


def test_different_priority_does_not_conflict():
    # deny 优先级更高：对同空间是显式 deny 覆盖，这不是装载期冲突
    doc = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "low-allow",
                "effect": "allow",
                "identities": ["*"],
                "resources": ["r"],
                "actions": ["read"],
                "priority": 1,
            },
            {
                "name": "high-deny",
                "effect": "deny",
                "identities": ["*"],
                "resources": ["r"],
                "actions": ["read"],
                "priority": 2,
            },
        ],
    }
    parsed = parse_policy_dict(doc)
    assert len(parsed.rules) == 2


def test_failed_replace_keeps_running_policy(store):
    before = store.current()
    bad = {"schema_version": "2.0", "rules": []}
    with pytest.raises(PolicySchemaVersionError):
        store.load_dict(bad)
    assert store.current() is before  # 在运策略未被污染


def test_merge_rejects_name_collision_and_cross_conflict(store):
    same_name = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "allow-dev-read",  # 与既有同名
                "effect": "allow",
                "identities": ["zoe"],
                "resources": ["docs"],
                "actions": ["read"],
                "priority": 99,
            }
        ],
    }
    with pytest.raises(PolicyConflictError, match="同名"):
        store.merge_json(__import__("json").dumps(same_name))

    cross = {
        "schema_version": "1.0",
        "rules": [
            {
                "name": "new-allow",
                "effect": "allow",
                "identities": ["*"],
                "resources": ["*"],
                "actions": ["*"],
                "priority": 0,  # 与 deny-all-default 同优先级相反且相交
            }
        ],
    }
    with pytest.raises(PolicyConflictError, match="与既有规则冲突"):
        store.merge_json(__import__("json").dumps(cross))
