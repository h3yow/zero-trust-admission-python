"""策略仓库原子生效与乐观版本控制测试。"""

from __future__ import annotations

import pytest
from conftest import make_policy_doc

from admission.errors import PolicyValidationError, PolicyVersionError
from admission.store import PolicyStore


def test_failed_update_keeps_old_policy(store: PolicyStore) -> None:
    v1 = store.load_dict(make_policy_doc(version=1, name="p1"))
    assert v1.name == "p1"

    # 非法更新必须失败，旧策略原样保留
    bad = make_policy_doc(version=2, rules=[{"id": "broken"}])
    with pytest.raises(PolicyValidationError):
        store.load_dict(bad)
    assert store.require().name == "p1"
    assert store.require().version == 1


def test_optimistic_concurrency_check(store: PolicyStore) -> None:
    store.load_dict(make_policy_doc(version=1))
    with pytest.raises(PolicyVersionError):
        store.load_dict(
            make_policy_doc(version=2, name="p2"), expected_current_version=99
        )
    updated = store.load_dict(
        make_policy_doc(version=2, name="p2"), expected_current_version=1
    )
    assert updated.version == 2
