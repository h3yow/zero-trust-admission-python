"""pytest 公共夹具与日志配置：单测日志打印策略输入与判定依据。"""

from __future__ import annotations

import logging

import pytest

from admission.audit import InMemoryAuditor
from admission.engine import AdmissionEngine
from admission.store import PolicyStore

# 通过 pytest 的 --log-cli-level=INFO 输出 admission.engine 的
# “策略输入”“判定依据”日志（见 pyproject.toml 的 addopts）。
logging.getLogger("admission.engine").setLevel(logging.INFO)


def make_policy_doc(
    *, version: int = 1, rules: list | None = None, name: str = "test"
) -> dict:
    return {
        "apiVersion": "zero-trust-admission/v1",
        "kind": "AdmissionPolicy",
        "metadata": {"name": name, "version": version},
        "rules": [] if rules is None else rules,
    }


@pytest.fixture
def store() -> PolicyStore:
    return PolicyStore()


@pytest.fixture
def auditor() -> InMemoryAuditor:
    return InMemoryAuditor()


@pytest.fixture
def engine(store: PolicyStore, auditor: InMemoryAuditor) -> AdmissionEngine:
    return AdmissionEngine(store=store, auditor=auditor)
