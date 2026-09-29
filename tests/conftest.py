"""pytest 公共夹具与日志配置。

单测中通过 caplog 断言"策略输入"（准入判定输入）与"判定依据"
（准入判定依据）均已打印。
"""

from __future__ import annotations

import logging

import pytest

from zero_trust_admission.admission import AdmissionGuard
from zero_trust_admission.audit import InMemoryAuditSink
from zero_trust_admission.model import (
    Effect,
    PolicyDocument,
    Principal,
    RateLimitPolicy,
    Rule,
)
from zero_trust_admission.policy_store import PolicyStore

ZTA_LOGGER = logging.getLogger("zero_trust_admission")


@pytest.fixture(autouse=True)
def _enable_zta_logs(caplog):
    caplog.set_level(logging.INFO, logger="zero_trust_admission")
    ZTA_LOGGER.setLevel(logging.INFO)
    yield


def make_document() -> PolicyDocument:
    return PolicyDocument(
        schema_version="1.0",
        rules=(
            Rule(
                name="deny-all-default",
                effect=Effect.DENY,
                identities=("*",),
                groups=(),
                resources=("*",),
                actions=("*",),
                priority=0,
            ),
            Rule(
                name="allow-dev-read",
                effect=Effect.ALLOW,
                identities=("*",),
                groups=("dev",),
                resources=("docs",),
                actions=("read",),
                priority=10,
            ),
            Rule(
                name="allow-alice-write",
                effect=Effect.ALLOW,
                identities=("alice",),
                groups=(),
                resources=("docs",),
                actions=("read", "write"),
                priority=20,
            ),
            Rule(
                name="deny-delete",
                effect=Effect.DENY,
                identities=("*",),
                groups=(),
                resources=("docs",),
                actions=("delete",),
                priority=30,
            ),
        ),
        rate_limits=(
            RateLimitPolicy(
                name="rl-global",
                identities=("*",),
                groups=(),
                resources=("docs",),
                rate_limit=5,
                rate_window_seconds=1.0,
                concurrency=2,
            ),
            RateLimitPolicy(
                name="rl-alice",
                identities=("alice",),
                groups=(),
                resources=("docs",),
                rate_limit=2,
                rate_window_seconds=1.0,
                concurrency=1,
            ),
        ),
    )


@pytest.fixture
def store() -> PolicyStore:
    return PolicyStore(make_document())


@pytest.fixture
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture
def guard(store, audit_sink) -> AdmissionGuard:
    return AdmissionGuard(store, audit_sink)


@pytest.fixture
def alice() -> Principal:
    return Principal("alice", ("dev",))


@pytest.fixture
def bob() -> Principal:
    return Principal("bob", ("dev",))
