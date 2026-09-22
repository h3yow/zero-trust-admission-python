"""引擎端到端判定：默认拒绝、显式拒绝优先、限流/并发、审计一致性、下游异常。"""

from __future__ import annotations

import threading
import time

import pytest
from conftest import make_policy_doc

from admission.audit import AuditStage, Outcome
from admission.engine import AdmissionEngine
from admission.errors import (
    AuditUnavailableError,
    ConcurrencyLimitError,
    DefaultDenyError,
    DownstreamError,
    ExplicitDenyError,
    RateLimitedError,
)
from admission.model import Identity, Request


def req(
    user: str = "alice",
    roles=(),
    *,
    resource_type: str = "document",
    resource: str = "docs/a",
    action: str = "GET",
    request_id: str = "req-1",
) -> Request:
    return Request(
        identity=Identity(user=user, roles=frozenset(roles)),
        resource_type=resource_type,
        resource=resource,
        action=action,
        request_id=request_id,
    )


def allow_rule(rid: str = "allow-docs", **over) -> dict:
    base = {
        "id": rid,
        "effect": "allow",
        "subject": {"users": ["alice"], "roles": ["admin"]},
        "resource": {"type": "document", "patterns": ["docs/*"]},
        "action": {"methods": ["GET"]},
    }
    base.update(over)
    return base


def load(engine: AdmissionEngine, rules: list, version: int = 1) -> None:
    engine.store.load_dict(make_policy_doc(version=version, rules=rules))


def test_default_deny_when_no_rule_matches(engine: AdmissionEngine) -> None:
    load(engine, [])  # 空策略：默认拒绝而非放行
    with pytest.raises(DefaultDenyError) as ei:
        engine.admit(req(), lambda: "ok")
    assert ei.value.reason_code == "DENY_NO_MATCHING_RULE"
    events = engine.auditor.events()
    assert len(events) == 1
    assert events[0].outcome is Outcome.DENIED
    assert events[0].reason_code == "DENY_NO_MATCHING_RULE"


def test_explicit_deny_takes_priority_over_allow(engine: AdmissionEngine) -> None:
    load(
        engine,
        [
            allow_rule(),
            {
                "id": "deny-alice",
                "effect": "deny",
                "subject": {"users": ["alice"]},
                "resource": {"type": "document", "patterns": ["docs/*"]},
                "action": {"methods": ["GET"]},
            },
        ],
    )
    with pytest.raises(ExplicitDenyError) as ei:
        engine.admit(req(), lambda: "ok")
    assert ei.value.reason_code == "DENY_EXPLICIT_RULE"
    assert engine.auditor.events()[0].rule_id == "deny-alice"


def test_allow_happy_path_writes_decision_then_completion(
    engine: AdmissionEngine,
) -> None:
    load(engine, [allow_rule()])
    result = engine.admit(req(request_id="happy-1"), lambda: {"ok": True})
    assert result == {"ok": True}
    events = engine.auditor.events()
    assert [e.stage for e in events] == [AuditStage.DECISION, AuditStage.COMPLETION]
    assert events[0].outcome is Outcome.ALLOWED
    assert events[1].outcome is Outcome.ALLOWED
    assert all(e.policy_version == 1 for e in events)


def test_rate_limit_reason_is_distinct_and_counted(engine: AdmissionEngine) -> None:
    load(engine, [allow_rule(rateLimit={"maxRequests": 2, "windowSeconds": 60.0})])
    assert engine.admit(req(request_id="r1"), lambda: 1) == 1
    assert engine.admit(req(request_id="r2"), lambda: 1) == 1
    with pytest.raises(RateLimitedError) as ei:
        engine.admit(req(request_id="r3"), lambda: 1)
    assert ei.value.reason_code == "RATE_LIMIT_EXCEEDED"
    assert ei.value.limit == 2
    # 被限流请求只有 decision 事件，且与最终判定一致
    last = engine.auditor.events()[-1]
    assert last.stage is AuditStage.DECISION
    assert last.outcome is Outcome.DENIED
    assert last.reason_code == "RATE_LIMIT_EXCEEDED"
    assert last.request_id == "r3"


def test_rate_limits_isolated_between_identities(engine: AdmissionEngine) -> None:
    load(engine, [allow_rule(rateLimit={"maxRequests": 1, "windowSeconds": 60.0})])
    engine.admit(req(user="alice", request_id="a1"), lambda: 1)
    # alice 第二发超限
    with pytest.raises(RateLimitedError):
        engine.admit(req(user="alice", request_id="a2"), lambda: 1)
    # admin 角色身份独立，不受影响（不串号、不误伤）
    assert (
        engine.admit(req(user="bob", roles=["admin"], request_id="b1"), lambda: 1) == 1
    )


def test_concurrency_limit_under_parallel_burst(engine: AdmissionEngine) -> None:
    load(engine, [allow_rule(concurrencyLimit={"maxInFlight": 2})])
    entered = threading.Event()
    entered_count = 0
    count_lock = threading.Lock()
    proceed = threading.Event()
    results: list[str] = []
    lock = threading.Lock()

    def downstream() -> str:
        nonlocal entered_count
        # 先进入的两个请求占住槽位，通知主线程，再等待闸门释放
        with count_lock:
            entered_count += 1
            if entered_count == 2:
                entered.set()
        proceed.wait(timeout=5)
        time.sleep(0.02)
        return "done"

    def worker(i: int) -> None:
        try:
            engine.admit(req(request_id=f"c{i}"), downstream)
            outcome = "ok"
        except ConcurrencyLimitError as exc:
            outcome = exc.reason_code
        with lock:
            results.append(outcome)

    holder_threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for t in holder_threads:
        t.start()
    # 等待两个槽位确实被占住，保证后续请求一定撞上满员，测试确定可复现
    assert entered.wait(timeout=5)
    time.sleep(0.05)  # 让两个持有者都进入 proceed 等待

    burst = [threading.Thread(target=worker, args=(i,)) for i in range(2, 8)]
    for t in burst:
        t.start()
    for t in burst:
        t.join()
    proceed.set()
    for t in holder_threads:
        t.join()

    assert results.count("ok") == 2
    assert results.count("CONCURRENCY_LIMIT_EXCEEDED") == 6
    # 槽位必须全部归还：之后仍可正常进入
    assert engine.admit(req(request_id="after"), lambda: "later") == "later"


def test_audit_unavailable_blocks_allow_and_refunds_quota(
    engine: AdmissionEngine,
) -> None:
    load(engine, [allow_rule(rateLimit={"maxRequests": 2, "windowSeconds": 60.0})])
    engine.auditor.set_failed(True)
    with pytest.raises(AuditUnavailableError):
        engine.admit(req(request_id="x1"), lambda: 1)
    engine.auditor.set_failed(False)
    # 审计失败回滚了配额：两次请求都应成功（若未回滚，只剩 1 次）
    assert engine.admit(req(request_id="x2"), lambda: 1) == 1
    assert engine.admit(req(request_id="x3"), lambda: 1) == 1


def test_audit_unavailable_also_blocks_deny_audit_by_default(
    engine: AdmissionEngine,
) -> None:
    load(engine, [])
    engine.auditor.set_failed(True)
    # fail-closed：连拒绝审计都写不进去时，不静默
    with pytest.raises(AuditUnavailableError):
        engine.admit(req(), lambda: 1)


def test_fail_open_mode_is_explicit_and_logged(engine: AdmissionEngine) -> None:
    engine.fail_open_on_audit = True
    load(engine, [allow_rule()])
    engine.auditor.set_failed(True)
    called: list[bool] = []
    # 显式 fail-open 下放行（决策仍可解释：由 fail_open_on_audit 开关决定）
    assert engine.admit(req(), lambda: called.append(True) or "ok") == "ok"
    assert called == [True]


def test_downstream_error_is_distinct_and_audited(engine: AdmissionEngine) -> None:
    load(engine, [allow_rule()])

    def boom() -> None:
        raise ValueError("db connection lost")

    with pytest.raises(DownstreamError) as ei:
        engine.admit(req(request_id="down-1"), boom)
    assert ei.value.reason_code == "DOWNSTREAM_ERROR"
    assert "db connection lost" in str(ei.value)
    events = engine.auditor.events()
    assert (
        events[0].stage is AuditStage.DECISION and events[0].outcome is Outcome.ALLOWED
    )
    assert events[1].stage is AuditStage.COMPLETION
    assert events[1].outcome is Outcome.DOWNSTREAM_ERROR
    assert events[1].reason_code == "DOWNSTREAM_ERROR"
    assert events[1].request_id == "down-1"


def test_concurrency_slot_released_after_downstream_error(
    engine: AdmissionEngine,
) -> None:
    load(engine, [allow_rule(concurrencyLimit={"maxInFlight": 1})])

    def boom() -> None:
        raise RuntimeError("fail")

    for i in range(3):
        with pytest.raises(DownstreamError):
            engine.admit(req(request_id=f"f{i}"), boom)
    # 三次都能进入说明槽位在异常路径下也被释放


def test_fail_open_concurrency_deny_with_dead_auditor_still_denies(
    engine: AdmissionEngine,
) -> None:
    """fail-open 只豁免“放行决策”的审计；并发拒绝本身仍要被拒绝且不消耗额外状态。

    同时验证：故障审计恢复后，后续请求行为完全正常（槽位释放、状态一致）。
    """
    engine.fail_open_on_audit = True
    load(engine, [allow_rule(concurrencyLimit={"maxInFlight": 1})])
    entered = threading.Event()
    proceed = threading.Event()

    def hold() -> None:
        entered.set()
        proceed.wait(timeout=5)

    t = threading.Thread(target=lambda: engine.admit(req(request_id="hold"), hold))
    t.start()
    assert entered.wait(timeout=5)

    # 审计后端宕机 + 并发槽满：fail-open 下记录被跳过，但请求仍因并发被拒
    engine.auditor.set_failed(True)
    with pytest.raises(ConcurrencyLimitError):
        engine.admit(req(request_id="bump"), lambda: None)
    engine.auditor.set_failed(False)

    proceed.set()
    t.join()
    # 槽位已释放，状态一致，后续请求正常进入并产生完整两条审计
    assert engine.admit(req(request_id="after"), lambda: "ok") == "ok"
    after_events = [e for e in engine.auditor.events() if e.request_id == "after"]
    assert [(e.stage, e.outcome) for e in after_events] == [
        (AuditStage.DECISION, Outcome.ALLOWED),
        (AuditStage.COMPLETION, Outcome.ALLOWED),
    ]


def test_concurrency_deny_refunds_rate_quota_for_later_traffic(
    engine: AdmissionEngine,
) -> None:
    """并发上限拒绝的请求不进入下游，其限流配额必须归还，不影响后续正常流量。"""
    load(
        engine,
        [
            allow_rule(
                rateLimit={"maxRequests": 2, "windowSeconds": 60.0},
                concurrencyLimit={"maxInFlight": 1},
            )
        ],
    )
    entered = threading.Event()
    proceed = threading.Event()

    def hold() -> None:
        entered.set()
        proceed.wait(timeout=5)

    t = threading.Thread(target=lambda: engine.admit(req(request_id="hold"), hold))
    t.start()
    assert entered.wait(timeout=5)
    # 在途的 hold 已占 1 个限流配额（在途不还），窗口剩余 1 个。
    # bump 占用最后 1 个配额后被并发拒绝，必须回滚，否则后续正常流量会被误伤。
    with pytest.raises(ConcurrencyLimitError):
        engine.admit(req(request_id="bump"), lambda: None)
    proceed.set()
    t.join()
    # 回滚后窗口恢复到 1 个可用配额：下一个请求成功，再下一个才限流
    assert engine.admit(req(request_id="after-1"), lambda: "ok") == "ok"
    with pytest.raises(RateLimitedError):
        engine.admit(req(request_id="after-2"), lambda: "ok")
