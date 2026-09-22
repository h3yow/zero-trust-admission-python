"""准入判定核心编排。

判定流水线（每一步都带可解释依据，且短路后不消耗后续资源）：

1. 声明式规则匹配：最高优先级命中规则决定 allow/deny；无任何命中 ->
   零信任默认拒绝（``no_matching_policy``），绝不回退到更宽松的规则。
2. 限流：滑动窗口超阈值 -> ``rate_limited``，被拒请求不登记、不占配额。
3. 并发：每键信号量获取失败 -> ``concurrency_limited``。
4. 审计写入（admission 阶段）：
   - fail_closed（默认）：审计不可用则释放已获取并发槽并拒绝
     （``audit_unavailable``），保证不存在"已放行却无记录"；
   - fail_open：显式降级放行，记录进入有界内存缓冲并计数，日志明示。
5. 下游执行（:meth:`AdmissionGuard.execute_guarded`）：异常时在
   ``downstream`` 阶段审计中记录错误类型与消息，finally 中确定性释放并发槽。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable

from .audit import (
    AuditFailureMode,
    AuditSink,
    AuditUnavailableError,
    InMemoryAuditSink,
)
from .limiter import (
    ConcurrencyLimiter,
    SlidingWindowRateLimiter,
    request_matches_rule,
    select_rate_limit_policy,
)
from .model import (
    AccessRequest,
    Action,
    AdmissionResult,
    AuditRecord,
    Decision,
    DenyReason,
    MatchedRule,
    PolicyDocument,
    Principal,
    RateLimitPolicy,
)
from .policy_store import PolicyStore

logger = logging.getLogger("zero_trust_admission")

_FALLBACK_BUFFER_LIMIT = 10_000


def request_summary(req: AccessRequest) -> dict[str, Any]:
    return {
        "identity": req.principal.identity,
        "groups": list(req.principal.groups),
        "resource": req.resource,
        "action": req.action.value,
    }


def match_rules(req: AccessRequest, doc: PolicyDocument):
    """返回所有命中规则，按 (优先级降序, 名称升序) 排列，保证确定性。"""
    matched = [r for r in doc.rules if request_matches_rule(req, r)]
    matched.sort(key=lambda r: (-r.priority, r.name))
    return matched


def decide(
    req: AccessRequest, doc: PolicyDocument
) -> tuple[Decision, DenyReason | None, MatchedRule | None]:
    """纯函数式规则判定：返回 (结论, 拒绝原因, 命中规则)。"""
    matched = match_rules(req, doc)
    if not matched:
        return Decision.DENY, DenyReason.NO_MATCHING_POLICY, None
    winner = matched[0]
    if winner.effect.value == Decision.DENY.value:
        return (
            Decision.DENY,
            DenyReason.EXPLICIT_DENY,
            MatchedRule(winner.name, winner.effect, winner.priority),
        )
    return (
        Decision.ALLOW,
        None,
        MatchedRule(winner.name, winner.effect, winner.priority),
    )


def build_audit_record(
    *,
    phase: str,
    result: AdmissionResult,
    downstream_error: str | None = None,
    audit_id: str | None = None,
    timestamp: float | None = None,
) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id or uuid.uuid4().hex,
        timestamp=time.time() if timestamp is None else timestamp,
        phase=phase,
        decision=result.decision,
        reason=result.reason,
        request_summary=dict(result.request_summary),
        matched_rule_name=result.matched_rule.rule_name
        if result.matched_rule
        else None,
        rate_limit_name=result.rate_limit.name if result.rate_limit else None,
        detail=result.detail,
        downstream_error=downstream_error,
    )


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """:meth:`AdmissionGuard.execute_guarded` 的执行结果。"""

    result: AdmissionResult
    value: Any = None
    downstream_error: str | None = None

    @property
    def allowed(self) -> bool:
        return self.result.decision is Decision.ALLOW and self.downstream_error is None


class AdmissionGuard:
    """组合策略存储、限流器、并发限制器与审计 sink 的准入门面。"""

    def __init__(
        self,
        policy_store: PolicyStore,
        audit_sink: AuditSink,
        *,
        audit_failure_mode: str = AuditFailureMode.FAIL_CLOSED,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        concurrency_limiter: ConcurrencyLimiter | None = None,
    ) -> None:
        if audit_failure_mode not in AuditFailureMode.VALID:
            raise ValueError(
                f"非法审计失败模式 {audit_failure_mode!r}，"
                f"合法值: {AuditFailureMode.VALID}"
            )
        self._store = policy_store
        self._sink = audit_sink
        self._failure_mode = audit_failure_mode
        self._rate_limiter = rate_limiter or SlidingWindowRateLimiter()
        self._concurrency = concurrency_limiter or ConcurrencyLimiter()
        self._stats_lock = threading.Lock()
        self._stats = {
            "total": 0,
            "allow": 0,
            "deny": 0,
            "audit_write_failures": 0,
            "downstream_errors": 0,
        }
        # fail_open 或 post-downstream 写入失败时的显式降级缓冲
        self._fallback_buffer: deque[AuditRecord] = deque(
            maxlen=_FALLBACK_BUFFER_LIMIT
        )

    # ---- 统计与降级可观测性 ---------------------------------------------

    def audit_stats(self) -> dict[str, int]:
        with self._stats_lock:
            return dict(self._stats)

    def buffered_records(self) -> list[AuditRecord]:
        return list(self._fallback_buffer)

    @property
    def failure_mode(self) -> str:
        return self._failure_mode

    # ---- 审计写入与失败模式 ---------------------------------------------

    def _write_audit(self, record: AuditRecord) -> bool:
        """尝试写审计；失败时计数并入降级缓冲。返回是否写入成功。"""
        try:
            self._sink.write(record)
            return True
        except AuditUnavailableError as exc:
            with self._stats_lock:
                self._stats["audit_write_failures"] += 1
            self._fallback_buffer.append(record)
            logger.error("审计写入失败，记录已进入降级缓冲: %s", exc)
            return False

    # ---- 判定 -----------------------------------------------------------

    def evaluate(self, req: AccessRequest, *, now: float | None = None) -> AdmissionResult:
        """执行准入 + 限流 + 并发判定并写 admission 阶段审计。

        允许时会持有并发槽，调用方应使用
        :meth:`execute_guarded` 或在 finally 中 :meth:`release`。
        """
        with self._stats_lock:
            self._stats["total"] += 1
        summary = request_summary(req)
        logger.info("准入判定输入: %s", json.dumps(summary, ensure_ascii=False))

        doc = self._store.current()
        decision, reason, matched = decide(req, doc)
        rate_policy: RateLimitPolicy | None = None
        basis: dict[str, Any] = {
            "rule_decision": decision.value,
            "reason": reason.value if reason else None,
            "matched_rule": matched.rule_name if matched else None,
        }

        if decision is Decision.DENY:
            return self._finalize_deny(req, summary, reason, matched, basis)

        # 规则允许，继续限流判定
        rate_policy = select_rate_limit_policy(req, doc.rate_limits)
        basis["rate_limit_policy"] = rate_policy.name if rate_policy else None
        permit_held = False
        rate_registered_at: float | None = None
        if rate_policy is not None and rate_policy.rate_limit is not None:
            allowed, count, threshold = self._rate_limiter.check(
                req, rate_policy, now=now
            )
            basis["rate_count"] = count
            basis["rate_threshold"] = threshold
            if not allowed:
                basis["denied_at"] = "rate_limit"
                return self._finalize_deny(
                    req,
                    summary,
                    DenyReason.RATE_LIMITED,
                    matched,
                    basis,
                    rate_policy=rate_policy,
                    detail=(
                        f"窗口内请求数 {count} 已达限流阈值 {threshold}"
                        f"（策略 {rate_policy.name}）"
                    ),
                )
            rate_registered_at = time.monotonic() if now is None else now

        # 并发判定
        if rate_policy is not None and rate_policy.concurrency is not None:
            if not self._concurrency.acquire(req, rate_policy):
                # 未获得准入：回滚限流登记，被拒请求不得占用正常流量配额
                if rate_registered_at is not None:
                    self._rate_limiter.retract(req, rate_policy, rate_registered_at)
                basis["denied_at"] = "concurrency"
                basis["concurrency_limit"] = rate_policy.concurrency
                return self._finalize_deny(
                    req,
                    summary,
                    DenyReason.CONCURRENCY_LIMITED,
                    matched,
                    basis,
                    rate_policy=rate_policy,
                    detail=(
                        f"在途并发已达上限 {rate_policy.concurrency}"
                        f"（策略 {rate_policy.name}）"
                    ),
                )
            permit_held = True
            basis["concurrency_limit"] = rate_policy.concurrency

        result = AdmissionResult(
            decision=Decision.ALLOW,
            reason=None,
            request_summary=summary,
            matched_rule=matched,
            rate_limit=rate_policy,
            detail="规则/限流/并发全部通过",
        )
        record = build_audit_record(phase="admission", result=result)
        written = self._write_audit(record)

        if not written and self._failure_mode == AuditFailureMode.FAIL_CLOSED:
            # 默认拒绝：释放并发槽并回滚限流登记，翻转为审计不可用拒绝，
            # 杜绝"已放行却无记录"，且被拒请求不占配额
            if permit_held:
                self._concurrency.release(req, rate_policy)
            if rate_registered_at is not None:
                self._rate_limiter.retract(req, rate_policy, rate_registered_at)
            fail_result = AdmissionResult(
                decision=Decision.DENY,
                reason=DenyReason.AUDIT_UNAVAILABLE,
                request_summary=summary,
                matched_rule=matched,
                rate_limit=rate_policy,
                detail="审计后端不可用且失败模式为 fail_closed，按零信任原则拒绝",
            )
            basis["denied_at"] = "audit"
            basis["audit_failure_mode"] = self._failure_mode
            logger.info("准入判定依据: %s", json.dumps(basis, ensure_ascii=False))
            self._count_decision(fail_result.decision)
            return fail_result

        basis["audit_written"] = written
        if not written:
            basis["audit_failure_mode"] = self._failure_mode
            basis["detail"] = "审计不可用，按显式 fail_open 配置降级放行并缓冲记录"
        logger.info("准入判定依据: %s", json.dumps(basis, ensure_ascii=False))
        self._count_decision(Decision.ALLOW)
        return result

    def _finalize_deny(
        self,
        req: AccessRequest,
        summary: dict[str, Any],
        reason: DenyReason | None,
        matched: MatchedRule | None,
        basis: dict[str, Any],
        *,
        rate_policy: RateLimitPolicy | None = None,
        detail: str | None = None,
    ) -> AdmissionResult:
        if detail is None:
            if reason is DenyReason.NO_MATCHING_POLICY:
                detail = "没有任何策略规则匹配该身份/资源/动作，默认拒绝"
            elif reason is DenyReason.EXPLICIT_DENY:
                detail = f"命中拒绝规则 {matched.rule_name if matched else '?'}"
        result = AdmissionResult(
            decision=Decision.DENY,
            reason=reason,
            request_summary=summary,
            matched_rule=matched,
            rate_limit=rate_policy,
            detail=detail or "",
        )
        # 拒绝同样审计；审计失败不影响拒绝结论，但计数并缓冲以便解释
        self._write_audit(build_audit_record(phase="admission", result=result))
        logger.info("准入判定依据: %s", json.dumps(basis, ensure_ascii=False))
        self._count_decision(Decision.DENY)
        return result

    def _count_decision(self, decision: Decision) -> None:
        with self._stats_lock:
            if decision is Decision.ALLOW:
                self._stats["allow"] += 1
            else:
                self._stats["deny"] += 1

    def release(self, result: AdmissionResult) -> None:
        """显式释放某次允许判定持有的并发槽。"""
        if result.decision is not Decision.ALLOW or result.rate_limit is None:
            return
        if result.rate_limit.concurrency is not None:
            from .model import AccessRequest as _AR  # local: 通过 summary 重建

            req = _AR(
                Principal(
                    result.request_summary["identity"],
                    tuple(result.request_summary.get("groups", [])),
                ),
                result.request_summary["resource"],
                Action(result.request_summary["action"]),
            )
            self._concurrency.release(req, result.rate_limit)

    # ---- 下游执行包装 ---------------------------------------------------

    def execute_guarded(
        self,
        req: AccessRequest,
        downstream: Callable[[], Any],
        *,
        now: float | None = None,
    ) -> ExecutionOutcome:
        """完成准入后执行下游调用，保证异常链路下并发释放与审计一致。"""
        result = self.evaluate(req, now=now)
        if result.decision is Decision.DENY:
            return ExecutionOutcome(result=result)

        downstream_error: str | None = None
        value: Any = None
        try:
            value = downstream()
        except Exception as exc:  # noqa: BLE001 - 需记录任意下游异常链路
            downstream_error = f"{type(exc).__name__}: {exc}"
            with self._stats_lock:
                self._stats["downstream_errors"] += 1
            logger.warning("下游调用异常: %s", downstream_error)
        finally:
            # 无论下游成功或异常，并发槽必须确定性释放
            if result.rate_limit is not None and result.rate_limit.concurrency is not None:
                self._concurrency.release(req, result.rate_limit)
            completion = build_audit_record(
                phase="downstream",
                result=result,
                downstream_error=downstream_error,
            )
            # admission 记录在 fail_closed 下已成功落盘；此处失败只降级缓冲，
            # 不能也不会改变已发生的实际判定
            self._write_audit(completion)

        return ExecutionOutcome(
            result=result, value=value, downstream_error=downstream_error
        )


__all__ = [
    "AdmissionGuard",
    "ExecutionOutcome",
    "match_rules",
    "decide",
    "build_audit_record",
    "request_summary",
]
