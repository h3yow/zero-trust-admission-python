"""准入判定核心编排。

判定流水线（每一步都带可解释依据，且短路后不消耗后续资源）：

1. 声明式规则匹配：最高优先级命中规则决定 allow/deny；无任何命中 ->
   零信任默认拒绝（``no_matching_policy``），绝不回退到更宽松的规则。
2. 配额判定，按文档 ``quota.mode``（或构造期 ``quota_mode`` 覆盖）分流：
   - single（默认，老策略语义）：只取最具体的一条限流策略；
   - layered：所有命中策略按 身份 > 组 > 资源整体 的固定顺序逐层判定
     （同具体度时严格按各层在策略文件里的书写位置，与层名无关），
     任一层不过即拒绝并精确退回此前各层已登记名额；详见
     :meth:`AdmissionGuard._evaluate_layered`。
3. 限流：滑动窗口超阈值 -> ``rate_limited``，被拒请求不登记、不占配额。
4. 并发：每键信号量获取失败 -> ``concurrency_limited``。
5. 审计写入（admission 阶段）：
   - fail_closed（默认）：审计不可用则释放已获取并发槽并拒绝
     （``audit_unavailable``），保证不存在"已放行却无记录"；
   - fail_open：显式降级放行，记录进入有界内存缓冲并计数，日志明示。
6. 下游执行（:meth:`AdmissionGuard.execute_guarded`）：异常时在
   ``downstream`` 阶段审计中记录错误类型与消息，finally 中确定性释放全部
   持有并发槽（single 模式一个键、layered 模式按层逐一释放）。
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
    layer_scope,
    request_matches_rule,
    select_rate_limit_layers,
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
    QuotaLayerResult,
    QuotaMode,
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
        quota_mode: str | None = None,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        concurrency_limiter: ConcurrencyLimiter | None = None,
    ) -> None:
        if audit_failure_mode not in AuditFailureMode.VALID:
            raise ValueError(
                f"非法审计失败模式 {audit_failure_mode!r}，"
                f"合法值: {AuditFailureMode.VALID}"
            )
        if quota_mode is not None and quota_mode not in QuotaMode.VALID:
            raise ValueError(
                f"非法配额模式 {quota_mode!r}，合法值: {QuotaMode.VALID}"
            )
        self._store = policy_store
        self._sink = audit_sink
        self._failure_mode = audit_failure_mode
        # None 表示跟随策略文档的 quota.mode（老文档缺省即 single，
        # 因此老策略在不改动文件的前提下行为完全不变）
        self._quota_mode_override = quota_mode
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

    def _resolve_quota_mode(self, doc: PolicyDocument) -> str:
        return self._quota_mode_override or doc.quota_mode

    @staticmethod
    def _layer_rate_key(policy: RateLimitPolicy, scope_key: tuple) -> tuple:
        # 每个策略层拥有独立窗口：即便两层作用域相同也不共用计数
        return ("layer-rate", policy.name, scope_key)

    @staticmethod
    def _layer_concurrency_key(
        policy: RateLimitPolicy, scope_key: tuple
    ) -> tuple:
        return ("layer-conc", policy.name, scope_key)

    @staticmethod
    def _scope_key_from_label(label: str) -> tuple:
        """把 :class:`QuotaLayerResult` 的作用域标签还原成计数键。

        释放槽位时只依赖判定结果自带信息，策略随后被热替换也能精确释放。
        """
        if label.startswith("resource:"):
            return ("resource", "*", label[len("resource:") :])
        head, _, resource = label.partition("@")
        kind, _, name = head.partition(":")
        return (kind, name, resource)

    def _release_layer_slots(self, req: AccessRequest, result: AdmissionResult) -> None:
        for layer in result.quota_layers:
            if layer.concurrency is None:
                continue
            scope_key = self._scope_key_from_label(layer.scope)
            self._concurrency.release_key(
                ("layer-conc", layer.policy_name, scope_key)
            )

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

        # 规则允许：按文档 quota.mode（或构造期显式覆盖）选择配额判定路径
        if self._resolve_quota_mode(doc) == QuotaMode.LAYERED:
            return self._evaluate_layered(
                req, summary, matched, doc, basis, now=now
            )

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

    def _evaluate_layered(
        self,
        req: AccessRequest,
        summary: dict[str, Any],
        matched: MatchedRule | None,
        doc: PolicyDocument,
        basis: dict[str, Any],
        *,
        now: float | None = None,
    ) -> AdmissionResult:
        """分层配额判定：所有命中层按固定顺序逐一检查，任一层不过即拒绝。

        - 被某层拒绝时该层本身不登记；此前已通过各层登记的限流名额会被
          精确撤回、并发槽被释放，被拒请求不占任何一层的名额；
        - 短路后尚未判定到的层在结果中标记 ``allowed=None``，其静态阈值
          仍一并展示，完整呈现本次受约束的层链；
        - 整次判定使用同一个单调时钟读数（真实时钟，不注入时），各层
          窗口独立滑动恢复。
        """
        moment = time.monotonic() if now is None else now
        layers = select_rate_limit_layers(req, doc.rate_limits)
        basis["quota_mode"] = QuotaMode.LAYERED
        basis["quota_layers"] = [p.name for p in layers]

        # 已完成登记、需要在失败时回滚的层：(计数键, 登记时间戳)
        rate_holds: list[tuple[tuple, float]] = []
        # 已获取并发槽、需要在失败时释放的层：计数键
        conc_holds: list[tuple] = []
        results: list[QuotaLayerResult] = []

        def _rollback() -> None:
            for key, ts in rate_holds:
                self._rate_limiter.retract_key(key, ts)
            for key in conc_holds:
                self._concurrency.release_key(key)

        for index, policy in enumerate(layers):
            scope_key, scope_label = layer_scope(req, policy)
            rate_key = self._layer_rate_key(policy, scope_key)
            conc_key = self._layer_concurrency_key(policy, scope_key)

            # ---- 该层限流窗口 ----
            if policy.rate_limit is not None and policy.rate_window_seconds is not None:
                allowed, used, threshold = self._rate_limiter.check_key(
                    rate_key,
                    policy.rate_limit,
                    policy.rate_window_seconds,
                    now=moment,
                )
                if not allowed:
                    # 本层未登记；短路层之后的层不再判定
                    results.append(
                        QuotaLayerResult(
                            order=index,
                            policy_name=policy.name,
                            allowed=False,
                            scope=scope_label,
                            used=used,
                            threshold=threshold,
                            in_flight=self._concurrency.active_key(
                                conc_key, policy.concurrency
                            )
                            if policy.concurrency is not None
                            else None,
                            concurrency=policy.concurrency,
                        )
                    )
                    self._append_skipped_layers(
                        results, layers[index + 1 :], req, start=index + 1
                    )
                    _rollback()
                    basis["denied_at"] = "rate_limit"
                    basis["blocked_layer"] = policy.name
                    return self._finalize_deny(
                        req,
                        summary,
                        DenyReason.RATE_LIMITED,
                        matched,
                        basis,
                        rate_policy=policy,
                        quota_layers=tuple(results),
                        detail=(
                            f"层 {policy.name}（{scope_label}）窗口内请求数 {used} "
                            f"已达限流阈值 {threshold}，该层拦截"
                        ),
                    )
                rate_holds.append((rate_key, moment))
            else:
                used = self._rate_limiter.current_count_key(
                    rate_key,
                    policy.rate_window_seconds or 0.0,
                    now=moment,
                )
                threshold = None

            # ---- 该层并发槽 ----
            in_flight = (
                self._concurrency.active_key(conc_key, policy.concurrency)
                if policy.concurrency is not None
                else None
            )
            if policy.concurrency is not None:
                if not self._concurrency.acquire_key(conc_key, policy.concurrency):
                    results.append(
                        QuotaLayerResult(
                            order=index,
                            policy_name=policy.name,
                            allowed=False,
                            scope=scope_label,
                            used=used,
                            threshold=policy.rate_limit,
                            in_flight=in_flight,
                            concurrency=policy.concurrency,
                        )
                    )
                    self._append_skipped_layers(
                        results, layers[index + 1 :], req, start=index + 1
                    )
                    _rollback()
                    basis["denied_at"] = "concurrency"
                    basis["blocked_layer"] = policy.name
                    basis["concurrency_limit"] = policy.concurrency
                    return self._finalize_deny(
                        req,
                        summary,
                        DenyReason.CONCURRENCY_LIMITED,
                        matched,
                        basis,
                        rate_policy=policy,
                        quota_layers=tuple(results),
                        detail=(
                            f"层 {policy.name}（{scope_label}）在途并发 {in_flight} "
                            f"已达上限 {policy.concurrency}，该层拦截"
                        ),
                    )
                conc_holds.append(conc_key)
                in_flight += 1

            results.append(
                QuotaLayerResult(
                    order=index,
                    policy_name=policy.name,
                    allowed=True,
                    scope=scope_label,
                    used=used,
                    threshold=policy.rate_limit,
                    in_flight=in_flight,
                    concurrency=policy.concurrency,
                )
            )

        # ---- 所有层通过：写审计 ----
        quota_layers = tuple(results)
        result = AdmissionResult(
            decision=Decision.ALLOW,
            reason=None,
            request_summary=summary,
            matched_rule=matched,
            rate_limit=layers[0] if layers else None,
            detail=(
                "全部配额层通过"
                if layers
                else "规则通过，且未配置命中的配额层"
            ),
            quota_layers=quota_layers,
        )
        record = build_audit_record(phase="admission", result=result)
        written = self._write_audit(record)

        if not written and self._failure_mode == AuditFailureMode.FAIL_CLOSED:
            _rollback()
            fail_result = AdmissionResult(
                decision=Decision.DENY,
                reason=DenyReason.AUDIT_UNAVAILABLE,
                request_summary=summary,
                matched_rule=matched,
                rate_limit=layers[0] if layers else None,
                detail="审计后端不可用且失败模式为 fail_closed，按零信任原则拒绝",
                quota_layers=quota_layers,
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

    def _append_skipped_layers(
        self,
        results: list[QuotaLayerResult],
        skipped: tuple[RateLimitPolicy, ...],
        req: AccessRequest,
        *,
        start: int,
    ) -> None:
        for offset, policy in enumerate(skipped):
            _, scope_label = layer_scope(req, policy)
            results.append(
                QuotaLayerResult(
                    order=start + offset,
                    policy_name=policy.name,
                    allowed=None,
                    scope=scope_label,
                    threshold=policy.rate_limit,
                    concurrency=policy.concurrency,
                )
            )

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
        quota_layers: tuple[QuotaLayerResult, ...] = (),
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
            quota_layers=quota_layers,
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
        """显式释放某次允许判定持有的并发槽（兼容 single 与 layered 模式）。"""
        if result.decision is not Decision.ALLOW:
            return
        req = AccessRequest(
            Principal(
                result.request_summary["identity"],
                tuple(result.request_summary.get("groups", [])),
            ),
            result.request_summary["resource"],
            Action(result.request_summary["action"]),
        )
        if result.quota_layers:
            self._release_layer_slots(req, result)
            return
        if result.rate_limit is not None and result.rate_limit.concurrency is not None:
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
            # 无论下游成功或异常，各层并发槽必须确定性释放
            if result.quota_layers:
                self._release_layer_slots(req, result)
            elif (
                result.rate_limit is not None
                and result.rate_limit.concurrency is not None
            ):
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
