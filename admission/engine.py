"""准入判定引擎。

判定链路（顺序固定，保证并发下结果确定、可解释）：
  1. 取当前生效策略快照（不可变对象，策略热更新不影响在途判定）；
  2. 规则匹配：显式 deny 优先，其次首个 allow；无命中默认拒绝；
  3. 固定窗口限流（RATE_LIMIT_EXCEEDED）；
  4. 并发约束（CONCURRENCY_LIMIT_EXCEEDED）；
  5. 写入 decision 审计（审计不可用则回滚配额并 fail-closed）；
  6. 调用下游；异常写 completion/downstream_error 审计并包装为 DownstreamError；
  7. 成功写 completion/allowed 审计；写失败返回 AUDIT_UNAVAILABLE。

不变量：
- 任何被放行的请求，其 decision 审计一定先于下游调用落盘；
- 拒绝与最终 outcome 一一对应，审计 reason_code 与抛出的错误原因码一致。
"""

from __future__ import annotations

import fnmatch
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from admission.audit import AuditEvent, Auditor, AuditStage, Outcome
from admission.errors import (
    AuditUnavailableError,
    ConcurrencyLimitError,
    DefaultDenyError,
    DownstreamError,
    ExplicitDenyError,
    RateLimitedError,
)
from admission.model import Decision, Identity, Policy, Request, Rule
from admission.ratelimit import ConcurrencyLimiter, RateLimiter
from admission.store import PolicyStore

logger = logging.getLogger("admission.engine")


def subject_matches(rule: Rule, identity: Identity) -> bool:
    sub = rule.subject
    if not sub.users and not sub.roles and not sub.groups:
        return True  # 空选择器匹配任意身份（含匿名）
    if identity.user and identity.user in sub.users:
        return True
    return bool(identity.roles & sub.roles or identity.groups & sub.groups)


def resource_matches(rule: Rule, resource_type: str, resource: str) -> bool:
    if rule.resource.type != resource_type:
        return False
    if not rule.resource.patterns:
        return True  # 空模式表示该类型下全部资源
    return any(fnmatch.fnmatchcase(resource, pat) for pat in rule.resource.patterns)


def action_matches(rule: Rule, action: str) -> bool:
    return not rule.action.methods or action in rule.action.methods


def match_rule(policy: Policy, request: Request) -> Rule | None:
    """返回命中规则：deny 优先于 allow；同类按声明顺序取第一条（确定可复现）。"""
    first_allow: Rule | None = None
    for rule in policy.rules:
        if (
            subject_matches(rule, request.identity)
            and resource_matches(rule, request.resource_type, request.resource)
            and action_matches(rule, request.action)
        ):
            if rule.effect.value == "deny":
                return rule
            if first_allow is None:
                first_allow = rule
    return first_allow


@dataclass
class AdmissionEngine:
    store: PolicyStore
    auditor: Auditor
    rate_limiter: RateLimiter = field(default_factory=RateLimiter)
    concurrency_limiter: ConcurrencyLimiter = field(default_factory=ConcurrencyLimiter)
    fail_open_on_audit: bool = False  # 审计不可用时默认 fail-closed
    clock: Callable[[], float] = time.monotonic

    def evaluate(self, request: Request) -> tuple[Policy, Decision]:
        """仅做策略匹配判定（不触碰限流与下游）。"""
        policy = self.store.require()
        rule = match_rule(policy, request)
        if rule is None:
            return policy, Decision(
                allowed=False,
                rule_id="",
                reason_code=DefaultDenyError.reason_code,
                reason="默认拒绝：没有任何规则匹配该身份/资源/动作",
            )
        if rule.effect.value == "deny":
            return policy, Decision(
                allowed=False,
                rule_id=rule.id,
                reason_code=ExplicitDenyError.reason_code,
                reason=f"显式拒绝：命中 deny 规则 {rule.id}（{rule.description}）",
            )
        return policy, Decision(
            allowed=True,
            rule_id=rule.id,
            reason_code="ALLOWED",
            reason=f"命中 allow 规则 {rule.id}（{rule.description}）",
        )

    # ---- 内部辅助 -------------------------------------------------------

    def _rate_key(self, rule: Rule, request: Request) -> tuple[Any, ...]:
        return (
            "rl",
            rule.id,
            request.identity.user,
            tuple(sorted(request.identity.roles)),
            tuple(sorted(request.identity.groups)),
            request.resource_type,
            request.resource,
            request.action,
        )

    def _conc_key(self, rule: Rule, request: Request) -> tuple[Any, ...]:
        return (
            "cc",
            rule.id,
            request.identity.user,
            tuple(sorted(request.identity.roles)),
            tuple(sorted(request.identity.groups)),
            request.resource_type,
            request.resource,
            request.action,
        )

    def _event(
        self,
        request: Request,
        policy: Policy,
        rule_id: str,
        stage: AuditStage,
        outcome: Outcome,
        reason_code: str,
        reason: str,
        detail: str = "",
    ) -> AuditEvent:
        return AuditEvent(
            request_id=request.request_id,
            stage=stage,
            outcome=outcome,
            reason_code=reason_code,
            reason=reason,
            rule_id=rule_id,
            user=request.identity.user,
            resource_type=request.resource_type,
            resource=request.resource,
            action=request.action,
            policy_version=policy.version,
            detail=detail,
        )

    def _record(self, event: AuditEvent) -> None:
        """写审计；不可用时按 fail-open / fail-closed 策略处理。"""
        try:
            self.auditor.record(event)
        except AuditUnavailableError:
            if self.fail_open_on_audit:
                logger.error(
                    "审计不可用但 fail_open_on_audit=true，放行且缺少审计: %s",
                    event.request_id,
                )
                return
            raise

    # ---- 主链路 ---------------------------------------------------------

    def admit(self, request: Request, downstream: Callable[[], Any]) -> Any:
        policy, decision = self.evaluate(request)
        rule = next((r for r in policy.rules if r.id == decision.rule_id), None)

        logger.info(
            "策略输入 policy=%s v%s request_id=%s user=%r roles=%s groups=%s "
            "resource_type=%s resource=%r action=%s",
            policy.name,
            policy.version,
            request.request_id,
            request.identity.user,
            sorted(request.identity.roles),
            sorted(request.identity.groups),
            request.resource_type,
            request.resource,
            request.action,
        )

        # --- 拒绝路径（默认拒绝 / 显式 deny）：先审计后拒绝 ---
        if not decision.allowed:
            self._record(
                self._event(
                    request,
                    policy,
                    decision.rule_id,
                    AuditStage.DECISION,
                    Outcome.DENIED,
                    decision.reason_code,
                    decision.reason,
                )
            )
            logger.info(
                "判定依据 %s rule=%s -> DENY(%s)",
                request.request_id,
                decision.rule_id or "-",
                decision.reason_code,
            )
            if decision.reason_code == ExplicitDenyError.reason_code:
                raise ExplicitDenyError(decision.reason)
            raise DefaultDenyError(decision.reason)

        assert rule is not None
        consumed_rate = False
        acquired_conc = False

        def _refund() -> None:
            if acquired_conc:
                self.concurrency_limiter.release(
                    self._conc_key(rule, request),
                    rule.concurrency_limit.max_in_flight,  # type: ignore[union-attr]
                )
            if consumed_rate and rule.rate_limit is not None:
                self.rate_limiter.release(
                    self._rate_key(rule, request),
                    rule.rate_limit.max_requests,
                    rule.rate_limit.window_seconds,
                    self.clock(),
                )

        # --- 限流 ---
        if rule.rate_limit is not None:
            rl = rule.rate_limit
            key = self._rate_key(rule, request)
            if not self.rate_limiter.try_acquire(
                key, rl.max_requests, rl.window_seconds, self.clock()
            ):
                count = self.rate_limiter.current_count(key)
                reason = (
                    f"限流拒绝：规则 {rule.id} 在 {rl.window_seconds}s 窗口内最多 "
                    f"{rl.max_requests} 次，当前计数 {count}"
                )
                # try_acquire 未成功，未占用配额，故此处无需回滚
                self._record(
                    self._event(
                        request,
                        policy,
                        rule.id,
                        AuditStage.DECISION,
                        Outcome.DENIED,
                        RateLimitedError.reason_code,
                        reason,
                    )
                )
                logger.info(
                    "判定依据 %s rule=%s -> DENY(%s) count=%s limit=%s/%ss",
                    request.request_id,
                    rule.id,
                    RateLimitedError.reason_code,
                    count,
                    rl.max_requests,
                    rl.window_seconds,
                )
                raise RateLimitedError(
                    reason,
                    rule_id=rule.id,
                    limit=rl.max_requests,
                    window=rl.window_seconds,
                )
            consumed_rate = True

        # --- 并发约束 ---
        if rule.concurrency_limit is not None:
            cl = rule.concurrency_limit
            key = self._conc_key(rule, request)
            if not self.concurrency_limiter.try_acquire(key, cl.max_in_flight):
                reason = (
                    f"并发拒绝：规则 {rule.id} 在途请求上限 {cl.max_in_flight} 已满"
                )
                deny_event = self._event(
                    request,
                    policy,
                    rule.id,
                    AuditStage.DECISION,
                    Outcome.DENIED,
                    ConcurrencyLimitError.reason_code,
                    reason,
                )
                # 该请求未进入下游，其限流配额无论审计结果如何都必须回滚，
                # 否则被并发拒绝的请求会挤占后续正常流量的配额。
                try:
                    self._record(deny_event)
                except AuditUnavailableError:
                    _refund()
                    raise
                _refund()
                logger.info(
                    "判定依据 %s rule=%s -> DENY(%s) limit=%s",
                    request.request_id,
                    rule.id,
                    ConcurrencyLimitError.reason_code,
                    cl.max_in_flight,
                )
                raise ConcurrencyLimitError(
                    reason, rule_id=rule.id, limit=cl.max_in_flight
                )
            acquired_conc = True

        # --- decision 审计：先记录，再放行 ---
        try:
            self._record(
                self._event(
                    request,
                    policy,
                    rule.id,
                    AuditStage.DECISION,
                    Outcome.ALLOWED,
                    "ALLOWED",
                    decision.reason,
                )
            )
        except AuditUnavailableError:
            _refund()
            logger.error(
                "判定依据 %s rule=%s -> AUDIT_UNAVAILABLE（已回滚配额，拒绝放行）",
                request.request_id,
                rule.id,
            )
            raise

        logger.info(
            "判定依据 %s rule=%s -> ALLOW rl=%s cc=%s",
            request.request_id,
            rule.id,
            f"{rule.rate_limit.max_requests}/{rule.rate_limit.window_seconds}s"
            if rule.rate_limit
            else "-",
            rule.concurrency_limit.max_in_flight if rule.concurrency_limit else "-",
        )

        # --- 下游调用与完成审计 ---
        try:
            try:
                result = downstream()
            except Exception as exc:  # 下游异常链路：记录后包装为可区分错误
                err = DownstreamError(f"下游处理失败: {exc}")
                try:
                    self._record(
                        self._event(
                            request,
                            policy,
                            rule.id,
                            AuditStage.COMPLETION,
                            Outcome.DOWNSTREAM_ERROR,
                            DownstreamError.reason_code,
                            str(err),
                        )
                    )
                except AuditUnavailableError:
                    # decision 审计已存在；完成审计失败不掩盖下游错误，仅记录日志
                    logger.error(
                        "完成审计写入失败（下游异常路径）: %s", request.request_id
                    )
                logger.info(
                    "判定依据 %s -> DOWNSTREAM_ERROR %r", request.request_id, str(exc)
                )
                raise err from exc

            try:
                self._record(
                    self._event(
                        request,
                        policy,
                        rule.id,
                        AuditStage.COMPLETION,
                        Outcome.ALLOWED,
                        "ALLOWED",
                        "下游处理成功",
                    )
                )
            except AuditUnavailableError:
                # 请求确实执行成功但无法补完成审计：以显式错误暴露，杜绝“无记录放行”的静默状态
                logger.error(
                    "完成审计不可用: %s 以 AUDIT_UNAVAILABLE 暴露", request.request_id
                )
                raise
            return result
        finally:
            if acquired_conc:
                self.concurrency_limiter.release(
                    self._conc_key(rule, request),
                    rule.concurrency_limit.max_in_flight,  # type: ignore[union-attr]
                )
