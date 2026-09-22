"""FastAPI 装配层。

- ``GET /`` 保持既有 {"Hello": "World"} 行为不变；
- ``POST /api/v1/evaluate``：对一次身份/资源/动作请求做准入+限流判定；
- ``GET /api/v1/resources/{name}``：受保护资源示例，准入失败不触达下游，
  下游异常也能得到一致审计；
- ``GET/PUT /api/v1/policy``：查看与原子替换当前生效策略，非法/版本不兼容/
  冲突策略以 4xx 与可区分错误码拒绝，不改变在运策略。
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .admission import AdmissionGuard
from .audit import (
    AuditFailureMode,
    JsonlAuditSink,
)
from .errors import PolicyError
from .model import AccessRequest, Action, Principal
from .policy_store import PolicyStore

_DEFAULT_POLICY = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "policies", "default.json"
)
_DEFAULT_AUDIT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "audit.log")


class PrincipalModel(BaseModel):
    identity: str = Field(min_length=1)
    groups: list[str] = Field(default_factory=list)


class EvaluateRequest(BaseModel):
    principal: PrincipalModel
    resource: str = Field(min_length=1)
    action: Action


def _to_domain(req: EvaluateRequest) -> AccessRequest:
    return AccessRequest(
        principal=Principal(
            identity=req.principal.identity,
            groups=tuple(req.principal.groups),
        ),
        resource=req.resource,
        action=req.action,
    )


def _result_payload(result) -> dict[str, Any]:
    return {
        "decision": result.decision.value,
        "reason": result.reason.value if result.reason else None,
        "matched_rule": result.matched_rule.rule_name if result.matched_rule else None,
        "rate_limit_policy": result.rate_limit.name if result.rate_limit else None,
        "detail": result.detail,
        "request": result.request_summary,
    }


def create_app(
    *,
    policy_path: str | None = None,
    audit_path: str | None = None,
    guard: AdmissionGuard | None = None,
) -> FastAPI:
    application = FastAPI(title="zero-trust-admission")

    if guard is None:
        store = PolicyStore()
        store.load_json_file(policy_path or _DEFAULT_POLICY)
        failure_mode = os.environ.get(
            "ZTA_AUDIT_FAILURE_MODE", AuditFailureMode.FAIL_CLOSED
        )
        sink = JsonlAuditSink(audit_path or _DEFAULT_AUDIT)
        guard = AdmissionGuard(store, sink, audit_failure_mode=failure_mode)
    application.state.guard = guard

    @application.get("/")
    def read_root():
        # 既有接口行为保持兼容，不受准入策略影响
        return {"Hello": "World"}

    @application.post("/api/v1/evaluate")
    def evaluate(body: EvaluateRequest):
        # 纯判定探针：走完整流水线（含并发获取与释放），不触达业务下游
        outcome = guard.execute_guarded(_to_domain(body), lambda: None)
        result = outcome.result
        status = 200 if result.decision.value == "allow" else 403
        return JSONResponse(status_code=status, content=_result_payload(result))

    @application.get("/api/v1/resources/{name}")
    def get_resource(name: str, identity: str = "anonymous", group: str | None = None):
        # 示例受保护下游：任何下游异常都由 guard 记录并保持审计一致
        req = AccessRequest(
            Principal(identity, (group,) if group else ()), name, Action.READ
        )

        def downstream() -> dict[str, Any]:
            return {"resource": name, "owner": identity, "payload": "ok"}

        outcome = guard.execute_guarded(req, downstream)
        if outcome.result.decision.value == "deny":
            return JSONResponse(
                status_code=403, content=_result_payload(outcome.result)
            )
        if outcome.downstream_error is not None:
            return JSONResponse(
                status_code=502,
                content={
                    "decision": "allow",
                    "downstream_error": outcome.downstream_error,
                },
            )
        return outcome.value

    @application.get("/api/v1/policy")
    def get_policy():
        doc = guard._store.current()  # noqa: SLF001 - 装配层内受控访问
        return {
            "schema_version": doc.schema_version,
            "rules": [
                {
                    "name": r.name,
                    "effect": r.effect.value,
                    "identities": list(r.identities),
                    "groups": list(r.groups),
                    "resources": list(r.resources),
                    "actions": list(r.actions),
                    "priority": r.priority,
                }
                for r in doc.rules
            ],
            "rate_limits": [
                {
                    "name": p.name,
                    "identities": list(p.identities),
                    "groups": list(p.groups),
                    "resources": list(p.resources),
                    "rate_limit": p.rate_limit,
                    "rate_window_seconds": p.rate_window_seconds,
                    "concurrency": p.concurrency,
                }
                for p in doc.rate_limits
            ],
        }

    @application.put("/api/v1/policy")
    def replace_policy(body: dict[str, Any]):
        try:
            doc = guard._store.load_dict(body)  # noqa: SLF001
        except PolicyError as exc:
            return JSONResponse(
                status_code=422,
                content={"error_code": exc.code, "error": str(exc)},
            )
        return JSONResponse(status_code=200, content={"schema_version": doc.schema_version})

    @application.get("/api/v1/audit/stats")
    def audit_stats():
        return {
            **guard.audit_stats(),
            "audit_failure_mode": guard.failure_mode,
            "buffered_records": len(guard.buffered_records()),
        }

    return application


app = create_app(
    policy_path=os.environ.get("ZTA_POLICY_PATH", _DEFAULT_POLICY),
    audit_path=os.environ.get("ZTA_AUDIT_PATH", _DEFAULT_AUDIT),
)


__all__ = ["app", "create_app"]
