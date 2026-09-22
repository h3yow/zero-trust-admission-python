"""HTTP 接口：策略管理与受保护资源演示端点。

身份通过请求头声明（本地零依赖演示用）：
  X-User / X-Roles（逗号分隔）/ X-Groups（逗号分隔）/ X-Request-ID
所有拒绝响应均携带可区分的 reason_code，便于调用方与审计对账。
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from fastapi import APIRouter, Header
from fastapi import Request as FastAPIRequest

from admission.engine import AdmissionEngine
from admission.model import Identity, Policy, Request

_DENY_STATUS = {
    "DENY_EXPLICIT_RULE": 403,
    "DENY_NO_MATCHING_RULE": 403,
    "RATE_LIMIT_EXCEEDED": 429,
    "CONCURRENCY_LIMIT_EXCEEDED": 429,
    "DOWNSTREAM_ERROR": 502,
    "AUDIT_UNAVAILABLE": 500,
    "POLICY_NOT_FOUND": 503,
}


def error_status(reason_code: str) -> int:
    return _DENY_STATUS.get(reason_code, 403)


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    return {
        "apiVersion": policy.api_version,
        "kind": policy.kind,
        "metadata": {"name": policy.name, "version": policy.version},
        "rules": [
            {
                "id": r.id,
                "description": r.description,
                "effect": r.effect.value,
                "subject": {
                    "users": sorted(r.subject.users),
                    "roles": sorted(r.subject.roles),
                    "groups": sorted(r.subject.groups),
                },
                "resource": {
                    "type": r.resource.type,
                    "patterns": sorted(r.resource.patterns),
                },
                "action": {"methods": sorted(r.action.methods)},
                **(
                    {
                        "rateLimit": {
                            "maxRequests": r.rate_limit.max_requests,
                            "windowSeconds": r.rate_limit.window_seconds,
                        }
                    }
                    if r.rate_limit
                    else {}
                ),
                **(
                    {
                        "concurrencyLimit": {
                            "maxInFlight": r.concurrency_limit.max_in_flight
                        }
                    }
                    if r.concurrency_limit
                    else {}
                ),
            }
            for r in policy.rules
        ],
    }


def _split_csv(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(v.strip() for v in value.split(",") if v.strip())


def _build_request(
    req: FastAPIRequest,
    x_user: str,
    x_roles: str,
    x_groups: str,
    x_request_id: str,
    resource_type: str,
    resource: str,
) -> Request:
    return Request(
        identity=Identity(
            user=x_user.strip(),
            roles=_split_csv(x_roles),
            groups=_split_csv(x_groups),
        ),
        resource_type=resource_type,
        resource=resource,
        action=req.method.upper(),
        request_id=x_request_id.strip() or str(uuid.uuid4()),
    )


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    def healthz(
        request: FastAPIRequest,
        x_user: str = Header(default=""),
        x_roles: str = Header(default=""),
        x_groups: str = Header(default=""),
        x_request_id: str = Header(default=""),
    ) -> Any:
        engine: AdmissionEngine = request.app.state.engine
        req = _build_request(
            request, x_user, x_roles, x_groups, x_request_id, "system", "/healthz"
        )
        return engine.admit(req, lambda: {"status": "ok", "requestId": req.request_id})

    @router.get("/api/resources/documents/{doc_path:path}")
    def get_document(
        doc_path: str,
        request: FastAPIRequest,
        x_user: str = Header(default=""),
        x_roles: str = Header(default=""),
        x_groups: str = Header(default=""),
        x_request_id: str = Header(default=""),
    ) -> Any:
        engine: AdmissionEngine = request.app.state.engine
        resource = f"docs/{doc_path}"
        req = _build_request(
            request, x_user, x_roles, x_groups, x_request_id, "document", resource
        )

        def downstream() -> dict[str, Any]:
            return {
                "resource": resource,
                "data": f"content-of:{resource}",
                "requestId": req.request_id,
            }

        return engine.admit(req, downstream)

    @router.post("/api/echo")
    async def echo(
        request: FastAPIRequest,
        x_user: str = Header(default=""),
        x_roles: str = Header(default=""),
        x_groups: str = Header(default=""),
        x_request_id: str = Header(default=""),
    ) -> Any:
        engine: AdmissionEngine = request.app.state.engine
        body = await request.json()
        delay = float(body.get("delay", 0.0))
        fail = bool(body.get("fail", False))
        message = body.get("message", "")
        req = _build_request(
            request, x_user, x_roles, x_groups, x_request_id, "api", "/api/echo"
        )

        def downstream() -> dict[str, Any]:
            if delay > 0:
                time.sleep(delay)  # 用于稳定触发并发上限
            if fail:
                raise RuntimeError("模拟下游故障（fail=true）")
            return {"echo": message, "requestId": req.request_id}

        return engine.admit(req, downstream)

    # ---- 策略管理（结构化区分拒绝原因，由 main.py 统一映射状态码） ----

    @router.get("/admin/policy")
    def get_policy(request: FastAPIRequest) -> Any:
        engine: AdmissionEngine = request.app.state.engine
        return policy_to_dict(engine.store.require())

    @router.put("/admin/policy")
    async def put_policy(
        request: FastAPIRequest,
        expected_current_version: int | None = None,
    ) -> Any:
        engine: AdmissionEngine = request.app.state.engine
        raw = await request.json()
        policy = engine.store.load_dict(
            raw, expected_current_version=expected_current_version
        )
        return {
            "accepted": True,
            "metadata": {"name": policy.name, "version": policy.version},
        }

    # ---- 审计查询 ----

    @router.get("/admin/audit")
    def get_audit(request: FastAPIRequest) -> Any:
        engine: AdmissionEngine = request.app.state.engine
        return {"events": [e.as_dict() for e in engine.auditor.events()]}

    return router
