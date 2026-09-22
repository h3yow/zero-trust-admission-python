"""FastAPI 应用入口：保持既有 GET / 行为兼容，并挂载零信任准入能力。"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from admission.api import build_router, error_status
from admission.audit import InMemoryAuditor
from admission.config import load_default_policy
from admission.engine import AdmissionEngine
from admission.errors import (
    AdmissionError,
    PolicyConflictError,
    PolicyValidationError,
    PolicyVersionError,
)
from admission.store import PolicyStore

logger = logging.getLogger("admission")


def create_app() -> FastAPI:
    app = FastAPI(title="zero-trust-admission-python")

    # 启动期从本地加载声明式策略；非法策略会阻止启动（fail-closed）。
    store = PolicyStore()
    load_default_policy(store)
    auditor = InMemoryAuditor()
    engine = AdmissionEngine(store=store, auditor=auditor)

    app.state.engine = engine
    app.state.auditor = auditor
    app.state.store = store
    app.include_router(build_router())

    @app.exception_handler(AdmissionError)
    async def handle_admission_error(_: Request, exc: AdmissionError) -> JSONResponse:
        # 策略管理类错误：400 非法 / 409 版本或冲突
        if isinstance(exc, PolicyValidationError):
            status = 400
        elif isinstance(exc, (PolicyVersionError, PolicyConflictError)):
            status = 409
        else:
            status = error_status(exc.reason_code)
        logger.warning("准入错误: code=%s reason=%s", exc.reason_code, exc)
        return JSONResponse(
            status_code=status,
            content={
                "allowed": False,
                "error": {"reasonCode": exc.reason_code, "reason": str(exc)},
            },
        )

    @app.get("/")
    def read_root():
        # 保持既有行为完全不变：返回 {"Hello": "World"}
        return {"Hello": "World"}

    return app


app = create_app()
