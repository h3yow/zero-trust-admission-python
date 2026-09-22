"""启动期本地策略加载：纯本地文件，不依赖任何外部服务或凭据。"""

from __future__ import annotations

import json
from pathlib import Path

from admission.errors import AdmissionError
from admission.store import PolicyStore

DEFAULT_POLICY_PATH = (
    Path(__file__).resolve().parent.parent / "policies" / "default_policy.json"
)


def load_default_policy(store: PolicyStore, path: Path = DEFAULT_POLICY_PATH) -> None:
    """从本地 JSON 文件加载策略到仓库。

    文件缺失、JSON 非法或策略校验失败都直接抛出（fail-closed，拒绝启动），
    绝不静默回退到“无策略=全放行”。
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AdmissionError(f"默认策略文件不可读: {path}: {exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        from admission.errors import PolicyValidationError

        raise PolicyValidationError(f"默认策略 JSON 非法: {path}: {exc}") from exc
    store.load_dict(raw)
