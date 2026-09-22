"""本地策略校验工具，不依赖任何外部服务或凭据。

用法::

    python -m zero_trust_admission.cli validate policies/default.json
    python -m zero_trust_admission.cli validate new-policy.json --base policies/default.json
    python -m zero_trust_admission.cli serve --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import argparse
import json
import sys

from .errors import PolicyError
from .policy_store import PolicyStore


def _validate(path: str, base: str | None) -> int:
    store = PolicyStore()
    if base is not None:
        try:
            store.load_json_file(base)
        except PolicyError as exc:
            print(f"[拒绝] 基线策略非法 {base}: [{exc.code}] {exc}", file=sys.stderr)
            return 2
    try:
        if base is not None:
            with open(path, encoding="utf-8") as fh:
                doc = store.merge_json(fh.read())
            action = "合并生效"
        else:
            doc = store.load_json_file(path)
            action = "替换生效"
    except PolicyError as exc:
        print(f"[拒绝] 策略 {path} 无法生效: [{exc.code}] {exc}", file=sys.stderr)
        return 2
    print(
        f"[通过] 策略可{action}: schema={doc.schema_version} "
        f"rules={len(doc.rules)} rate_limits={len(doc.rate_limits)}"
    )
    return 0


def _serve(host: str, port: int) -> int:
    import uvicorn

    from .app import app

    uvicorn.run(app, host=host, port=port)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="zta", description="零信任准入策略本地校验与服务"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="校验策略文件能否安全生效")
    v.add_argument("path", help="待校验策略 JSON 文件")
    v.add_argument("--base", help="既有（基线）策略文件；提供时按合并语义校验")
    v.set_defaults(func=lambda a: _validate(a.path, a.base))

    s = sub.add_parser("serve", help="启动 HTTP 服务")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    s.set_defaults(func=lambda a: _serve(a.host, a.port))

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
