# zero-trust-admission-python

策略驱动的零信任请求准入与限流防护（FastAPI）。

- 默认拒绝、显式拒绝优先；策略声明式、可版本化、冲突可检测
- 按 身份×资源×动作×规则 隔离的固定窗口限流与并发约束，并发下计数不漂移、不串号
- 判定全程审计；审计不可用时默认 fail-closed，杜绝“已放行却无记录”
- 全部本地验证，无外部服务/凭据依赖
- 既有 `GET /` 行为完全保持不变

## 快速开始

```bash
uv sync
uv run pytest                       # 39 个测试（含判定日志）
uv run uvicorn main:app --reload    # http://127.0.0.1:8000
```

## 文档

- [总览与接口/原因码](docs/README.md)
- [策略模型](docs/policy.md)
- [限流与并发语义、审计一致性](docs/rate-limiting.md)
- [验证方法](docs/verification.md)
