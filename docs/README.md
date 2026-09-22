# 零信任请求准入与限流防护 — 总览

本服务在既有 FastAPI 应用之上实现了一层**策略驱动（policy-driven）**的零信任准入
控制层。核心原则：

- **默认拒绝（default-deny）**：任何身份/资源/动作若没有命中允许规则，一律拒绝；
- **显式拒绝优先**：同一请求同时命中 allow 与 deny 时，deny 生效；
- **判定确定可复现**：规则按声明顺序匹配，限流/并发操作原子完成；
- **失败即关闭（fail-closed）**：策略非法、审计不可用等异常绝不静默放行；
- **全程可解释**：每次判定都有可区分的 `reason_code`、INFO 级判定日志与审计记录。

## 目录

- [策略模型](./policy.md)：声明式策略文档格式、匹配语义、版本与冲突处理
- [限流与并发语义](./rate-limiting.md)：固定窗口、键隔离、审计一致性保证
- [验证方法](./verification.md)：如何运行测试、手工验证各类场景

## 模块结构

```
admission/
├── model.py       # 策略/身份/请求/判定的不可变领域模型
├── errors.py      # 全部可区分错误原因码（reason_code）
├── parser.py      # JSON 策略解析、结构校验、版本检查、冲突检测
├── store.py       # 策略仓库：全部校验通过后原子发布，失败保留旧策略
├── ratelimit.py   # 固定窗口限流器 + 每键独立并发信号量（线程安全）
├── audit.py       # 审计事件模型与内存后端（可模拟不可用）
├── engine.py      # 判定引擎：匹配→限流→并发→审计→下游→完成审计
├── config.py      # 启动期从本地文件加载默认策略（零外部依赖）
└── api.py         # HTTP 路由：受保护资源 + 策略管理 + 审计查询
policies/
└── default_policy.json   # 启动默认策略（本地文件，无需任何凭据）
main.py            # 应用入口；GET / 保持 {"Hello": "World"} 不变
tests/             # 39 个测试：解析/仓库/限流/引擎/HTTP
```

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 既有接口，行为完全保持不变（不经引擎） |
| GET | `/healthz` | 受引擎保护的健康检查 |
| GET | `/api/resources/documents/{path}` | 受保护文档读取（演示限流/并发/拒绝） |
| POST | `/api/echo` | 受保护回显；body 支持 `delay`（触发并发）与 `fail`（触发下游异常） |
| GET | `/admin/policy` | 查看当前生效策略 |
| PUT | `/admin/policy?expected_current_version=N` | 提交新策略（乐观版本控制） |
| GET | `/admin/audit` | 查看全部审计事件 |

身份通过请求头声明（本地演示，无外部 IdP 依赖）：

- `X-User`：用户名；`X-Roles` / `X-Groups`：逗号分隔；`X-Request-ID`：链路 ID（缺省自动生成）。

## 拒绝原因码（可区分、可对账）

| reason_code | HTTP | 含义 |
| --- | --- | --- |
| `DENY_NO_MATCHING_RULE` | 403 | 默认拒绝：无规则匹配 |
| `DENY_EXPLICIT_RULE` | 403 | 命中显式 deny 规则 |
| `RATE_LIMIT_EXCEEDED` | 429 | 固定窗口限流（响应/审计/日志中带当前计数与上限） |
| `CONCURRENCY_LIMIT_EXCEEDED` | 429 | 在途并发上限已满（与限流同状态码但原因码不同） |
| `DOWNSTREAM_ERROR` | 502 | 下游处理抛异常（已写完成审计） |
| `AUDIT_UNAVAILABLE` | 500 | 审计后端不可用，按 fail-closed 拒绝放行 |
| `POLICY_INVALID` | 400 | 策略结构/字段非法 |
| `POLICY_VERSION_INCOMPATIBLE` | 409 | apiVersion/kind 不支持，或版本不连续/乐观锁失败 |
| `POLICY_CONFLICT` | 409 | 与既有规则同选择器但效果/约束冲突 |
| `POLICY_NOT_FOUND` | 503 | 尚无生效策略（fail-closed） |
