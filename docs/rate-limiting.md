# 限流与并发语义

## 1. 固定窗口限流（rateLimit）

- 每条 allow 规则可声明 `rateLimit: {maxRequests, windowSeconds}`；
- 采用**固定窗口计数**：窗口起点由该键第一次请求确定，窗口内累计请求数，
  达到 `maxRequests` 后同窗口内的请求返回 `RATE_LIMIT_EXCEEDED`；
  新窗口开始时计数归零，**不会误伤窗口后的正常流量**。
- “检查 + 占用”在同一把锁内一次完成，因此在**突发流量与重复请求**下：
  成功数恰好等于上限，计数不会漂移、不会多放，也不会少算。

## 2. 计数键：身份 × 资源 × 动作 × 规则

计数键的完整结构：

```
("rl", rule_id, user, sorted(roles), sorted(groups),
 resource_type, resource, action)
```

因此：

- 不同用户之间**绝不共享计数**（不跨身份串号）；
- 同一用户的不同资源、不同 HTTP 动作也分别计数；
- 多身份混合突发时，A 打满只影响 A 自己，B 的正常请求不被误伤
  （见 `tests/test_ratelimit.py::test_identities_never_share_counters`
  与 `tests/test_api.py::test_mixed_identity_concurrent_burst_is_isolated`）。

被限流的请求**不调用下游**，只写一条 `decision/denied/RATE_LIMIT_EXCEEDED` 审计，
审计原因里带当前计数与窗口上限，便于解释。

## 3. 配额回滚不漂移

请求若在占用限流配额**之后**没有真正进入下游，引擎会回滚本次占用：

- **并发槽获取失败**：无论审计写入成功、失败还是 fail-open，该请求都被拒绝、
  未调用下游，因此限流配额一律回滚——被并发拒绝的请求不会挤占后续正常流量；
- **decision 审计不可用（fail-closed）**：回滚限流配额并释放已获取的并发槽；
- 回滚只在当前窗口内、计数 >0 时扣减，**不会变负**，也不会跨旧窗口回滚；
- 注意：已经在下游执行中的请求占用的配额在其完成前不回滚（这是正确语义，
  它确实在消耗在途容量）。

## 4. 并发约束（concurrencyLimit）

- 每个计数键持有一个独立的 `BoundedSemaphore(maxInFlight)`；
- 获取不到槽位立即返回 `CONCURRENCY_LIMIT_EXCEEDED`（不排队、不阻塞）；
- 槽位在 `finally` 中释放——**无论下游成功、抛异常还是完成审计失败都释放**，
  不泄漏；
- 与限流同样按完整复合键隔离，不同身份互不影响；
- 与限流 HTTP 状态码同为 429，但 `reason_code` 不同，日志与审计可区分。

## 5. 判定链路顺序（固定，确定可解释）

```
取策略快照
  → 规则匹配（deny 优先 → 首个 allow → 默认拒绝）
  → 固定窗口限流 try_acquire（失败：记 denied 审计 → RATE_LIMIT_EXCEEDED）
  → 并发槽 try_acquire（失败：回滚限流配额 → 记 denied 审计 → CONCURRENCY_LIMIT_EXCEEDED）
  → 写 decision/allowed 审计（失败：回滚全部配额 → AUDIT_UNAVAILABLE，绝不在无记录时放行）
  → 调用下游
       异常 → 写 completion/downstream_error 审计 → DOWNSTREAM_ERROR（502）
  → 写 completion/allowed 审计（失败 → AUDIT_UNAVAILABLE 显式暴露）
  → 释放并发槽（finally）
```

被拒绝（默认拒绝/显式拒绝）的请求也同样先写审计再返回拒绝；若此时审计不可用，
默认以 `AUDIT_UNAVAILABLE` 失败，而不是产生一条无法解释的拒绝。

## 6. 审计可用性策略（明确且可解释）

引擎构造参数 `fail_open_on_audit` 决定审计不可用时的行为：

- **`false`（默认，fail-closed，推荐）**：审计写不进去就不放行，已占用配额回滚，
  返回 `AUDIT_UNAVAILABLE`。不会出现“已放行却无记录”；
- `true`（显式 fail-open）：仅在可接受“无记录放行”的环境开启，放行时打印
  ERROR 级日志，行为由开关显式决定，而非隐式回退。

审计一致性保证：

| 实际情况 | decision 事件 | completion 事件 | 客户端结果 |
| --- | --- | --- | --- |
| 放行且下游成功 | `allowed` | `allowed` | 200 |
| 放行但下游异常 | `allowed` | `downstream_error` | 502 `DOWNSTREAM_ERROR` |
| 限流/并发/规则拒绝 | `denied/<原因码>` | 无 | 429/403 |
| 审计后端宕机 | 无法写入 | — | 500 `AUDIT_UNAVAILABLE`（配额回滚） |

每条事件是不可变值对象，含 `request_id / rule_id / user / resource / action /
policy_version / reason_code`，可通过 `GET /admin/audit` 与最终判定逐条对账。

## 7. 可观测日志

引擎对每个请求打印两条 INFO 日志：

- `策略输入 ...`：完整策略输入（策略名/版本、身份、角色、组、资源、动作、request_id）；
- `判定依据 ... -> ALLOW|DENY(reason_code) ...`：命中规则、限流/并发参数或当前计数。

pytest 已配置 `--log-cli-level=INFO`，运行测试即可在日志中看到上述输入与依据。
