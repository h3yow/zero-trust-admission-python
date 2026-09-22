# 策略驱动的零信任请求准入与限流防护

在既有 FastAPI 服务（`GET /` 行为完全兼容）之上，实现了一套**声明式策略、
零信任默认拒绝、按身份/资源维度限流与并发约束、判定全程可审计**的请求准入层。
全部能力可在本地验证，不依赖任何外部服务或凭据。

## 1. 架构与模块

| 模块 | 职责 |
| --- | --- |
| `zero_trust_admission/model.py` | 身份 `Principal`、请求 `AccessRequest`、规则 `Rule`、限流策略 `RateLimitPolicy`、文档 `PolicyDocument`、判定结果与审计记录等领域类型 |
| `zero_trust_admission/errors.py` | 策略装载阶段可区分错误：格式错误 / 版本不兼容 / 规则冲突 / 语义非法 |
| `zero_trust_admission/policy_store.py` | 策略解析、严格校验、版本检查、冲突检测、原子替换与合并 |
| `zero_trust_admission/limiter.py` | 滑动日志窗口限流 + 每键信号量并发限制，时间源可注入 |
| `zero_trust_admission/audit.py` | 审计 sink 抽象、JSONL 文件 sink（逐条 fsync）、内存/故障 sink |
| `zero_trust_admission/admission.py` | 判定流水线编排、审计失败策略、下游异常两阶段审计 |
| `zero_trust_admission/app.py` | FastAPI 装配层与 HTTP 接口 |
| `zero_trust_admission/cli.py` | 本地策略校验 / 启动服务 |
| `policies/default.json` | 默认策略示例 |

## 2. 策略模型

一份策略文档（schema `1.0`）包含若干**准入规则**与**限流策略**：

```json
{
  "schema_version": "1.0",
  "rules": [
    {
      "name": "allow-dev-read",
      "effect": "allow",
      "identities": ["*"],
      "groups": ["dev"],
      "resources": ["docs"],
      "actions": ["read"],
      "priority": 10
    }
  ],
  "rate_limits": [
    {
      "name": "rl-docs",
      "identities": ["*"],
      "groups": [],
      "resources": ["docs"],
      "rate_limit": 5,
      "rate_window_seconds": 1.0,
      "concurrency": 2
    }
  ]
}
```

- **维度**：身份（`identities` 精确名 / `*`）、组（`groups`，空表示不限定）、
  资源（`resources`）、动作（`actions`：`read`/`write`/`delete`/`*`）。
- **效果与优先级**：每条规则 `allow` 或 `deny`。所有命中规则中
  **优先级数值最大者生效**（同分时按名称字典序，保证确定性）；没有任何规则
  命中时按零信任原则**默认拒绝**（`no_matching_policy`），不会回退到宽松规则。
- **冲突检测（生效前拒绝，绝不静默放行）**：同优先级、效果相反且匹配空间
  （身份/组/资源/动作）相交的两条规则构成冲突。文档内部冲突与"新策略合并到
  既有规则"的跨文档冲突都会被拒绝。错误码可区分：
  - `policy_format_error`：不是合法 JSON 或字段类型/必填错误；
  - `policy_version_incompatible`：`schema_version` 不在支持列表（`1.0`）；
  - `policy_validation_error`：语义非法（非法动作、阈值 ≤ 0、窗口与阈值
    未成对提供、规则重名等）；
  - `policy_conflict`：规则冲突或合并时名称重复。
- **稳定可复现**：更新在锁内完成引用的原子替换（`replace`）或合并
  （`merge`）；校验失败时在运策略保持不变。时间源在判定时可注入，测试
  结果确定。

## 3. 限流与并发语义

- 限流与并发均以 **(身份, 资源)** 为独立计数键：不同身份的计数物理隔离，
  **不跨身份串号**；同一身份访问不同资源也互不影响。
- **滑动日志窗口**：仅保留窗口内时间戳；第 N+1 个请求被拒，窗口滑动后自动
  恢复。时间来源可注入，判定确定且可复现。
- **被拒请求不占配额**：限流拒绝的请求不登记时间戳（重复超限不会造成计数
  漂移）；若在后续的并发/审计阶段被拒，此前已登记的时间戳会被**精确撤回**，
  不会误伤未超限的正常流量。
- **并发约束**：每键 `BoundedSemaphore`。获取失败返回可区分原因
  `concurrency_limited`；下游成功或异常都会在 `finally` 中确定性释放。
- **多策略命中**时选择约束维度最具体的一条（显式身份 > 组 > 通配，
  显式资源 > 通配资源），同分按名称确定性裁决。
- 拒绝原因全部可区分：`no_matching_policy` / `explicit_deny` /
  `rate_limited` / `concurrency_limited` / `audit_unavailable`。

### 判定流水线

```
规则匹配 ──(无命中)──▶ 默认拒绝 no_matching_policy
        ──(最高优先级 deny)──▶ 显式拒绝 explicit_deny
        ──(allow)──▶ 滑动窗口限流 ──超限──▶ rate_limited（不登记）
                      ──通过──▶ 并发信号量 ──失败──▶ concurrency_limited（撤回限流登记）
                                  ──获取──▶ 写审计 ──失败且 fail_closed──▶
                                               释放槽+撤回登记 → audit_unavailable
                                            ──成功/ fail_open──▶ 执行下游
                                  下游 finally：释放槽 + 写 downstream 审计（含异常链路）
```

## 4. 审计语义与"审计不可用"策略

- 每次判定（允许**和**拒绝）都写一条 `admission` 审计；`execute_guarded`
  执行下游后再写一条 `downstream` 审计，字段包含最终判定、拒绝原因、命中
  规则、限流策略、请求摘要以及 `downstream_error`，**记录与实际判定严格一致**。
- JSONL sink 每条记录 `flush + fsync`，保证"已放行即有记录"。
- 审计写入失败时失败模式显式可配置：
  - **`fail_closed`（默认，零信任）**：审计不可用则拒绝请求
    （`audit_unavailable`），释放并发槽并撤回限流登记，杜绝"已放行却无记录"；
  - **`fail_open`（显式降级）**：允许请求，但记录进入有界内存缓冲
    （可通过统计接口观测到 `audit_write_failures` 与缓冲条数），判定依据
    日志中明示本次为降级放行。
- 拒绝路径的审计写失败不改变拒绝结论；下游阶段的审计写失败只缓冲，
  不会改变已发生的准入事实。

## 5. HTTP 接口

| 方法与路径 | 说明 |
| --- | --- |
| `GET /` | 既有接口，保持 `{"Hello": "World"}` 不变 |
| `POST /api/v1/evaluate` | 提交 `{principal, resource, action}` 做准入+限流判定；允许 200，拒绝 403 并给出可区分 `reason` |
| `GET /api/v1/resources/{name}?identity=&group=` | 受保护资源示例；拒绝不触达下游，下游异常返回 502 且审计保留异常链路 |
| `GET /api/v1/policy` | 查看当前生效策略 |
| `PUT /api/v1/policy` | 原子替换策略；非法/版本不兼容/冲突返回 422 与可区分 `error_code`，在运策略不变 |
| `GET /api/v1/audit/stats` | 判定计数、审计写失败数、降级缓冲条数与失败模式 |

启动（默认读取 `policies/default.json`，审计写入 `./audit.log`）：

```bash
uv run python -m zero_trust_admission.cli serve
# 或：uv run uvicorn main:app
```

环境变量：`ZTA_POLICY_PATH`、`ZTA_AUDIT_PATH`、
`ZTA_AUDIT_FAILURE_MODE=fail_closed|fail_open`。

## 6. 本地验证方法

所有验证均可离线完成：

```bash
# 1) 全量单测（46 个），含并发超限、非法策略、下游异常场景；
#    zero_trust_admission logger 会打印"准入判定输入"与"准入判定依据"
uv run python -m pytest
uv run python -m pytest --log-cli-level=INFO   # 实时查看每条判定的输入与依据

# 2) 策略本地校验（替换语义）
uv run python -m zero_trust_admission.cli validate policies/default.json

# 3) 策略合并校验：新策略是否与既有规则冲突/重名
uv run python -m zero_trust_admission.cli validate new-policy.json \
    --base policies/default.json
# 非法时退出码为 2，并输出 policy_format_error / policy_version_incompatible /
# policy_validation_error / policy_conflict 之一

# 4) 手工体验
curl -s localhost:8000/
curl -s -X POST localhost:8000/api/v1/evaluate -H 'content-type: application/json' \
  -d '{"principal":{"identity":"alice","groups":["dev"]},"resource":"docs","action":"read"}'
```

测试覆盖（`tests/`）：

- `test_policy.py`：非法 JSON / 字段、版本不兼容、语义非法、重名、同优先级
  冲突、跨文档合并冲突、更新失败不污染在运策略；
- `test_limiter.py`：滑动窗口恢复、多身份/多资源键隔离、重复超限计数不漂移、
  配额撤回、并发信号量隔离与释放、最具体策略选择；
- `test_concurrency.py`：16 线程 × 20 次突发下放行数严格等于阈值、
  三身份混合计数不串号、两阶段栅栏下并发上限精确、同一突发中多类拒绝原因
  可区分且审计条数与判定总数一致；
- `test_admission.py`：默认/显式拒绝原因可区分、被拒不占配额、审计与判定
  一致、fail_closed 拒绝并释放槽位、fail_open 缓冲放行、下游异常审计与
  确定性释放、被拒不触达下游、策略热更新即时生效；
- `test_app.py`：根路由兼容、HTTP 状态/原因码、策略热更新失败不影响在运
  策略、JSONL 审计落盘。
