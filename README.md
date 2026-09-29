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
| `zero_trust_admission/limiter.py` | 滑动日志窗口限流 + 每键信号量并发限制；含最具体单条选择（老模式）与按层独立计数的多层绑定/令牌撤回（分层模式），时间源可注入 |
| `zero_trust_admission/audit.py` | 审计 sink 抽象、JSONL 文件 sink（逐条 fsync）、内存/故障 sink |
| `zero_trust_admission/admission.py` | 判定流水线编排、审计失败策略、下游异常两阶段审计 |
| `zero_trust_admission/app.py` | FastAPI 装配层与 HTTP 接口 |
| `zero_trust_admission/cli.py` | 本地策略校验 / 启动服务 |
| `policies/default.json` | 默认策略示例（老模式，行为与分层能力上线前一致） |
| `policies/layered.example.json` | 多层配额叠加示例（身份/组/全局三层） |

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
- **限流叠加模式**（可选顶层字段 `rate_limit_mode`）：缺省/`most_specific`
  为老行为（只取最具体一条）；`layered` 为多层叠加，语义见 [3.1 节](#31-多层配额叠加rate_limit_mode-layered)。
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
- **多策略命中**时，默认（`"rate_limit_mode": "most_specific"`）选择约束维度
  最具体的一条（显式身份 > 组 > 通配，显式资源 > 通配资源），同分按名称
  确定性裁决——这是分层能力上线前的既有行为，保持不变。
- 拒绝原因全部可区分：`no_matching_policy` / `explicit_deny` /
  `rate_limited` / `concurrency_limited` / `audit_unavailable`。

### 3.1 多层配额叠加（`rate_limit_mode: "layered"`）

业务中一个请求往往要同时受**好几档**配额约束：它自己这一档、所在组/租户
那一档、再到资源整体那一档。把文档顶层显式配成 `"rate_limit_mode": "layered"`
后，所有命中该请求的限流策略**各自成为一层独立配额**，请求必须**逐层通过**：

- **任一层拒绝即整体拒绝**，其余层不再检查（短路）；只有全部层放行才算放行。
- 拒绝结果会固定带出**每一层的阈值与当时用量**（`rate_layers`），并标出
  具体是哪一层、卡在限流还是并发（拦截层 `denied_at` 为 `rate_limit` /
  `concurrency`，其后未检查的层标记为 `short_circuit`）。老字段
  `rate_limit` / `rate_limit_name` 在分层拒绝时指向拦截层，便于老消费方解释。
- **判定与展示顺序固定**，只依赖策略内容与在文档中的声明位置，与并发时序、
  策略名称无关：
  1. 层特异性降序：显式身份 > 组匹配 > 全局通配；资源显式 > 资源通配；
  2. 特异性相同则按策略在文档中的**声明顺序**升序。
- **每层有各自独立的窗口、阈值、信号量与计数桶**，层与层之间、身份与身份
  之间、资源与资源之间互不串号。

#### 配额桶（层计数作用域）如何确定

一条命中策略对某个身份落到哪个桶，按其身份/组声明确定（资源维度独立拼接）：

| 策略声明 | 桶作用域 | 共享范围 |
| --- | --- | --- |
| `identities` 显式列出该身份 | `identity` | 每个身份各自独立计数 |
| `identities: ["*"]` 且 `groups` 非空且命中 | `group` | 同组所有成员共享一档 |
| `identities: ["*"]` 且未限定组 | `global` | 资源整体一档 |

身份同时命中一条策略列出的多个组时，取**字典序最小**的命中组作为桶，保证
绑定确定、不随并发漂移。因此"每身份一档"必须在 `identities` 里**显式列出
身份**（或用多条策略）；`["*"]` 不带组永远是全局档。完整示例见
[`policies/layered.example.json`](policies/layered.example.json)。

#### 名额精确账（与线上验收一致：不注入时间，真实时钟压测）

- 被某层拒掉的请求：该层**不登记**时间戳、不获取信号量；本次请求在此前各层
  已登记的限流名额、已获取的并发槽会被**精确退回**，不占任何一层的名额。
- 撤回按每次登记的**唯一令牌**进行（真实时钟下并发线程可能拿到完全相同的
  时间戳，按时间戳撤会误撤同桶别人的名额）；回滚顺序固定为先撤限流登记、
  再放并发槽。
- 在并发获取之后、审计写入阶段才被拒（fail_closed）时，所有层的登记与槽位
  同样整体回滚。
- 峰值过去后，每层按**各自的窗口**独立恢复，互不影响。

#### 与老策略的兼容范围（什么情况下才会叠加）

- **默认不叠加**。文档不写 `rate_limit_mode` 或写成 `"most_specific"` 时，
  判定结果、拒绝原因、`detail` 文案、HTTP 响应字段、JSONL 审计字段
  （**不含** `rate_layers` 键）都与升级前逐条一致，本来能过的合规请求不会被
  新逻辑误伤——既有用例已完整回归验证。
- 只有文档**显式**配置 `"rate_limit_mode": "layered"` 时，才进入多层叠加路径；
  无需改动任何老策略文件即可继续按老行为运行，想启用分层时使用一份带该字段
  的新文档（或示例文件）替换/装载即可。
- 策略**合并**（`merge`）时叠加模式沿用在运文档的设置，分片策略不能各自
  改变全局模式。
- 分层模式放行的结果，HTTP 响应与审计记录会**额外**携带 `rate_layers`；
  老模式响应与审计的字段集合保持不变。

### 判定流水线

老模式（`most_specific`，默认）：

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

分层模式（`layered`）：规则通过后，按固定顺序对**每一个命中层**依次执行
「滑动窗口限流 → 并发信号量」；任一层失败即短路并把此前各层已登记名额与
已获取槽位**精确回滚**，返回 `rate_limited` / `concurrency_limited` 并在
`rate_layers` 中给出拦截层与各层用量；全部通过后再写审计（fail_closed
写失败同样整体回滚为 `audit_unavailable`）。

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
| `GET /api/v1/policy` | 查看当前生效策略（含 `rate_limit_mode`） |
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
# 1) 全量单测（61 个），含多层叠加、真实时钟并发退回、并发超限、
#    非法策略、下游异常、老策略兼容等场景；
#    zero_trust_admission logger 会打印"准入判定输入"与"准入判定依据"
uv run python -m pytest
uv run python -m pytest --log-cli-level=INFO   # 实时查看每条判定的输入与依据

# 静态检查（与 CI 一致的规则集）
uv run ruff check .

# 2) 策略本地校验（替换语义），含分层示例策略
uv run python -m zero_trust_admission.cli validate policies/default.json
uv run python -m zero_trust_admission.cli validate policies/layered.example.json

# 3) 用分层示例策略起服务（不修改老的 default.json）
ZTA_POLICY_PATH=policies/layered.example.json \
  uv run python -m zero_trust_admission.cli serve
# 然后连续请求观察多层放行 -> 某层拦截的 rate_layers：
curl -s -X POST localhost:8000/api/v1/evaluate -H 'content-type: application/json' \
  -d '{"principal":{"identity":"alice","groups":["dev"]},"resource":"docs","action":"read"}'

# 4) 策略合并校验：新策略是否与既有规则冲突/重名
uv run python -m zero_trust_admission.cli validate new-policy.json \
    --base policies/default.json
# 非法时退出码为 2，并输出 policy_format_error / policy_version_incompatible /
# policy_validation_error / policy_conflict 之一

# 5) 手工体验（默认策略）
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
- `test_layered.py`：多层叠加与固定顺序（特异性 + 声明顺序，不随名称/并发
  变化）、各层拦截时阈值/用量可解释、被组层拦时身份层名额精确退回、并发层
  拦截时前层槽位退回、分层模式显式 opt-in、老模式（`most_specific`）结果与
  JSONL 审计字段逐项兼容、分层 HTTP 响应结构；
- `test_layered_concurrency.py`：**真实时钟**（不注入 `now`）多线程验收——
  16×20 突发下被全局层拒的请求不占身份层/全局层名额、多身份+组+全局混合
  各层计数不漂不串、资源桶不共享、峰值过后各窗口独立恢复、并发层拒绝精确
  退回前序所有层槽位。
