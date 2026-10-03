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

### 2.1 配额模式：单条最具体（single）与多层叠加（layered）

限流策略有两种生效模式，由文档顶层 `quota.mode` 决定：

```json
{
  "schema_version": "1.0",
  "quota": { "mode": "layered" },
  "rules": [ ... ],
  "rate_limits": [ ... ]
}
```

- **`single`（默认）**：一个请求只受**一条**命中策略（最具体的一条）
  约束。这是历史行为，不写 `quota` 段的老策略一律走这条路。
- **`layered`**：请求通过准入后，**所有命中的限流策略同时作为多个配额层
  生效**：个人这一档、所在组/租户那一档、资源整体那一档各自独立计数，
  **任一层不过即拒绝，所有层都放行才真正放行**。

多层叠加的判定与展示规则：

- **固定顺序，不随并发或命名漂移**：按层的具体度降序判定——
  显式身份层 > 组（租户）层 > 通配身份的资源整体层；**同具体度**（例如同时
  命中两个组层、或两个资源整体层）时，严格按各层在策略文件 `rate_limits`
  数组里的**书写位置**先后判定。排序键只含具体度，同分时由稳定排序保留
  文件先后顺序，**层名完全不参与排序**：只改某一层的名字、不动书写位置，
  判定与展示顺序绝不换位；要调整同具体度层的先后，只能调整它们在文件里
  的书写位置。该顺序是策略文档的纯函数，无论并发多高、是否真实时钟，
  结果都逐次一致。
- **拦截归因唯一**：一次请求若有多层同时够格拦截（如一层窗口已满、另一层
  并发已满），由上述固定顺序中**最靠前**的层承担拦截，对外
  `rate_limit_policy` 与 `reason`（`rate_limited` / `concurrency_limited`）
  随之唯一确定——改名不会让另一层顶包、也不会把限流变成并发；只有调整
  书写位置才会有意改变归因。
- **拦截可解释**：被拒响应/结果的 `rate_limit_policy` 指向第一个拦截层，
  `quota_layers` 按固定顺序列出每一层的 `used`（当时窗口用量）、
  `threshold`（阈值）、`in_flight`（在途并发）、`concurrency`（并发上限）
  与 `scope`（计数归属）。因短路尚未判定到的层标记 `"allowed": null`，
  但静态阈值仍完整展示，层链一目了然。
- **计数归属（scope）**：显式身份策略归属 `identity:<身份>@<资源>`；
  组策略归属 `group:<组名>@<资源>`（一个身份同时属于多个命中组时，取名称
  字典序最小的组，保证计数桶唯一）；通配身份策略归属
  `resource:<资源>` 的资源整体层。每个策略层的窗口/信号量相互独立，
  同资源多档配额不共用计数。
- **被拒不占任何一层名额**：某层限流拒绝时该层本身不登记；此前各层已经
  登记的限流时间戳被**精确撤回**、已获取的并发槽被**逐层释放**。在后面的
  并发阶段或审计阶段（fail_closed）被拒时，前面所有层的登记同样精确退回，
  未超限的正常流量不会被误伤。
- **各层独立恢复**：峰值过去后每层按自己的 `rate_window_seconds` 滑动恢复，
  互不影响。
- 判定使用同一个真实单调时钟读数贯穿所有层（测试仍可注入 `now` 得到
  确定性结果）。

**与老策略的兼容范围（到底什么时候才叠加）**：

- 老策略文件没有 `quota` 段，解析后 `quota_mode` 缺省为 `single`，
  判定结果、拒绝原因、`detail` 文案、HTTP 响应字段集合（不含
  `quota_layers`）与历史完全一致，合规请求不会被新逻辑误伤；
- 要使用分层，二选一即可，**老策略文件本身可以一个字都不改**：
  1. 在（新的）策略文档里显式写 `"quota": {"mode": "layered"}`
     （参考 `policies/layered-example.json`）；
  2. 装配 `AdmissionGuard(..., quota_mode="layered")` 在代码侧显式覆盖，
     直接对既有 single 文档启用分层。
- `quota.mode` 只接受 `single` / `layered`，非法值在策略装载期以
  `policy_validation_error`（`quota` 段类型错误为 `policy_format_error`）
  拒绝，不改变在运策略。

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
- **多策略命中**：
  - `single` 模式（默认，老策略）：只选择约束维度最具体的一条
    （显式身份 > 组 > 通配，显式资源 > 通配资源），同分按名称确定性裁决；
  - `layered` 模式：所有命中策略按相同的具体度顺序**逐层叠加**
    （同具体度按文件书写位置，与层名无关），
    任一层不过即拒绝，详见 [2.1 配额模式](#21-配额模式单条最具体single与多层叠加layered)。
- 拒绝原因全部可区分：`no_matching_policy` / `explicit_deny` /
  `rate_limited` / `concurrency_limited` / `audit_unavailable`。

### 判定流水线

```
规则匹配 ──(无命中)──▶ 默认拒绝 no_matching_policy
        ──(最高优先级 deny)──▶ 显式拒绝 explicit_deny
        ──(allow)──▶ 配额判定（按 quota.mode 分流）
   single（默认，老策略）：选最具体一条
        滑动窗口限流 ──超限──▶ rate_limited（不登记）
                  ──通过──▶ 并发信号量 ──失败──▶ concurrency_limited（撤回限流登记）
   layered：命中层按 身份 > 组 > 资源整体 的固定顺序逐层判定
        （同具体度按文件书写位置，层名不参与排序）
        某层限流超限 ──▶ rate_limited（精确撤回此前各层登记、释放各层槽位）
        某层并发槽满 ──▶ concurrency_limited（同上，精确退回此前各层名额）
        全部层通过 ─────────────────────────────┐
                                  ──获取──▶ 写审计 ──失败且 fail_closed──▶
                                               释放全部槽+撤回全部登记 → audit_unavailable
                                            ──成功/ fail_open──▶ 执行下游
                                  下游 finally：释放全部持有槽 + 写 downstream 审计（含异常链路）
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
| `POST /api/v1/evaluate` | 提交 `{principal, resource, action}` 做准入+限流判定；允许 200，拒绝 403 并给出可区分 `reason`。layered 模式额外返回 `quota_layers`：每层的顺序、策略、归属、当时用量/阈值/在途并发与是否放行 |
| `GET /api/v1/resources/{name}?identity=&group=` | 受保护资源示例；拒绝不触达下游，下游异常返回 502 且审计保留异常链路 |
| `GET /api/v1/policy` | 查看当前生效策略（含 `quota_mode`） |
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
# 1) 全量单测（78 个），含并发超限、多层叠加、真实时钟并发验收、
#    非法策略、下游异常场景；
#    zero_trust_admission logger 会打印"准入判定输入"与"准入判定依据"
uv run python -m pytest
uv run python -m pytest -v                     # 按业务模块逐条列出用例与结果
uv run python -m pytest --log-cli-level=INFO   # 实时查看每条判定的输入与依据

# 2) 策略本地校验（替换语义）
uv run python -m zero_trust_admission.cli validate policies/default.json
uv run python -m zero_trust_admission.cli validate policies/layered-example.json

# 3) 策略合并校验：新策略是否与既有规则冲突/重名
uv run python -m zero_trust_admission.cli validate new-policy.json \
    --base policies/default.json
# 非法时退出码为 2，并输出 policy_format_error / policy_version_incompatible /
# policy_validation_error / policy_conflict 之一

# 4) 用分层示例策略启动服务（不改老的 default.json 即可体验多层叠加）
uv run python -m zero_trust_admission.cli serve --host 127.0.0.1 --port 8000 &
# 或： ZTA_POLICY_PATH=policies/layered-example.json uv run uvicorn main:app &

# 5) 手工体验：alice 同时受 个人(5/s) / dev 组(20/s) / 资源整体(100/s) 三档约束，
#    连续打到第 6 次会看到 reason=rate_limited、rate_limit_policy 指向个人层，
#    quota_layers 按 身份→组→资源整体 固定顺序给出每层用量与阈值
for i in $(seq 1 7); do
  curl -s -X POST localhost:8000/api/v1/evaluate \
    -H 'content-type: application/json' \
    -d '{"principal":{"identity":"alice","groups":["dev"]},"resource":"docs","action":"read"}'
  echo
done
```

测试覆盖（`tests/`）：

- `test_policy.py`：非法 JSON / 字段、版本不兼容、语义非法、重名、同优先级
  冲突、跨文档合并冲突、更新失败不污染在运策略；
- `test_limiter.py`：滑动窗口恢复、多身份/多资源键隔离、重复超限计数不漂移、
  配额撤回、并发信号量隔离与释放、最具体策略选择；
- `test_layered_quota.py`：多层同时约束且各层独立计数、顺序不随定义顺序/
  命名变化、同具体度严格按文件书写位置（改名不换位、调换书写位置才换位）、
  多层同时够格拦截时拦截层与拒绝原因由固定顺序唯一决定（改名不改变归因，
  调换书写位置则归因跟随新位置）、中层拦截的自我归因、短路层标记与阈值
  展示、限流/并发/审计三类拦截的名额精确退回、并发-only 层与跨资源隔离、
  各层按自己窗口恢复；
- `test_layered_concurrency.py`：**真实时钟（不注入 `now`）**下 24 线程
  混合多身份/多组/多资源突发，放行数严格等于各层阈值推导的期望（个人层
  合计先耗尽）、所有拒绝归因正确且拦截只发生在先耗尽的个人层、组层/全局层
  用量精确等于其合规放行数（反证被拒流量没有占用/串用任何一层名额）、
  跨资源计数完全隔离、审计条数与判定总数一致；真实时钟下撞并发层时
  前层限流名额精确退回；以及同具体度三层故意按"名字字典序与书写顺序相反"
  排列的 16 线程突发：每一次判定的层链顺序都恒等于书写位置序、拦截归因
  唯一、各层计数精确不漂；
- `test_layered_compat.py`：老文档缺省 single、老结果无层链、老 HTTP 载荷
  键集合逐一对齐（不出现 `quota_layers`）、guard 覆盖参数不改文件启用分层、
  `quota.mode` 解析与非法值可区分拒绝、layered HTTP 载荷各层阈值/用量/
  作用域完整；
- `test_concurrency.py`：16 线程 × 20 次突发下放行数严格等于阈值、
  三身份混合计数不串号、两阶段栅栏下并发上限精确、同一突发中多类拒绝原因
  可区分且审计条数与判定总数一致；
- `test_admission.py`：默认/显式拒绝原因可区分、被拒不占配额、审计与判定
  一致、fail_closed 拒绝并释放槽位、fail_open 缓冲放行、下游异常审计与
  确定性释放、被拒不触达下游、策略热更新即时生效；
- `test_app.py`：根路由兼容、HTTP 状态/原因码、策略热更新失败不影响在运
  策略、JSONL 审计落盘。
