# 策略模型

策略是一份**声明式 JSON 文档**，全部规则都可以在本地编辑、本地加载、本地验证，
不依赖任何外部服务、网络或凭据。

## 1. 文档结构

```json
{
  "apiVersion": "zero-trust-admission/v1",
  "kind": "AdmissionPolicy",
  "metadata": {"name": "default", "version": 1},
  "rules": [
    {
      "id": "docs-admin-read",
      "description": "管理员可读取文档",
      "effect": "allow",
      "subject": {"users": ["alice"], "roles": ["admin"], "groups": []},
      "resource": {"type": "document", "patterns": ["docs/*"]},
      "action": {"methods": ["GET"]},
      "rateLimit": {"maxRequests": 3, "windowSeconds": 1.0},
      "concurrencyLimit": {"maxInFlight": 3}
    }
  ]
}
```

| 字段 | 约束 |
| --- | --- |
| `apiVersion` | 必须恰好为 `zero-trust-admission/v1`，否则 `POLICY_VERSION_INCOMPATIBLE` |
| `kind` | 必须为 `AdmissionPolicy` |
| `metadata.name` | 非空字符串 |
| `metadata.version` | ≥1 的整数；更新时必须**正好 +1**（见 §4） |
| `rules[].id` | 同一文档内唯一的非空字符串 |
| `rules[].effect` | `allow` 或 `deny`，其他取值拒绝 |
| `rateLimit` | `maxRequests` 正整数、`windowSeconds` 正数 |
| `concurrencyLimit` | `maxInFlight` 正整数 |

未知顶层字段、未知规则字段、错误类型（布尔/负数/空串等）一律以
`POLICY_INVALID` **明确拒绝并给出字段路径**，绝不静默忽略。

## 2. 三维匹配语义

一条规则命中请求，当且仅当 subject、resource、action 三个维度**同时**匹配。

- **subject（身份）**：
  - `users` / `roles` / `groups` 三个集合之间为 **OR**：请求身份具名命中用户，
    或其任一角色/组在集合中，即匹配；
  - 三个集合全空表示**匹配任意身份（含匿名）**。
- **resource（资源）**：
  - `type` 必须与请求资源类型**精确相等**；
  - `patterns` 使用 shell 通配（`fnmatch`，大小写敏感，`*` 不跨语义边界外做任何特殊处理），
    任一模式匹配即命中；`patterns` 为空表示该类型下**全部资源**。
- **action（动作）**：
  - `methods` 中的 HTTP 方法（解析时统一转大写），为空表示匹配全部动作。

## 3. 多规则命中的确定性优先级

对规则按**声明顺序**扫描，输出是确定的：

1. 任何命中的 `deny` 规则立即生效（**显式拒绝优先于 allow**）；
2. 否则取第一条命中的 `allow` 规则；
3. 没有任何命中 → `DENY_NO_MATCHING_RULE`（默认拒绝，绝不放行）。

## 4. 版本与生效模型（稳定可复现）

- 首次加载：版本必须 ≥1；
- 后续更新：新版本号必须 = 当前版本 + 1，否则 `POLICY_VERSION_INCOMPATIBLE`；
- 乐观并发控制：`PUT /admin/policy?expected_current_version=N`，当当前版本不是 N 时拒绝，
  避免多客户端相互覆盖；
- **原子发布**：解析 → 版本检查 → 冲突检测全部通过后才替换当前策略；任一步失败，
  旧策略原样保留并继续服务，系统绝不会运行在“半成品策略”上；
- 在途判定使用不可变策略对象的快照，热更新不影响正在处理的请求。

## 5. 冲突检测（不回退到更宽松规则）

新规则与既有规则**选择器完全相同**（subject×resource×action 的规范化表示一致）时：

- `effect` 不同 → `POLICY_CONFLICT`（明确指出冲突的两条规则 id 与各自 effect）；
- 限流/并发约束不同 → `POLICY_CONFLICT`；
- 完全相同（同 effect 同约束）→ 视为**幂等重传**，允许通过。

新策略**内部**存在同选择器且语义不一致的规则，同样以 `POLICY_CONFLICT` 拒绝。

## 6. 策略管理 API

```bash
# 查看当前策略
curl -s http://127.0.0.1:8000/admin/policy

# 更新（带乐观版本检查）；非法/版本错误/冲突分别返回 400/409/409
curl -s -X PUT "http://127.0.0.1:8000/admin/policy?expected_current_version=1" \
  -H 'Content-Type: application/json' --data @new_policy.json
```

启动时从 `policies/default_policy.json` 加载默认策略；文件缺失或非法会**阻止启动**，
而不是带着空策略（=全拦截）或放行策略默默运行。
