# 验证方法

全部验证均可在本地完成，无需外部服务或凭据。

## 1. 环境准备

```bash
uv sync          # 安装依赖（fastapi、pytest）
```

## 2. 运行测试

```bash
uv run pytest                 # 全部 39 个用例，含引擎 INFO 判定日志
uv run pytest -k rate         # 只跑限流相关
uv run pytest tests/test_engine.py -k concurrency   # 并发上限场景
```

测试与需求场景的对应关系：

| 需求场景 | 测试 |
| --- | --- |
| 非法策略被拒绝、原因可区分 | `tests/test_policy_parser.py`（错误 apiVersion/kind/字段/约束/未知字段） |
| 版本不兼容/不连续 | `test_reject_bad_api_version_*`、`test_version_must_be_incremented_by_one` |
| 规则冲突被明确拒绝 | `test_conflict_same_selector_different_effect/limits` |
| 更新失败旧策略不变 | `tests/test_store.py::test_failed_update_keeps_old_policy`、`test_policy_update_takes_effect_and_old_policy_survives_failure` |
| 并发超限、计数不漂移 | `tests/test_ratelimit.py::test_concurrent_burst_admits_exactly_the_limit`（200 线程抢 10 个配额，恰好 10 成功） |
| 重复请求/突发 | `test_fixed_window_does_not_drift_under_burst` |
| 多身份不串号、不误伤 | `test_identities_never_share_counters`、`tests/test_api.py::test_mixed_identity_concurrent_burst_is_isolated` |
| 窗口重置不误伤 | `test_window_reset_does_not_punish_later_normal_traffic` |
| 并发在途上限及槽位释放 | `test_concurrency_slots_are_isolated_and_released`、`tests/test_engine.py::test_concurrency_limit_under_parallel_burst` |
| 默认拒绝/显式拒绝优先 | `test_default_deny_when_no_rule_matches`、`test_explicit_deny_takes_priority_over_allow` |
| 下游异常链路 | `test_downstream_error_is_distinct_and_audited`、`test_downstream_failure_returns_502_and_audited` |
| 审计不可用 fail-closed + 配额回滚 | `test_audit_unavailable_blocks_allow_and_refunds_quota` |
| 审计与判定一致 | `test_audit_events_align_with_decisions`、`test_rate_limit_reason_is_distinct_and_counted` |
| 既有接口兼容 | `tests/test_api.py::test_legacy_root_endpoint_unchanged`（`GET /` 仍为 `{"Hello": "World"}`） |

测试日志中每个请求都会打印“策略输入”和“判定依据”，例如：

```
INFO admission.engine: 策略输入 policy=test v1 request_id=r3 user='alice' ...
INFO admission.engine: 判定依据 r3 rule=allow-docs -> DENY(RATE_LIMIT_EXCEEDED) count=2 limit=2/60.0s
```

## 3. 启动服务手工验证

```bash
uv run uvicorn main:app --reload
```

### 3.1 行为兼容

```bash
curl -s http://127.0.0.1:8000/
# {"Hello":"World"}
```

### 3.2 允许 / 显式拒绝 / 默认拒绝（原因码可区分）

```bash
curl -s -H 'X-User: alice' \
  http://127.0.0.1:8000/api/resources/documents/report-1            # 200
curl -s -w '\n%{http_code}\n' -H 'X-User: mallory' \
  http://127.0.0.1:8000/api/resources/documents/report-1            # 403 DENY_EXPLICIT_RULE
curl -s -w '\n%{http_code}\n' \
  http://127.0.0.1:8000/api/resources/documents/report-1            # 403 DENY_NO_MATCHING_RULE
```

### 3.3 限流（第 4 次起 429，原因码 RATE_LIMIT_EXCEEDED）

```bash
for i in 1 2 3 4; do
  curl -s -o /dev/null -w "%{http_code} " -H 'X-User: alice' \
    http://127.0.0.1:8000/api/resources/documents/report-1
done; echo
# 200 200 200 429
```

### 3.4 并发上限（`delay` 让请求在途）

```bash
for i in 1 2 3 4; do
  curl -s -o /dev/null -w "%{http_code} " -X POST \
    -H 'X-Roles: admin' -H 'Content-Type: application/json' \
    -d '{"delay":0.5}' http://127.0.0.1:8000/api/echo &
done; wait; echo
# 2 个 200，其余 429 CONCURRENCY_LIMIT_EXCEEDED（echo 规则上限为 2）
```

### 3.5 下游异常（502，原因可区分，审计记录 downstream_error）

```bash
curl -s -w '\n%{http_code}\n' -X POST \
  -H 'X-Roles: admin' -H 'Content-Type: application/json' \
  -d '{"fail":true}' http://127.0.0.1:8000/api/echo
# 502 DOWNSTREAM_ERROR
```

### 3.6 审计对账

```bash
curl -s http://127.0.0.1:8000/admin/audit | python3 -m json.tool
```

### 3.7 策略更新：非法 / 版本 / 冲突

```bash
# 非法策略 -> 400 POLICY_INVALID
curl -s -X PUT http://127.0.0.1:8000/admin/policy \
  -H 'Content-Type: application/json' -d '{"apiVersion":"bad"}'

# 版本不连续 -> 409 POLICY_VERSION_INCOMPATIBLE（旧策略继续生效）
curl -s -X PUT http://127.0.0.1:8000/admin/policy \
  -H 'Content-Type: application/json' -d '{
    "apiVersion":"zero-trust-admission/v1","kind":"AdmissionPolicy",
    "metadata":{"name":"default","version":99},"rules":[]}'
```

冲突场景（与既有 `docs-admin-read` 同选择器但 effect=deny）：

```bash
curl -s -X PUT http://127.0.0.1:8000/admin/policy \
  -H 'Content-Type: application/json' -d '{
    "apiVersion":"zero-trust-admission/v1","kind":"AdmissionPolicy",
    "metadata":{"name":"default","version":2},
    "rules":[{"id":"c1","effect":"deny",
      "subject":{"users":["alice"],"roles":["admin"]},
      "resource":{"type":"document","patterns":["docs/*"]},
      "action":{"methods":["GET"]}}]}'
# 409 POLICY_CONFLICT
```
