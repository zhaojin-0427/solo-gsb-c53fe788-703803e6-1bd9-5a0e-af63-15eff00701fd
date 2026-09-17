# JSON 脱敏网关（JSON Redaction Gateway）

供内部系统之间交换数据的 JSON 脱敏网关。调用方提交文档与策略版本，网关按
**不可变的已发布策略**执行删除、局部遮盖（mask）、基于服务端密钥的确定性 HMAC
令牌化（tokenize），返回脱敏结果、规则轨迹与策略版本。所有转换请求支持
**版本级幂等**，同键只执行一次。

技术栈：Python 3.11 · FastAPI · SQLAlchemy 2（asyncio）· PostgreSQL 16 · asyncpg。

---

## 1. 一键启动（Docker Compose）

```bash
cp .env.example .env
# 编辑 .env，至少设置一个强随机的 SERVER_HMAC_KEY，例如：
#   SERVER_HMAC_KEY=$(openssl rand -hex 32)
docker compose up --build
```

启动后：

| 用途 | 地址 |
| --- | --- |
| 网关 API | <http://localhost:8080> |
| 交互式文档（Swagger UI） | <http://localhost:8080/docs> |
| OpenAPI 描述 | <http://localhost:8080/openapi.json> |
| 健康检查 | `GET http://localhost:8080/health` |
| PostgreSQL | 容器 `db:5432`（仅内部网络） |

`GATEWAY_PORT` 可改宿主机映射端口；数据保存在 compose 管理卷 `pgdata`。

本地开发若只想跑网关（自行准备 Postgres）：

```bash
pip install -r requirements.txt
export DATABASE_URL='postgresql+asyncpg://gateway:gateway_change_me@localhost:5432/gateway'
export SERVER_HMAC_KEY="$(openssl rand -hex 32)"
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

> 表结构在启动时自动幂等创建（`CREATE TABLE IF NOT EXISTS`），无需手动迁移。
> 未设置 `SERVER_HMAC_KEY` 时服务**拒绝启动**；仅本地开发可显式设置
> `ALLOW_INSECURE_DEV_KEY=1` 使用内置开发密钥，切勿用于生产。

### 配置项

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `DATABASE_URL` | 指向 compose 的 `db` | SQLAlchemy asyncpg DSN |
| `SERVER_HMAC_KEY` | 空（必填） | 确定性 HMAC 令牌化密钥；不入库、不入日志，建议由密钥管理系统注入 |
| `ALLOW_INSECURE_DEV_KEY` | `0` | 仅本地开发：允许使用内置固定密钥 |
| `LOG_LEVEL` | `INFO` | 日志级别，输出 stdout 单行 JSON |
| `GATEWAY_PORT` | `8080` | 宿主机暴露端口 |

---

## 2. 策略模型

策略（policy）包含一份**可变草稿**与若干**不可变发布版本**：

- 草稿可反复修改，每次修改使 `draft_revision` 自增（草稿乐观锁）；
- `POST .../publish` 以当时的草稿生成一个不可变版本 `policy_version`，
  `revision` 从 1 起单调递增；发布后该版本的规则永不改变；
- 发布采用 CAS：请求必须携带 `expected_revision`（当前已发布版本号，首次为
  `0`）。与当前值不一致时返回 **409 `REVISION_CONFLICT`**。并发发布由
  行锁 `SELECT ... FOR UPDATE` + `(policy_id, revision)` 唯一约束双重保证。

### 规则

```json
{
  "id": "mask-user-name",
  "path": "$.user.name",
  "action": "mask",
  "keep_prefix": 1,
  "keep_suffix": 1
}
```

| 字段 | 说明 |
| --- | --- |
| `id` | 策略内唯一，`[A-Za-z0-9_\-.:]`，≤64 |
| `path` | 受限路径，见下 |
| `action` | `delete` / `mask` / `tokenize` |
| `keep_prefix` / `keep_suffix` | 仅 `mask` 有效，保留首尾字符数；默认 0 |

动作语义：

- **delete**：删除命中的对象键；对数组元素按**索引降序**删除；`[*]` 删除当前
  数组的全部元素（保留空数组本身）。
- **mask**：字符串做局部遮盖，如 `alice` + 首尾各 1 → `a***e`；无保留位或保留
  位覆盖整个字符串时返回固定占位 `***`（不通过星号数量泄露长度）；非字符串
  （数字/布尔/null/对象/数组）一律返回 `***`。
- **tokenize**：对命中值的 **JCS 规范字节**计算
  `HMAC-SHA256(服务端密钥)`，输出 `hmac.<hex>`。同值同密钥恒等，不同值雪崩；
  密钥只存在于服务端配置，不随响应、日志或数据库泄露。

### 路径语法（只允许以下四种构件）

| 构件 | 含义 |
| --- | --- |
| `$` | 文档根 |
| `.name` | 对象字段（`name` 为字母/数字/下划线） |
| `[n]` | 数组索引，非负整数、禁止前导零（如 `[0]`、`[12]`） |
| `[*]` | 数组通配，命中当前数组的每一个元素 |

可任意串联，如 `$.users[*].cards[0].number`。其余语法（`..`、`['x']`、
`.*`、切片、负索引、过滤表达式等）一律 422 拒绝。

### 命中与执行顺序（确定性）

1. 在**原始文档**上计算全部规则的命中（通配按原始数组长度展开）；
2. 同一具体节点被多条规则命中时，**按规则声明顺序只取首条**，其余在轨迹中标记
   为 `duplicate`；
3. 祖先节点被删除时，其后代的所有命中标为 `skipped`（不执行）；
4. 先应用所有 `mask` / `tokenize`，再执行删除；同一数组的删除按索引降序，避免
   位移导致误删。

---

## 2A. 策略合规契约与发布门禁

除策略外，网关还管理**合规契约（compliance contract）**：一份受限的
**JSON Schema Draft 2020-12** 文档（不可变版本链），用自定义关键字
`x-redaction` 声明敏感节点允许的脱敏动作。发布策略版本时可携带一个不可变
契约版本作为**发布门禁**：发布事务内对待发布规则做**静态分析**，只有
**所有可满足分支中的敏感实例都由允许动作覆盖**才生成 revision。

### 契约语法（只支持以下关键字）

| 类别 | 关键字 |
| --- | --- |
| 元 | `$schema`（必须是 Draft 2020-12 meta-schema URL）、`$id`、`$ref`、`$defs` |
| 类型/结构 | `type`、`properties`、`required`、`additionalProperties`、`items`、`prefixItems` |
| 组合 | `allOf`、`anyOf`、`oneOf` |
| 敏感声明 | `x-redaction`（形如 `{"actions": ["mask", "tokenize"]}`） |
| 布尔 schema | `true` / `false` |

- `type` 取值：`null` / `boolean` / `object` / `array` / `number` /
  `integer` / `string`，或其非空唯一数组。
- 任何其他关键字（`minimum`、`enum`、`format`、`pattern`、`contains`、
  `$anchor` 等）一律 **422 `CONTRACT_SCHEMA_INVALID`** 拒绝，错误 details
  给出 `pointer`（出错子 schema 的 JSON Pointer）与 `reason`。
- `$ref` **只允许本地引用** `#` 或 `#/$defs/<name>`；外部 URL、JSON Pointer
  形式（`#/properties/...`）、悬空引用均拒绝。引用图**允许成环**
  （如递归树节点），分析器带深度预算保证循环引用分析必然终止。
- `x-redaction` 只能是 `{"actions": [...]}`，动作取自
  `delete` / `mask` / `tokenize`，非空且唯一；`allOf` 中多个声明取动作
  交集。

示例契约：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "users": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "name":   {"type": "string",
                     "x-redaction": {"actions": ["mask"]}},
          "tax_id": {"type": "string",
                     "x-redaction": {"actions": ["tokenize", "delete"]}}
        },
        "required": ["name", "tax_id"]
      }
    }
  }
}
```

### 门禁静态分析语义

分析器**枚举契约所有可满足分支中的敏感实例**（`anyOf` / `oneOf` 按分支
展开，`allOf` 合并），并严格按脱敏引擎的语义判定：

- 在**原始文档**上命中，规则路径每个节点都必须存在；
- 同一具体节点多条规则命中时**首条声明规则生效**（其余 duplicate）；
- 祖先节点的首条 `delete` 覆盖其全部后代敏感实例（后代随祖先消失）；
- 数组按**具体索引**判定：`[*]` 覆盖该数组所有元素；只覆盖固定索引时，
  分析器会在后续索引上找到未覆盖实例。

三种失败（每个违规都附带**最短具体路径、分支（`anyOf`/`oneOf` 选中项与
schema 路径）、相关规则及符合该分支的最小 witness 文档**）：

| kind | 含义 |
| --- | --- |
| `uncovered` | 敏感实例在 witness 上没有任何规则命中（含固定索引漏掉后续数组元素、`additionalProperties` 的新鲜键名） |
| `mismatch` | 首条命中规则的动作不在契约允许集合内，且没有后序允许规则 |
| `shadowed` | 一条本可允许的规则被前序规则遮蔽——同节点首条命中为不允许动作（后序为 duplicate），或祖先 delete 使其后效失效 |

- witness 是分析器合成的**结构占位文档**（值为 `"x"` / `0` 等，不含真实
  敏感数据），并经自身实例校验器确认满足目标分支；能区分时（如
  `oneOf` 各分支有可判别的类型/必填字段）会附加判别字段使 witness
  恰好满足目标分支，无法区分时至少保证目标选中分支校验通过。
- 分析是**纯静态**的：不执行任何脱敏转换、不读取入站业务文档、不保存
  业务数据；违规时事务回滚，**不生成 revision**。

### 契约 API

```bash
# 创建契约（草稿即按受限 Draft 2020-12 子集校验）
curl -sS -X POST localhost:8080/v1/contracts \
  -H 'content-type: application/json' \
  -d @contract.json
# -> 201 {"id":"<CID>","draft_schema":{...},"draft_revision":0,"current_version":0}

# 修改草稿（草稿 CAS）
curl -sS -X PUT localhost:8080/v1/contracts/<CID>/draft \
  -H 'content-type: application/json' \
  -d '{"expected_draft_revision": 0, "schema": { ... }}'

# 冻结不可变契约版本（版本 CAS，首次 expected_version=0）
curl -sS -X POST localhost:8080/v1/contracts/<CID>/versions \
  -H 'content-type: application/json' \
  -d '{"expected_version": 0}'
# -> 201 {"contract_id":"<CID>","version":1,"schema":{ ... 冻结快照 ... }}

# 读取不可变历史版本（只读，永不改写）
curl localhost:8080/v1/contracts/<CID>/versions/1
```

发布时携带门禁参数（`contract_id` 与 `contract_version` 必须同时出现；
契约版本不存在返回 404 `CONTRACT_VERSION_NOT_FOUND`）：

```bash
curl -sS -X POST localhost:8080/v1/policies/<PID>/publish \
  -H 'content-type: application/json' \
  -d '{"expected_revision": 0,
       "contract_id": "<CID>", "contract_version": 1}'
```

### 失败响应示例（422 CONTRACT_VIOLATION）

下例契约要求 `users[*].tax_id` 只能 `tokenize` / `delete`，而待发布规则
把它 `mask`（动作不符），且后序 tokenize 规则被首条遮蔽：

```json
{
  "error": {
    "code": "CONTRACT_VIOLATION",
    "message": "publish rejected: sensitive instances are not fully covered ...",
    "request_id": "7f0b0e3e-....",
    "details": {
      "contract_id": "<CID>",
      "contract_version": 1,
      "violations": [
        {
          "kind": "shadowed",
          "path": "$.users[0].tax_id",
          "allowed_actions": ["tokenize", "delete"],
          "branch": [],
          "witness": {"users": [{"name": "x", "tax_id": "x"}]},
          "rules": [
            {"order": 0, "id": "bad-mask", "path": "$.users[*].tax_id",
             "action": "mask", "role": "preceding"},
            {"order": 1, "id": "ok-tokenize", "path": "$.users[*].tax_id",
             "action": "tokenize", "role": "shadowed"}
          ]
        }
      ]
    }
  }
}
```

`uncovered` 的 `rules` 为空数组；`mismatch` 的 `rules` 只有首条命中规则
（`role: "first_hit"`）；`branch` 在 `anyOf` / `oneOf` 分支下形如
`[{"combinator": "oneOf", "index": 1, "schema_path": "#"}]`。违规列表按
路径长度排序，首条即**最短**具体路径。

契约 schema 本身非法时：

```json
{"error": {"code": "CONTRACT_SCHEMA_INVALID",
           "message": "contract schema is not a supported JSON Schema Draft 2020-12 document",
           "request_id": "...",
           "details": {"pointer": "#/properties/age",
                       "reason": "unsupported keyword(s): ['minimum']; ..."}}}
```

---

## 3. API 一览与访问示例

所有请求/响应均为 JSON。每个响应都会回带头 `X-Request-ID`；可在请求中传入合法
UUID 作为关联 ID，非法或缺失时由服务端生成。

### 3.1 创建策略

```bash
curl -sS -X POST localhost:8080/v1/policies \
  -H 'content-type: application/json' \
  -d '{
    "name": "user-export",
    "rules": [
      {"id": "n1", "path": "$.user.name", "action": "mask", "keep_prefix": 1, "keep_suffix": 1},
      {"id": "n2", "path": "$.user.tax_id", "action": "tokenize"},
      {"id": "n3", "path": "$.user.addresses[*]", "action": "delete"}
    ]
  }'
# -> 201 {"id":"<uuid>", "draft_rules":[...], "draft_revision":0, "current_revision":0}
```

### 3.2 修改草稿（草稿 CAS）

```bash
curl -sS -X PUT localhost:8080/v1/policies/<PID>/draft \
  -H 'content-type: application/json' \
  -d '{"expected_draft_revision": 0, "rules": [ ... 新规则全集 ... ]}'
# expected_draft_revision 不匹配 -> 409 DRAFT_REVISION_CONFLICT
```

### 3.3 发布不可变版本（revision CAS）

```bash
curl -sS -X POST localhost:8080/v1/policies/<PID>/publish \
  -H 'content-type: application/json' \
  -d '{"expected_revision": 0}'
# -> 201 {"policy_id":"<PID>", "revision":1, "rules":[...],
#         "contract_id": null, "contract_version": null}
# 并发/重复发布（expected_revision 已过期）-> 409 REVISION_CONFLICT
```

需要发布门禁时额外携带 `contract_id` + `contract_version`（详见第 2A 节）；
门禁不通过返回 422 `CONTRACT_VIOLATION`，不生成 revision。

### 3.4 查询

```bash
curl localhost:8080/v1/policies/<PID>                         # 草稿 + 当前版本号
curl localhost:8080/v1/policies/<PID>/versions/1              # 指定不可变版本
```

### 3.5 执行脱敏转换（核心接口）

```bash
curl -sS -X POST localhost:8080/v1/policies/<PID>/transform \
  -H 'content-type: application/json' \
  -H 'X-Request-ID: 550e8400-e29b-41d4-a716-446655440000' \
  -d '{
    "idempotency_key": "biz-order-20260917-0001",
    "revision": 1,
    "document": {
      "user": {"name": "alice", "tax_id": 123456789,
               "addresses": ["Beijing", "Shanghai"], "role": "admin"}
    }
  }'
```

响应：

```json
{
  "result": {
    "user": {"name": "a***e", "tax_id": "hmac.9ad6…ce94", "addresses": []}
  },
  "trace": [
    {"rule_id": "n1", "path": "$.user.name", "action": "mask",
     "matched": 1, "applied": 1, "skipped": 0,
     "hits": [{"path": "$.user.name", "status": "applied"}]},
    {"rule_id": "n2", "path": "$.user.tax_id", "action": "tokenize",
     "matched": 1, "applied": 1, "skipped": 0, "hits": [ ... ]},
    {"rule_id": "n3", "path": "$.user.addresses[*]", "action": "delete",
     "matched": 2, "applied": 2, "skipped": 0,
     "hits": [{"path": "$.user.addresses[0]", "status": "applied"},
              {"path": "$.user.addresses[1]", "status": "applied"}]}
  ],
  "version": {"policy_id": "<PID>", "revision": 1}
}
```

- `revision` **必填**，且必须是已存在的不可变发布版本；版本不存在返回
  404 `VERSION_NOT_FOUND`。
- `trace` 只包含规则 id、路径、动作、命中位置与计数，**不包含任何值**。
- 轨迹状态：`applied`（生效）/ `skipped`（祖先删除导致失效）/
  `duplicate`（节点已被声明在前的规则命中）。

#### 幂等语义（键仅在同一 `policy_id + revision` 内生效）

- 请求必须携带 `idempotency_key`（≤128 字符）。网关对 `document` 计算
  **JCS（RFC 8785）规范化 SHA-256 摘要**。
- **首次**：插入 `pending` 占位行（唯一约束
  `(policy_id, revision, key)`），执行脱敏，把最终响应与一条审计事件在
  **同一事务**提交。
- **同键同摘要并发**：只有一个请求执行；其余请求在占位行的
  `SELECT … FOR UPDATE` 行锁上等待，提交后**回放首次保存的最终响应**，不重复
  执行、**不新增审计**。
- **同键异摘要**：无论首次请求是否完成，均返回
  **409 `IDEMPOTENCY_DIGEST_CONFLICT`**。
- 执行事务在提交前任何环节失败（含进程崩溃）→ 占位随事务回滚，**同键可立即
  重试**；不会留下永久 pending 行。
- 键按版本隔离：新版本下旧键可重新使用。

---

## 4. 错误响应

统一格式（不回显输入或敏感值）：

```json
{"error": {"code": "REVISION_CONFLICT",
           "message": "policy was published concurrently; refetch current revision",
           "request_id": "<uuid>"}}
```

| HTTP | code | 触发场景 |
| --- | --- | --- |
| 400 | `INVALID_INPUT` | 文档无法 JCS 规范化（如 NaN/Infinity、非字符串键） |
| 404 | `POLICY_NOT_FOUND` / `VERSION_NOT_FOUND` | 策略或版本不存在 |
| 404 | `CONTRACT_NOT_FOUND` / `CONTRACT_VERSION_NOT_FOUND` | 契约或契约版本不存在 |
| 409 | `REVISION_CONFLICT` | 发布 CAS 失败（并发发布） |
| 409 | `DRAFT_REVISION_CONFLICT` | 草稿乐观锁失败 |
| 409 | `CONTRACT_VERSION_CONFLICT` / `CONTRACT_DRAFT_REVISION_CONFLICT` | 契约冻结 CAS / 契约草稿乐观锁失败 |
| 409 | `IDEMPOTENCY_DIGEST_CONFLICT` | 同幂等键对应不同输入摘要 |
| 422 | `VALIDATION_ERROR` | 请求结构/规则路径语法非法（details 仅含位置与校验类型） |
| 422 | `CONTRACT_SCHEMA_INVALID` | 契约不是受支持的 Draft 2020-12 子集（details: pointer/reason） |
| 422 | `CONTRACT_VIOLATION` | 发布门禁失败：敏感实例未被允许动作覆盖（details: 最短路径/分支/规则/witness） |
| 500 | `INTERNAL_ERROR` | 服务端内部错误（不携带细节） |

---

## 5. 数据留痕与最小化

- **审计表 `audit_event`**：仅 `request_id`、`policy_id`、`revision`、
  `input_digest`（JCS SHA-256 hex）、`error_code`、时间戳；成功转换每次执行
  一条，**回放不新增**。
- **幂等表 `idempotency_record`**：仅保存键、摘要、`pending/completed` 状态与
  最终响应（用于回放）；**从不保存原始文档**。
- **日志**：stdout 单行 JSON，字段经白名单过滤，只可能出现
  `request_id` / `policy_id` / `version` / `input_digest` / `error_code` /
  `http_status` / `idempotency_replay`；关闭了 uvicorn 默认访问日志（避免 URL
  与查询串泄露），不记录异常堆栈（第三方组件的堆栈文本可能包含入参）。
- **错误响应与追踪**：同样只暴露请求 ID、版本、输入摘要与错误码，不包含原始
  值或脱敏后的敏感值。

---

## 6. 测试

纯逻辑单元测试（无外部依赖）：

```bash
python -m unittest discover -s tests        # 安装 requirements 后
# 极简环境（无 pip 时）用标准库 + 轻量 stub 运行：
python tests/run_stdlib.py
```

覆盖 JCS 规范化边界数字、路径语法正反例、引擎的首条规则优先、祖先删除 skip、
数组降序删除、根删除、遮盖/令牌化确定性、轨迹不含值，以及契约关键字白名单/
本地 `$ref`/循环终止、发布门禁的未覆盖/动作不符/前序遮蔽、分支 witness、
数组索引与 `additionalProperties` 语义等。

真实 PostgreSQL 端到端验证（自动拉起嵌入式 Postgres，需
`pip install pgserver pytest httpx`）：

```bash
python tests/integration_pg.py   # 草稿/发布 CAS、转换、回放、异摘要 409、
                                 # 版本级键隔离、审计计数、回滚后同键重试
python tests/concurrency_pg.py   # 10 个同键同摘要并发 => 只执行一次、审计 1 条
```

> 上述两个脚本均已在随仓代码上通过。

---

## 7. 目录结构

```
app/
  main.py            FastAPI 应用、启动建表、健康检查
  config.py          环境配置（DSN / HMAC 密钥 / 日志级别）
  database.py        async engine / session
  models.py          policy / policy_version / compliance_contract / contract_version / idempotency_record / audit_event
  schemas.py         请求响应模型与规则校验
  pathlang.py        受限路径解析与匹配（$ .name [n] [*]）
  jcs.py             RFC 8785 JCS 规范化与输入摘要
  security.py        mask 与服务端密钥 HMAC 令牌化
  engine.py          规则命中、去重、skip、执行顺序与轨迹
  contracts.py       受限 JSON Schema Draft 2020-12 编译/校验（x-redaction、本地 $ref、循环终止）
  compliance.py      发布门禁静态分析（敏感实例枚举、分支、witness 合成）
  exceptions.py      无第三方依赖的 ClientError
  errors.py          统一错误处理器
  logging_config.py  白名单结构化 JSON 日志
  middleware.py      X-Request-ID
  api/policies.py    草稿/发布/版本接口（revision CAS + 发布门禁）
  api/contracts.py   契约草稿/冻结/只读版本接口
  api/transform.py   转换接口（版本级幂等、等待回放、同事务审计）
tests/               单元测试与 Postgres 集成/并发脚本
docker-compose.yml   db + gateway 一键启动
Dockerfile
```
