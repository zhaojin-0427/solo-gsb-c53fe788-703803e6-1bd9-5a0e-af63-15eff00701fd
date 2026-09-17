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

### 合规契约绑定（可选）

策略可绑定一份**不可变契约版本**（见第 3 节）：创建策略时携带
`contract_id` + `contract_revision`（必须同时提供），或在 `PUT .../draft`
中同时携带这两个字段变更绑定。绑定后，每次 `POST .../publish` 都会在发布事务内
对待发布规则做**静态合规分析**，不满足契约则发布失败且不生成 revision。
未绑定的策略行为不变。

---

## 3. 合规契约与发布门禁

契约（contract）是一份**受限 JSON Schema（Draft 2020-12）**文档，用
`x-redaction` 扩展关键字声明敏感节点及其允许的脱敏动作。契约以**不可变版本**
保存：创建即生成 `revision 1`，之后只能以 CAS 追加新版本；没有修改/删除接口，
查询永不改写历史版本。

### 3.1 契约 schema 的允许关键字

为保证发布门禁的静态分析可判定、可终止，只允许以下验证关键字：

`type` · `properties` · `required` · `additionalProperties` · `items` ·
`prefixItems` · `allOf` · `anyOf` · `oneOf`

外加：

- `$ref` / `$defs`：仅允许**文档内** JSON Pointer（`#...` 或 `#/$defs/...`）；
  无法解析的引用与非本地引用一律拒绝；**循环引用会被检测并拒绝**（检测本身在
  有限指针图上做 DFS，保证终止）；
- `$schema`：若出现，必须等于 `https://json-schema.org/draft/2020-12/schema`；
- `x-redaction`：`{"actions": [...]}`，`actions` 为 `delete` / `mask` /
  `tokenize` 的非空不重复子集，声明**该节点**允许的脱敏动作。

其余关键字（`pattern`、`enum`、`format`、`minimum`、`title`、`not`、`if` 等）
一律 **422 `CONTRACT_SCHEMA_INVALID`** 拒绝。子 schema 可以是布尔值
（`true` 任意 / `false` 不可满足），与 Draft 2020-12 一致。

### 3.2 契约 API

```bash
# 创建契约（同时生成不可变 revision 1）
curl -sS -X POST localhost:8080/v1/contracts \
  -H 'content-type: application/json' \
  -d '{
    "name": "user-pii",
    "schema": {
      "$schema": "https://json-schema.org/draft/2020-12/schema",
      "type": "object",
      "properties": {
        "user": {
          "type": "object",
          "properties": {
            "name":   {"type": "string", "x-redaction": {"actions": ["mask"]}},
            "tax_id": {"type": ["string","number"], "x-redaction": {"actions": ["tokenize"]}}
          },
          "required": ["name"]
        }
      }
    }
  }'
# -> 201 {"id":"<CID>", "name":"user-pii", "current_revision":1}

# 追加不可变版本（CAS：expected_revision 必须等于当前版本号）
curl -sS -X POST localhost:8080/v1/contracts/<CID>/versions \
  -H 'content-type: application/json' \
  -d '{"expected_revision": 1, "schema": { ... 新 schema ... }}'
# -> 201 {"contract_id":"<CID>", "revision":2, "schema":{...}}
# 并发冲突 -> 409 REVISION_CONFLICT

# 只读查询（历史版本永不改写）
curl localhost:8080/v1/contracts/<CID>                # 当前版本号
curl localhost:8080/v1/contracts/<CID>/versions/1     # 指定不可变版本
```

### 3.3 发布门禁语义

策略绑定契约后，`POST .../publish` 在**发布事务内**对待发布规则与契约版本做
纯静态分析（不执行任何脱敏转换、不保存业务数据；失败则事务回滚、不生成
revision）。分析对契约中每个 `x-redaction` 敏感节点展开全部**可满足分支**
（`allOf` 合并、`anyOf`/`oneOf` 逐分支、`$ref` 展开），并按引擎既有语义判定
每个敏感实例的**实际生效动作**：

- **首条命中**：同一节点被多条规则命中时，声明序首条生效；
- **祖先动作上提**：路径上**最浅**被命中的祖先（或节点自身）决定整个子树的
  命运（删除即移除，mask/tokenize 即整体替换为不透明值），与规则声明顺序无关；
- **数组索引语义**：`[n]` 只覆盖下标 `n`，`[*]` 覆盖全部下标；`items` 管辖
  `prefixItems` 之后的所有下标。

只有**全部**敏感实例的生效动作都落在该节点 `x-redaction.actions` 允许集合内，
才生成 revision。失败类型：

| kind | 含义 |
| --- | --- |
| `uncovered` | 敏感实例无任何规则命中 |
| `action_mismatch` | 生效动作不在允许集合内 |
| `shadowed` | 本可覆盖的规则被同节点的前序规则遮蔽（首条命中生效的动作不允许） |

### 3.4 门禁失败示例

策略只遮盖了 `name`，漏掉了 `tax_id`：

```bash
curl -sS -X POST localhost:8080/v1/policies \
  -H 'content-type: application/json' \
  -d '{
    "name": "user-export",
    "contract_id": "<CID>", "contract_revision": 1,
    "rules": [{"id": "n1", "path": "$.user.name", "action": "mask",
               "keep_prefix": 1, "keep_suffix": 1}]
  }'
curl -sS -X POST localhost:8080/v1/policies/<PID>/publish \
  -H 'content-type: application/json' -d '{"expected_revision": 0}'
```

响应 **422 `CONTRACT_GATE_FAILED`**，携带最短具体路径、分支、相关规则与符合
该分支的最小 witness 文档（witness 由契约结构合成，只含类型占位值）：

```json
{
  "error": {
    "code": "CONTRACT_GATE_FAILED",
    "message": "policy rules do not satisfy the bound compliance contract",
    "request_id": "<uuid>",
    "details": {
      "contract_id": "<CID>",
      "contract_revision": 1,
      "violations": [
        {
          "kind": "uncovered",
          "path": "$.user.tax_id",
          "allowed_actions": ["tokenize"],
          "effective_action": null,
          "schema_path": "#/properties/user/properties/tax_id",
          "branch": [],
          "rules": [],
          "witness": {"user": {"name": "", "tax_id": ""}}
        }
      ]
    }
  }
}
```

再例如规则 `{"id":"n2","path":"$.user.tax_id","action":"delete"}` 在前、
`{"id":"n3","path":"$.user.tax_id","action":"tokenize"}` 在后：首条命中使
`delete` 生效（不在允许集合），`n3` 被遮蔽，返回：

```json
{
  "kind": "shadowed",
  "path": "$.user.tax_id",
  "allowed_actions": ["tokenize"],
  "effective_action": "delete",
  "schema_path": "#/properties/user/properties/tax_id",
  "branch": [],
  "rules": [
    {"id": "n2", "path": "$.user.tax_id", "action": "delete"},
    {"id": "n3", "path": "$.user.tax_id", "action": "tokenize"}
  ],
  "witness": {"user": {"name": "", "tax_id": ""}}
}
```

修正规则（`tax_id` 改 `tokenize`）后重新发布即可通过。门禁失败不会留下任何
revision 或业务数据。

---

## 4. API 一览与访问示例

所有请求/响应均为 JSON。每个响应都会回带头 `X-Request-ID`；可在请求中传入合法
UUID 作为关联 ID，非法或缺失时由服务端生成。

### 4.1 创建策略

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

### 4.2 修改草稿（草稿 CAS）

```bash
curl -sS -X PUT localhost:8080/v1/policies/<PID>/draft \
  -H 'content-type: application/json' \
  -d '{"expected_draft_revision": 0, "rules": [ ... 新规则全集 ... ]}'
# expected_draft_revision 不匹配 -> 409 DRAFT_REVISION_CONFLICT
```

### 4.3 发布不可变版本（revision CAS）

```bash
curl -sS -X POST localhost:8080/v1/policies/<PID>/publish \
  -H 'content-type: application/json' \
  -d '{"expected_revision": 0}'
# -> 201 {"policy_id":"<PID>", "revision":1, "rules":[...]}
# 并发/重复发布（expected_revision 已过期）-> 409 REVISION_CONFLICT
```

### 4.4 查询

```bash
curl localhost:8080/v1/policies/<PID>                         # 草稿 + 当前版本号
curl localhost:8080/v1/policies/<PID>/versions/1              # 指定不可变版本
```

### 4.5 执行脱敏转换（核心接口）

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

## 5. 错误响应

统一格式（不回显输入或敏感值）：

```json
{"error": {"code": "REVISION_CONFLICT",
           "message": "policy was published concurrently; refetch current revision",
           "request_id": "<uuid>"}}
```

| HTTP | code | 触发场景 |
| --- | --- | --- |
| 400 | `INVALID_INPUT` | 文档无法 JCS 规范化（如 NaN/Infinity、非字符串键） |
| 400 | `INVALID_RULES` | 规则非法（重复 id、动作与保留位冲突等） |
| 404 | `POLICY_NOT_FOUND` / `VERSION_NOT_FOUND` | 策略或版本不存在 |
| 404 | `CONTRACT_NOT_FOUND` / `CONTRACT_VERSION_NOT_FOUND` | 契约或契约版本不存在 |
| 409 | `REVISION_CONFLICT` | 发布/契约追加版本 CAS 失败（并发） |
| 409 | `DRAFT_REVISION_CONFLICT` | 草稿乐观锁失败 |
| 409 | `IDEMPOTENCY_DIGEST_CONFLICT` | 同幂等键对应不同输入摘要 |
| 422 | `VALIDATION_ERROR` | 请求结构/规则路径语法非法（details 仅含位置与校验类型） |
| 422 | `CONTRACT_SCHEMA_INVALID` | 契约 schema 含不支持的关键字、非法 `x-redaction`、非本地/不可解析 `$ref` 或循环引用 |
| 422 | `CONTRACT_GATE_FAILED` | 发布门禁失败：规则不满足绑定契约（details 含违规列表与最小 witness） |
| 500 | `INTERNAL_ERROR` | 服务端内部错误（不携带细节） |

---

## 6. 数据留痕与最小化

- **审计表 `audit_event`**：仅 `request_id`、`policy_id`、`revision`、
  `input_digest`（JCS SHA-256 hex）、`error_code`、时间戳；成功转换每次执行
  一条，**回放不新增**。
- **幂等表 `idempotency_record`**：仅保存键、摘要、`pending/completed` 状态与
  最终响应（用于回放）；**从不保存原始文档**。
- **日志**：stdout 单行 JSON，字段经白名单过滤，只可能出现
  `request_id` / `policy_id` / `contract_id` / `version` / `input_digest` /
  `error_code` / `http_status` / `idempotency_replay`；关闭了 uvicorn 默认访问
  日志（避免 URL 与查询串泄露），不记录异常堆栈（第三方组件的堆栈文本可能包含
  入参）。
- **错误响应与追踪**：同样只暴露请求 ID、版本、输入摘要与错误码，不包含原始
  值或脱敏后的敏感值。门禁失败的 `details` 只含规则 id、路径、分支与合成的
  最小 witness（类型占位值），不含任何业务数据。

---

## 7. 测试

纯逻辑单元测试（无外部依赖）：

```bash
python -m unittest discover -s tests        # 安装 requirements 后
# 极简环境（无 pip 时）用标准库 + 轻量 stub 运行：
python tests/run_stdlib.py
```

覆盖 JCS 规范化边界数字、路径语法正反例、引擎的首条规则优先、祖先删除 skip、
数组降序删除、根删除、遮盖/令牌化确定性、轨迹不含值；契约 schema 的关键字
白名单、`x-redaction` 形状、本地 `$ref` 解析与循环引用终止检测；门禁的首条
命中、祖先动作上提、数组索引/`prefixItems` 语义、`allOf`/`anyOf`/`oneOf` 分支、
三类违规（uncovered / action_mismatch / shadowed）与最小 witness 生成。

真实 PostgreSQL 端到端验证（自动拉起嵌入式 Postgres，需
`pip install pgserver pytest httpx`）：

```bash
python tests/integration_pg.py   # 草稿/发布 CAS、转换、回放、异摘要 409、
                                 # 版本级键隔离、审计计数、回滚后同键重试、
                                 # 契约版本不可变、发布门禁三类失败与放行
python tests/concurrency_pg.py   # 10 个同键同摘要并发 => 只执行一次、审计 1 条
```

> 上述两个脚本均已在随仓代码上通过。

---

## 8. 目录结构

```
app/
  main.py            FastAPI 应用、启动建表（含幂等列迁移）、健康检查
  config.py          环境配置（DSN / HMAC 密钥 / 日志级别）
  database.py        async engine / session
  models.py          policy / policy_version / contract / contract_version /
                     idempotency_record / audit_event
  schemas.py         请求响应模型与规则校验
  pathlang.py        受限路径解析与匹配（$ .name [n] [*]）
  contractschema.py  受限 JSON Schema 契约校验（关键字白名单、本地 $ref、循环检测）
  gate.py            发布门禁静态分析（分支展开、覆盖判定、最小 witness）
  jcs.py             RFC 8785 JCS 规范化与输入摘要
  security.py        mask 与服务端密钥 HMAC 令牌化
  engine.py          规则命中、去重、skip、执行顺序与轨迹
  exceptions.py      无第三方依赖的 ClientError
  errors.py          统一错误处理器
  logging_config.py  白名单结构化 JSON 日志
  middleware.py      X-Request-ID
  api/policies.py    草稿/发布/版本接口（revision CAS、契约绑定、发布门禁）
  api/contracts.py   契约接口（不可变版本、追加版本 CAS、只读查询）
  api/transform.py   转换接口（版本级幂等、等待回放、同事务审计）
tests/               单元测试与 Postgres 集成/并发脚本
docker-compose.yml   db + gateway 一键启动
Dockerfile
```
