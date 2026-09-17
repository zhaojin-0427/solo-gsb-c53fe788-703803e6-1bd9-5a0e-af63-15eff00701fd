"""真实 PostgreSQL 的端到端验证（需要 pgserver，仅供开发环境运行）：
启动嵌入式 Postgres -> 建表 -> 走完整 HTTP API：
草稿/发布 CAS、转换、同键回放、异摘要 409、回滚后同键重试、审计计数。
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import pathlib

os.environ.setdefault("SERVER_HMAC_KEY", "integration-test-key")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import httpx
import pgserver
from sqlalchemy import text

from app.database import engine
from app.models import Base


async def main() -> None:
    tmp = tempfile.mkdtemp(prefix="pgdata-")
    server = pgserver.get_server(tmp, cleanup_mode="delete")
    dsn = server.get_uri()  # e.g. postgresql://user:pass@/dbname?host=...
    # 转成 asyncpg DSN
    async_dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    if async_dsn.startswith("postgres://"):
        async_dsn = "postgresql+asyncpg://" + async_dsn[len("postgres://"):]
    print("DSN:", async_dsn.split("@")[-1])

    os.environ["DATABASE_URL"] = async_dsn
    # 重新绑定 engine
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    eng = create_async_engine(async_dsn)
    import app.database as dbmod

    dbmod.engine = eng
    dbmod.SessionLocal = async_sessionmaker(
        eng, expire_on_commit=False
    )
    import app.api.transform as tmod
    import app.api.policies as pmod

    tmod.session = dbmod.SessionLocal
    pmod.session = dbmod.SessionLocal

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from app.main import create_app

    app = create_app()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as ac:
        # 创建策略
        r = await ac.post(
            "/v1/policies",
            json={
                "name": "p1",
                "rules": [
                    {"id": "r1", "path": "$.user.name", "action": "mask",
                     "keep_prefix": 1, "keep_suffix": 1},
                    {"id": "r2", "path": "$.user.tax_id", "action": "tokenize"},
                    {"id": "r3", "path": "$.user.addresses[*]", "action": "delete"},
                    {"id": "r4", "path": "$.user.role", "action": "delete"},
                ],
            },
        )
        assert r.status_code == 201, r.text
        pid = r.json()["id"]
        print("policy created:", pid)

        # 草稿 CAS
        r = await ac.put(
            f"/v1/policies/{pid}/draft",
            json={"expected_draft_revision": 99, "rules": []},
        )
        assert r.status_code == 409, r.text
        print("draft CAS 409 OK")

        # 发布 CAS：错误期望 -> 409
        r = await ac.post(
            f"/v1/policies/{pid}/publish",
            json={"expected_revision": 5},
        )
        assert r.status_code == 409, r.text
        print("publish CAS 409 OK")

        # 正确发布 -> revision 1
        r = await ac.post(
            f"/v1/policies/{pid}/publish",
            json={"expected_revision": 0},
        )
        assert r.status_code == 201, r.text
        assert r.json()["revision"] == 1
        print("published revision 1")

        # 重复发布相同 expected=0 -> 409
        r = await ac.post(
            f"/v1/policies/{pid}/publish",
            json={"expected_revision": 0},
        )
        assert r.status_code == 409, r.text
        print("concurrent publish protection 409 OK")

        # 首次转换
        doc = {
            "user": {
                "name": "alice",
                "tax_id": 123456789,
                "addresses": ["x", "y"],
                "role": "admin",
            }
        }
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "k1", "revision": 1, "document": doc},
        )
        assert r.status_code == 200, r.text
        body1 = r.json()
        assert body1["result"]["user"]["name"] == "a***e", body1["result"]
        assert body1["result"]["user"]["tax_id"].startswith("hmac."), body1["result"]
        # [*] 删除全部元素，保留空数组；$.user.role 删除键本身
        assert body1["result"]["user"]["addresses"] == []
        assert "role" not in body1["result"]["user"]
        assert body1["version"]["revision"] == 1
        print("transform OK:", body1["result"]["user"])

        # 同键同摘要回放
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "k1", "revision": 1, "document": dict(doc)},
        )
        assert r.status_code == 200, r.text
        body2 = r.json()
        assert body2 == body1, "replay mismatch"
        print("idempotent replay OK")

        # 缺 revision => 422；版本不存在 => 404
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "no-ver", "document": doc},
        )
        assert r.status_code == 422, r.text
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "bad-ver", "revision": 99, "document": doc},
        )
        assert r.status_code == 404, r.text
        print("revision required & validated OK")

        # 同键异摘要 -> 409
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "k1", "revision": 1, "document": {"different": True}},
        )
        assert r.status_code == 409, r.text
        assert r.json()["error"]["code"] == "IDEMPOTENCY_DIGEST_CONFLICT"
        print("digest conflict 409 OK")

        # 版本内隔离：revision 2 上同键 k1 可用
        r = await ac.put(
            f"/v1/policies/{pid}/draft",
            json={
                "expected_draft_revision": 0,
                "rules": [
                    {"id": "r1", "path": "$.user.name", "action": "delete"}
                ],
            },
        )
        assert r.status_code == 200, r.text
        r = await ac.post(
            f"/v1/policies/{pid}/publish",
            json={"expected_revision": 1},
        )
        assert r.status_code == 201, r.text
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "k1", "revision": 2, "document": {"user": {"name": "z"}}},
        )
        assert r.status_code == 200, r.text
        assert "name" not in r.json()["result"]["user"]
        print("key scoped to version OK")

        # 审计计数：rev1 仅 1 条（回放不新增），rev2 1 条
        async with eng.connect() as conn:
            n1 = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM audit_event "
                        "WHERE revision = 1"
                    )
                )
            ).scalar_one()
            n2 = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM audit_event "
                        "WHERE revision = 2"
                    )
                )
            ).scalar_one()
            assert n1 == 1, n1
            assert n2 == 1, n2
            # 审计无敏感列
            cols = (
                await conn.execute(
                    text(
                        "SELECT to_json(audit_event) FROM audit_event "
                        "WHERE revision = 1"
                    )
                )
            ).scalar_one()
            assert "alice" not in str(cols)
            assert "123456789" not in str(cols)
        print("audit count & content OK:", dict(cols))

        # 请求 ID 回显
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "k2", "revision": 2, "document": {"user": {"name": "z"}}},
            headers={"X-Request-ID": "550e8400-e29b-41d4-a716-446655440000"},
        )
        assert r.status_code == 200
        assert r.headers["x-request-id"] == "550e8400-e29b-41d4-a716-446655440000"
        print("request id echo OK")

        # 非法 request id -> 服务端重新生成 UUID
        r = await ac.post(
            f"/v1/policies/{pid}/transform",
            json={"idempotency_key": "k3", "revision": 2, "document": {"user": {"name": "z"}}},
            headers={"X-Request-ID": "not-a-uuid"},
        )
        assert r.status_code == 200
        import uuid as uuidlib

        uuidlib.UUID(r.headers["x-request-id"])
        print("invalid request id replaced OK")

        # ---------------- 合规契约与发布门禁 ----------------
        # 非法契约 schema：不支持的关键字 -> 422
        r = await ac.post(
            "/v1/contracts",
            json={"name": "c-bad", "schema": {"type": "string", "pattern": "^a"}},
        )
        assert r.status_code == 422, r.text
        assert r.json()["error"]["code"] == "CONTRACT_SCHEMA_INVALID"
        # 循环引用 -> 422（分析必须终止）
        r = await ac.post(
            "/v1/contracts",
            json={
                "name": "c-cyc",
                "schema": {
                    "$defs": {"a": {"properties": {"n": {"$ref": "#/$defs/a"}}}},
                    "$ref": "#/$defs/a",
                },
            },
        )
        assert r.status_code == 422, r.text
        assert r.json()["error"]["code"] == "CONTRACT_SCHEMA_INVALID"
        print("invalid contract schemas rejected OK")

        # 合法契约 -> 201，revision 1
        contract_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "x-redaction": {"actions": ["mask"]},
                        },
                        "tax_id": {
                            "type": ["string", "number"],
                            "x-redaction": {"actions": ["tokenize"]},
                        },
                    },
                    "required": ["name"],
                }
            },
        }
        r = await ac.post(
            "/v1/contracts", json={"name": "c1", "schema": contract_schema}
        )
        assert r.status_code == 201, r.text
        cid = r.json()["id"]
        assert r.json()["current_revision"] == 1
        print("contract created:", cid)

        # 追加版本 CAS：错误期望 -> 409；正确 -> revision 2
        r = await ac.post(
            f"/v1/contracts/{cid}/versions",
            json={"expected_revision": 5, "schema": {"type": "object"}},
        )
        assert r.status_code == 409, r.text
        r = await ac.post(
            f"/v1/contracts/{cid}/versions",
            json={"expected_revision": 1, "schema": {"type": "object"}},
        )
        assert r.status_code == 201, r.text
        assert r.json()["revision"] == 2
        assert r.json()["schema"] == {"type": "object"}

        # 历史版本不可变：v1 仍是原 schema
        r = await ac.get(f"/v1/contracts/{cid}/versions/1")
        assert r.status_code == 200, r.text
        assert r.json()["schema"] == contract_schema
        r = await ac.get(f"/v1/contracts/{cid}/versions/2")
        assert r.json()["schema"] == {"type": "object"}
        r = await ac.get(f"/v1/contracts/{cid}/versions/99")
        assert r.status_code == 404, r.text
        assert r.json()["error"]["code"] == "CONTRACT_VERSION_NOT_FOUND"
        print("contract versions immutable OK")

        # 绑定契约创建策略（不存在的版本 -> 404）
        r = await ac.post(
            "/v1/policies",
            json={
                "name": "gated",
                "rules": [],
                "contract_id": cid,
                "contract_revision": 99,
            },
        )
        assert r.status_code == 404, r.text

        r = await ac.post(
            "/v1/policies",
            json={
                "name": "gated",
                "rules": [
                    {"id": "n1", "path": "$.user.name", "action": "mask",
                     "keep_prefix": 1, "keep_suffix": 1},
                ],
                "contract_id": cid,
                "contract_revision": 1,
            },
        )
        assert r.status_code == 201, r.text
        gpid = r.json()["id"]
        assert r.json()["contract_id"] == cid
        assert r.json()["contract_revision"] == 1

        # 发布门禁：tax_id 未覆盖 -> 422 CONTRACT_GATE_FAILED，含最短路径与 witness
        r = await ac.post(f"/v1/policies/{gpid}/publish", json={"expected_revision": 0})
        assert r.status_code == 422, r.text
        err = r.json()["error"]
        assert err["code"] == "CONTRACT_GATE_FAILED"
        details = err["details"]
        assert details["contract_id"] == cid
        assert details["contract_revision"] == 1
        v = details["violations"][0]
        assert v["kind"] == "uncovered", v
        assert v["path"] == "$.user.tax_id", v
        assert v["allowed_actions"] == ["tokenize"]
        assert v["witness"] == {"user": {"name": "", "tax_id": ""}}, v
        # 门禁失败不生成 revision
        r = await ac.get(f"/v1/policies/{gpid}")
        assert r.json()["current_revision"] == 0
        print("publish gate 422 with violation details OK")

        # 动作不符 -> 422 action_mismatch
        r = await ac.put(
            f"/v1/policies/{gpid}/draft",
            json={
                "expected_draft_revision": 0,
                "rules": [
                    {"id": "n1", "path": "$.user.name", "action": "mask"},
                    {"id": "n2", "path": "$.user.tax_id", "action": "delete"},
                ],
            },
        )
        assert r.status_code == 200, r.text
        r = await ac.post(f"/v1/policies/{gpid}/publish", json={"expected_revision": 0})
        assert r.status_code == 422, r.text
        v = r.json()["error"]["details"]["violations"][0]
        assert v["kind"] == "action_mismatch", v
        assert v["effective_action"] == "delete"
        assert [x["id"] for x in v["rules"]] == ["n2"]
        print("action mismatch violation OK")

        # 前序规则遮蔽 -> 422 shadowed
        r = await ac.put(
            f"/v1/policies/{gpid}/draft",
            json={
                "expected_draft_revision": 1,
                "rules": [
                    {"id": "n1", "path": "$.user.name", "action": "mask"},
                    {"id": "n2", "path": "$.user.tax_id", "action": "delete"},
                    {"id": "n3", "path": "$.user.tax_id", "action": "tokenize"},
                ],
            },
        )
        assert r.status_code == 200, r.text
        r = await ac.post(f"/v1/policies/{gpid}/publish", json={"expected_revision": 0})
        assert r.status_code == 422, r.text
        v = r.json()["error"]["details"]["violations"][0]
        assert v["kind"] == "shadowed", v
        assert [x["id"] for x in v["rules"]] == ["n2", "n3"]
        print("shadowed violation OK")

        # 全部覆盖 -> 发布成功
        r = await ac.put(
            f"/v1/policies/{gpid}/draft",
            json={
                "expected_draft_revision": 2,
                "rules": [
                    {"id": "n1", "path": "$.user.name", "action": "mask",
                     "keep_prefix": 1, "keep_suffix": 1},
                    {"id": "n2", "path": "$.user.tax_id", "action": "tokenize"},
                ],
            },
        )
        assert r.status_code == 200, r.text
        r = await ac.post(f"/v1/policies/{gpid}/publish", json={"expected_revision": 0})
        assert r.status_code == 201, r.text
        assert r.json()["revision"] == 1
        print("publish gate pass OK")

        # 绑定契约的策略发布后转换正常
        r = await ac.post(
            f"/v1/policies/{gpid}/transform",
            json={
                "idempotency_key": "gated-1",
                "revision": 1,
                "document": {"user": {"name": "alice", "tax_id": 123}},
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["result"]["user"]["name"] == "a***e"
        print("gated policy transform OK")

        # 无绑定策略发布不受门禁影响（既有行为）
        r = await ac.post("/v1/policies", json={"name": "ungated", "rules": []})
        assert r.status_code == 201, r.text
        upid = r.json()["id"]
        r = await ac.post(f"/v1/policies/{upid}/publish", json={"expected_revision": 0})
        assert r.status_code == 201, r.text
        print("ungated publish unaffected OK")

    # 回滚后同键重试：直接在事务里制造失败，验证占位不残留
    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import async_sessionmaker

    Session = async_sessionmaker(eng, expire_on_commit=False)
    from app.api.transform import _insert_placeholder
    import uuid as uuidlib

    rid = uuidlib.uuid4()
    try:
        async with Session() as s:
            async with s.begin():
                rec = await _insert_placeholder(
                    s, uuidlib.UUID(pid), 2, "retry-key", rid, "digest-x"
                )
                assert rec is not None
                raise RuntimeError("simulated failure before commit")
    except RuntimeError:
        pass  # 预期：事务整体回滚
    # 事务已整体回滚；同键可立即再次抢占
    async with Session() as s:
        async with s.begin():
            rec = await _insert_placeholder(
                s, uuidlib.UUID(pid), 2, "retry-key", rid, "digest-x"
            )
            assert rec is not None, "placeholder should be retriable after rollback"
    print("rollback allows same-key retry OK")

    await eng.dispose()
    server.cleanup()
    print("\nALL INTEGRATION CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
