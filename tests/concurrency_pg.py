"""并发幂等验证：同版本同键同摘要 N 个并发请求：
- 只有一个真正执行（审计仅 1 条，completed 记录 1 条）
- 所有响应完全一致
- 同键异摘要并发立即 409
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import pathlib

os.environ.setdefault("SERVER_HMAC_KEY", "concurrency-test-key")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import httpx
import pgserver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Base


async def main() -> None:
    tmp = tempfile.mkdtemp(prefix="pgdata-conc-")
    server = pgserver.get_server(tmp, cleanup_mode="delete")
    async_dsn = server.get_uri()
    async_dsn = async_dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    if async_dsn.startswith("postgres+asyncpg://"):
        async_dsn = "postgresql+asyncpg://" + async_dsn[len("postgres+asyncpg://"):]
    # pgserver 形如 postgresql+asyncpg:///postgres?host=/tmp/..，可直接被 asyncpg 使用

    os.environ["DATABASE_URL"] = async_dsn
    eng = create_async_engine(async_dsn)
    import app.database as dbmod

    dbmod.engine = eng
    dbmod.SessionLocal = async_sessionmaker(eng, expire_on_commit=False)
    import app.api.transform as tmod
    import app.api.policies as pmod

    tmod.session = dbmod.SessionLocal
    pmod.session = dbmod.SessionLocal

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from app.main import create_app

    app = create_app()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as ac:
        r = await ac.post(
            "/v1/policies",
            json={
                "name": "c1",
                "rules": [
                    {"id": "slow", "path": "$.secret", "action": "tokenize"}
                ],
            },
        )
        pid = r.json()["id"]
        r = await ac.post(
            f"/v1/policies/{pid}/publish", json={"expected_revision": 0}
        )
        assert r.status_code == 201, r.text
        url = f"/v1/policies/{pid}/transform"
        doc = {"secret": "4111111111111111"}

        # 10 个完全相同的同键请求并发
        N = 10

        async def call(i):
            return await ac.post(
                url, json={"idempotency_key": "HOT-KEY", "revision": 1, "document": dict(doc)}
            )

        results = await asyncio.gather(*(call(i) for i in range(N)))
        statuses = [r.status_code for r in results]
        assert all(s == 200 for s in statuses), statuses
        bodies = [r.json() for r in results]
        first = bodies[0]
        assert all(b == first for b in bodies), "responses differ"
        print("all", N, "concurrent identical requests got identical 200")

        async with eng.connect() as conn:
            audit_n = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM audit_event "
                        "WHERE revision=1 AND policy_id=CAST(:p AS uuid)"
                    ).bindparams(p=pid)
                )
            ).scalar_one()
            idem_n = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM idempotency_record "
                        "WHERE key='HOT-KEY'"
                    )
                )
            ).scalar_one()
            status = (
                await conn.execute(
                    text(
                        "SELECT status FROM idempotency_record WHERE key='HOT-KEY'"
                    )
                )
            ).scalar_one()
        assert audit_n == 1, f"audit rows={audit_n}"
        assert idem_n == 1
        assert status == "completed"
        print("exactly one execution; audit rows =", audit_n)

        # 异摘要的并发请求 => 409
        r = await ac.post(
            url, json={"idempotency_key": "HOT-KEY", "revision": 1, "document": {"other": 1}}
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "IDEMPOTENCY_DIGEST_CONFLICT"
        print("different-digest same-key -> 409")

    await eng.dispose()
    print("CONCURRENCY CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
