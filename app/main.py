import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from .api import policies, transform as transform_api
from .config import settings
from .database import engine
from .errors import register_exception_handlers
from .logging_config import configure_logging, get_logger
from .middleware import RequestIDMiddleware
from .models import Base


@asynccontextmanager
async def lifespan(app: FastAPI):
    log = get_logger("gateway.startup")
    # 启动即要求 HMAC 密钥就绪（开发模式显式开启时使用开发密钥）
    settings.hmac_key_bytes()

    last_err = None
    for attempt in range(30):
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
                # 幂等建表（内部系统、单服务部署；正式演进可接入 Alembic）
                await conn.run_sync(Base.metadata.create_all)
            break
        except Exception as exc:  # 数据库容器可能尚未就绪
            last_err = exc
            time.sleep(1.0)
    else:
        log.error("startup_failed", error_code="DATABASE_UNAVAILABLE", http_status=500)
        raise RuntimeError("database unavailable at startup") from last_err

    log.info("startup_completed")
    yield
    await engine.dispose()


def create_app() -> FastAPI:
    configure_logging(settings.log_level)
    app = FastAPI(
        title="JSON Redaction Gateway",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )
    app.add_middleware(RequestIDMiddleware)
    register_exception_handlers(app)
    app.include_router(policies.router)
    app.include_router(transform_api.router)

    @app.get("/health", tags=["meta"])
    async def health():
        return {"status": "ok"}

    return app


app = create_app()
