"""结构化 JSON 日志。

安全约束：业务日志只能携带 request_id / policy_id / version / input_digest /
error_code / http_status / idempotency_replay 等安全字段，禁止出现原始文档、
脱敏结果或规则中的具体值。
"""
from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from typing import Any

ALLOWED_EXTRA_KEYS = {
    "request_id",
    "policy_id",
    "version",
    "input_digest",
    "error_code",
    "http_status",
    "idempotency_replay",
}

request_id_ctx: ContextVar[str | None] = ContextVar(
    "request_id", default=None
)


class SafeJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = request_id_ctx.get()
        if rid:
            payload["request_id"] = rid
        for key, value in record.__dict__.items():
            if key in ALLOWED_EXTRA_KEYS:
                payload[key] = value
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


class SafeLogger(logging.Logger):
    """只接受白名单结构化字段；其他 kwargs 一律丢弃，避免意外写入敏感值。"""

    def _safe_kwargs(self, kwargs: dict) -> dict:
        extra = kwargs.pop("extra", None) or {}
        safe_extra = {k: v for k, v in extra.items() if k in ALLOWED_EXTRA_KEYS}
        for key in ALLOWED_EXTRA_KEYS:
            if key in kwargs:
                safe_extra[key] = kwargs.pop(key)
        kwargs.pop("exc_info", None)  # 不输出堆栈，堆栈可能包含原始值
        if safe_extra:
            kwargs["extra"] = safe_extra
        return kwargs

    def info(self, msg, *args, **kwargs):
        super().info(msg, *args, **self._safe_kwargs(kwargs))

    def warning(self, msg, *args, **kwargs):
        super().warning(msg, *args, **self._safe_kwargs(kwargs))

    def error(self, msg, *args, **kwargs):
        super().error(msg, *args, **self._safe_kwargs(kwargs))

    def debug(self, msg, *args, **kwargs):
        super().debug(msg, *args, **self._safe_kwargs(kwargs))

    def critical(self, msg, *args, **kwargs):
        super().critical(msg, *args, **self._safe_kwargs(kwargs))

    def exception(self, msg, *args, **kwargs):
        # 永不记录异常详情
        super().error(msg, *args, **self._safe_kwargs(kwargs))


logging.setLoggerClass(SafeLogger)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(SafeJSONFormatter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # uvicorn 自带访问日志含路径与查询串，关闭后由网关统一记录安全字段
    for name in ("uvicorn.access",):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = False
    for name in ("uvicorn", "uvicorn.error", "fastapi", "sqlalchemy.engine"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True

    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> SafeLogger:
    return logging.getLogger(name)  # type: ignore[return-value]
