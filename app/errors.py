"""错误模型与异常处理器。

错误响应只包含 code/message/request_id，绝不回显请求体或规则值。
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .exceptions import ClientError
from .logging_config import get_logger

__all__ = ["ClientError"]

logger = get_logger(__name__)


def _envelope(code: str, message: str, request_id: str | None, details=None):
    body = {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id,
        }
    }
    if details is not None:
        body["error"]["details"] = details
    return body


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ClientError)
    async def client_error_handler(request: Request, exc: ClientError):
        logger.warning(
            "request_failed",
            error_code=exc.code,
            http_status=exc.status_code,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(
                exc.code, exc.message, request.state.request_id, exc.details
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # 只暴露出错位置与校验类型，绝不包含输入值
        details = []
        for err in exc.errors():
            details.append(
                {
                    "loc": [str(p) for p in err.get("loc", [])],
                    "type": err.get("type", "value_error"),
                }
            )
        logger.warning(
            "request_failed",
            error_code="VALIDATION_ERROR",
            http_status=422,
        )
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "request validation failed",
                    "request_id": request.state.request_id,
                    "details": details,
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        code_map = {
            404: "NOT_FOUND",
            405: "METHOD_NOT_ALLOWED",
            409: "CONFLICT",
            413: "PAYLOAD_TOO_LARGE",
            415: "UNSUPPORTED_MEDIA_TYPE",
        }
        code = code_map.get(exc.status_code, "HTTP_ERROR")
        logger.warning(
            "request_failed",
            error_code=code,
            http_status=exc.status_code,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(code, str(exc.detail), request.state.request_id),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # 不记录异常消息/堆栈，避免第三方组件把原始值写进日志
        logger.error(
            "request_failed",
            error_code="INTERNAL_ERROR",
            http_status=500,
        )
        return JSONResponse(
            status_code=500,
            content=_envelope(
                "INTERNAL_ERROR",
                "internal server error",
                request.state.request_id,
            ),
        )
