"""请求 ID 中间件：接受客户端合法 UUID，否则服务端生成。"""
from __future__ import annotations

import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from .logging_config import request_id_ctx


class RequestIDMiddleware(BaseHTTPMiddleware):
    HEADER = "x-request-id"

    async def dispatch(self, request: Request, call_next):
        raw = request.headers.get(self.HEADER)
        try:
            request_id = str(uuid.UUID(raw)) if raw else str(uuid.uuid4())
        except (ValueError, AttributeError):
            request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        token = request_id_ctx.set(request_id)
        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)
        response.headers[self.HEADER] = request_id
        return response
