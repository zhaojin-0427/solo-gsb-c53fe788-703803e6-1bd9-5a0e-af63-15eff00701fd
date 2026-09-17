"""不依赖任何第三方库的客户端错误类型，供核心逻辑（jcs/engine）与 API 层共用。"""
from __future__ import annotations


class ClientError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: dict | None = None,
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        # 仅用于结构性诊断信息（如门禁违规列表），绝不携带业务值
        self.details = details
