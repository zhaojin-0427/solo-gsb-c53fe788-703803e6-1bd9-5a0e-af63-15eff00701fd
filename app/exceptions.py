"""不依赖任何第三方库的客户端错误类型，供核心逻辑（jcs/engine/compliance）与 API 层共用。"""
from __future__ import annotations

from typing import Any


class ClientError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: Any = None,
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        # 结构化细节：只允许位置/规则 id/分支/witness 等非业务值
        self.details = details
