"""不依赖任何第三方库的客户端错误类型，供核心逻辑（jcs/engine）与 API 层共用。"""
from __future__ import annotations


class ClientError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        self.code = code
        self.message = message
        self.status_code = status_code
