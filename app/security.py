"""脱敏动作：删除、局部遮盖、基于服务端密钥的确定性 HMAC 令牌化。"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .config import settings

_MASK_PLACEHOLDER = "***"  # 非字符串 / 非标量遮盖占位
_TOKEN_PREFIX = "hmac."


def mask_value(value: Any, keep_prefix: int = 0, keep_suffix: int = 0) -> str:
    if not isinstance(value, str):
        # 数字、布尔、null、对象、数组统一占位，绝不暴露原值的形态信息
        return _MASK_PLACEHOLDER
    n = len(value)
    if keep_prefix < 0 or keep_suffix < 0 or keep_prefix + keep_suffix > n:
        # 参数非法时安全兜底：固定占位，绝不返回原值
        return _MASK_PLACEHOLDER
    if keep_prefix + keep_suffix in (0, n):
        # 全覆盖（无保留位 或 保留位覆盖整个字符串）：固定占位，
        # 避免通过星号数量泄露原始长度
        return _MASK_PLACEHOLDER
    return (
        value[:keep_prefix]
        + "*" * (n - keep_prefix - keep_suffix)
        + value[n - keep_suffix:]
    )


def tokenize_value(value: Any, jcs_bytes: bytes) -> str:
    """对值的 JCS 规范字节做 HMAC-SHA256（密钥仅存在于服务端配置）。

    同一值 + 同一密钥 => 同一令牌；不同值（雪崩）=> 不同令牌。
    """
    digest = hmac.new(settings.hmac_key_bytes(), jcs_bytes, hashlib.sha256).hexdigest()
    return _TOKEN_PREFIX + digest
