"""
JCS (RFC 8785) JSON 规范化的精简实现，用于计算输入摘要。

只支持 JSON 允许的类型（None/bool/int/float/str/list/dict）。
非有限数字（NaN / Infinity）不是合法 JSON，直接抛错。
对象键按 UTF-16 码元序排列。数字按 ECMAScript Number.prototype.toString
的最短往返形式渲染。
"""
from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from typing import Any

from .exceptions import ClientError


class NonFiniteNumberError(ValueError):
    pass


def _render_number(x: float) -> str:
    if not math.isfinite(x):
        raise NonFiniteNumberError("NaN and Infinity are not valid JSON numbers")
    if x == 0.0:
        return "0"

    # Decimal(repr(x)) 保留 Python 的最短往返十进制串；normalize() 去掉
    # 整数值浮点（如 100.0）多余的尾随零
    d = Decimal(repr(x)).normalize()
    sign, digits, exp = d.as_tuple()
    ds = "".join(map(str, digits))
    k = len(ds)
    n = exp + k  # 最高有效位相对个位的位置

    # RFC 8785 数字序列化：当 -6 < n <= 21 时用十进制普通记数法
    if -5 <= n <= 21:
        if n <= 0:
            s = "0." + ("0" * (-n)) + ds
        elif n >= k:
            s = ds + ("0" * (n - k))
        else:
            s = ds[:n] + "." + ds[n:]
    else:
        e = n - 1
        if k == 1:
            sig = ds
        else:
            sig = ds[0] + "." + ds[1:]
        s = sig + ("e+" if e >= 0 else "e-") + str(abs(e))

    return ("-" if sign else "") + s


def _utf16_key(key: str) -> tuple[int, ...]:
    return tuple(ord(c) for c in key)


def canonicalize(value: Any) -> bytes:
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        return _render_number(value).encode("ascii")
    if isinstance(value, list):
        parts = [b"["]
        for i, item in enumerate(value):
            if i:
                parts.append(b",")
            parts.append(canonicalize(item))
        parts.append(b"]")
        return b"".join(parts)
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise NonFiniteNumberError("object keys must be strings")
        parts = [b"{"]
        ordered = sorted(value.keys(), key=_utf16_key)
        for i, k in enumerate(ordered):
            if i:
                parts.append(b",")
            parts.append(canonicalize(k))
            parts.append(b":")
            parts.append(canonicalize(value[k]))
        parts.append(b"}")
        return b"".join(parts)
    raise NonFiniteNumberError(f"unsupported value type: {type(value).__name__}")


def digest(value: Any) -> tuple[str, bytes]:
    """返回 (sha256 hex 摘要, JCS 规范化字节)。非法输入抛 ClientError(400)。"""
    try:
        blob = canonicalize(value)
    except (NonFiniteNumberError, ValueError) as exc:
        raise ClientError(
            "INVALID_INPUT",
            "document cannot be JCS canonicalized",
            status_code=400,
        ) from exc
    return hashlib.sha256(blob).hexdigest(), blob
