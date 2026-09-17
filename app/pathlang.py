"""受限规则路径解析与匹配。

允许的语法（且仅允许这些）：
  $            根
  .name        对象字段（name 由字母/数字/下划线组成，数字开头也允许，如 .1x）
  [n]          数组索引（十进制非负整数，禁止前导零，n >= 0）
  [*]          数组通配，命中该数组当前所有元素

示例： $.user.emails[*].address  /  $.items[0].id
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterator, Union

# 一段段匹配：.name  | [index] | [*]
_SEGMENT_RE = re.compile(
    r"(?:\.(?P<name>[A-Za-z0-9_]+))"
    r"|(?:\[(?:(?P<index>0|[1-9][0-9]*)|\*)\])"
)

Segment = Union[str, int, str]  # str 字段名 / int 索引 / "*" 通配
WILDCARD = "*"


class PathSyntaxError(ValueError):
    pass


def parse_path(path: str) -> tuple[Segment, ...]:
    if not isinstance(path, str) or not path:
        raise PathSyntaxError("path must be a non-empty string")
    if not path.startswith("$"):
        raise PathSyntaxError("path must start with '$'")
    rest = path[1:]
    segments: list[Segment] = []
    pos = 0
    while pos < len(rest):
        m = _SEGMENT_RE.match(rest, pos)
        if not m:
            raise PathSyntaxError(
                f"illegal path segment at position {pos + 1}; "
                "only '.name', '[n]' and '[*]' are allowed"
            )
        if m.group("name") is not None:
            segments.append(m.group("name"))
        elif m.group("index") is not None:
            segments.append(int(m.group("index")))
        else:
            segments.append(WILDCARD)
        pos = m.end()
    return tuple(segments)


@dataclass(frozen=True)
class Hit:
    """一次具体命中。prefix 是不含当前节点的具体路径（str 字段 / int 索引）。"""

    prefix: tuple[Any, ...]
    node: Any
    parent: Any | None
    term: Any  # 父容器中的键/索引；根命中时为 None


def _walk(
    value: Any,
    segments: tuple[Segment, ...],
    prefix: tuple[Any, ...],
    parent: Any | None,
    term: Any | None,
) -> Iterator[Hit]:
    if not segments:
        yield Hit(prefix=prefix, node=value, parent=parent, term=term)
        return
    seg = segments[0]
    tail = segments[1:]
    if seg == WILDCARD:
        if isinstance(value, list):
            for i, child in enumerate(value):
                yield from _walk(child, tail, prefix + (i,), value, i)
        return
    if isinstance(seg, int):
        if isinstance(value, list) and seg < len(value):
            yield from _walk(value[seg], tail, prefix + (seg,), value, seg)
        return
    # 字段
    if isinstance(value, dict) and seg in value:
        yield from _walk(value[seg], tail, prefix + (seg,), value, seg)


def match(value: Any, segments: tuple[Segment, ...]) -> list[Hit]:
    return list(_walk(value, segments, (), None, None))


def format_path(prefix: tuple[Any, ...]) -> str:
    out = "$"
    for p in prefix:
        if isinstance(p, int):
            out += f"[{p}]"
        else:
            out += f".{p}"
    return out
