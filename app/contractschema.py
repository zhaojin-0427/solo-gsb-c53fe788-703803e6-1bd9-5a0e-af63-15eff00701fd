"""受限 JSON Schema（Draft 2020-12）契约校验。

契约用于声明敏感节点（`x-redaction`）及其允许的脱敏动作，保存为不可变版本。
为保证发布门禁的静态分析可判定、可终止，契约只允许以下验证关键字：

  type / properties / required / additionalProperties / items / prefixItems /
  allOf / anyOf / oneOf

外加本地 `$ref` / `$defs`（仅文档内 JSON Pointer）、`$schema`（必须为
Draft 2020-12 URI）与扩展关键字 `x-redaction`。其余关键字一律拒绝。
`$ref` 循环引用会被检测并拒绝——循环分析本身保证终止（有限指针图上的 DFS）。

本模块不依赖任何第三方库，供 API 层与门禁分析共用。
"""
from __future__ import annotations

from typing import Any, Iterator

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

# 允许的验证关键字 + 本地引用/定义 + 扩展关键字
ALLOWED_KEYWORDS = frozenset(
    {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "prefixItems",
        "allOf",
        "anyOf",
        "oneOf",
        "$ref",
        "$defs",
        "$schema",
        "x-redaction",
    }
)

JSON_TYPES = frozenset(
    {"object", "array", "string", "number", "integer", "boolean", "null"}
)

REDACTION_ACTIONS = frozenset({"delete", "mask", "tokenize"})

# schema 嵌套深度上限：保证校验与门禁分析的递归始终有界、可终止
_MAX_DEPTH = 128


class SchemaError(ValueError):
    """契约 schema 非法。消息只包含关键字名与位置，不含业务值。"""


def _escape(pointer_segment: str) -> str:
    return pointer_segment.replace("~", "~0").replace("/", "~1")


def _unescape(pointer_segment: str) -> str:
    return pointer_segment.replace("~1", "/").replace("~0", "~")


def resolve_pointer(doc: Any, pointer: str) -> Any:
    """解析文档内 JSON Pointer（RFC 6901）。pointer 为空串时返回根。

    无法解析（段不存在 / 类型不符 / 数组下标非法）时抛 SchemaError。
    """
    if pointer == "":
        return doc
    if not pointer.startswith("/"):
        raise SchemaError(f"invalid local $ref pointer: '#{pointer}'")
    node = doc
    for raw in pointer.split("/")[1:]:
        seg = _unescape(raw)
        if isinstance(node, dict):
            if seg not in node:
                raise SchemaError(f"unresolvable $ref pointer: '#{pointer}'")
            node = node[seg]
        elif isinstance(node, list):
            if not seg.isdigit() or (seg != "0" and seg.startswith("0")):
                raise SchemaError(f"unresolvable $ref pointer: '#{pointer}'")
            idx = int(seg)
            if idx >= len(node):
                raise SchemaError(f"unresolvable $ref pointer: '#{pointer}'")
            node = node[idx]
        else:
            raise SchemaError(f"unresolvable $ref pointer: '#{pointer}'")
    return node


def _check_type_keyword(value: Any, loc: str) -> None:
    def ok(t: Any) -> bool:
        return isinstance(t, str) and t in JSON_TYPES

    if isinstance(value, str):
        if not ok(value):
            raise SchemaError(f"invalid type value at {loc}")
        return
    if isinstance(value, list):
        if not value or not all(ok(t) for t in value) or len(set(value)) != len(value):
            raise SchemaError(f"invalid type list at {loc}")
        return
    raise SchemaError(f"invalid 'type' keyword at {loc}")


def _check_string_list(value: Any, loc: str, keyword: str) -> None:
    if (
        not isinstance(value, list)
        or not all(isinstance(v, str) for v in value)
        or len(set(value)) != len(value)
    ):
        raise SchemaError(f"invalid '{keyword}' keyword at {loc}")


def _check_redaction(value: Any, loc: str) -> None:
    if not isinstance(value, dict) or set(value.keys()) != {"actions"}:
        raise SchemaError(
            f"invalid 'x-redaction' at {loc}: expected object with only 'actions'"
        )
    actions = value["actions"]
    if (
        not isinstance(actions, list)
        or not actions
        or not all(isinstance(a, str) for a in actions)
        or len(set(actions)) != len(actions)
        or not set(actions) <= REDACTION_ACTIONS
    ):
        raise SchemaError(
            f"invalid 'x-redaction.actions' at {loc}: non-empty unique subset of "
            "delete/mask/tokenize required"
        )


def _walk(node: Any, loc: str, depth: int = 0) -> Iterator[tuple[str, str]]:
    """校验单个 schema 节点并递归子节点；产出 (出现位置, $ref 目标指针)。"""
    if depth > _MAX_DEPTH:
        raise SchemaError(f"schema nesting too deep at {loc} (max {_MAX_DEPTH})")
    if isinstance(node, bool):
        return
    if not isinstance(node, dict):
        raise SchemaError(f"schema at {loc} must be an object or boolean")

    for key in node:
        if key not in ALLOWED_KEYWORDS:
            raise SchemaError(f"unsupported keyword '{key}' at {loc}")

    if "$schema" in node:
        if node["$schema"] != DRAFT_2020_12:
            raise SchemaError(f"'$schema' at {loc} must be {DRAFT_2020_12}")
    if "type" in node:
        _check_type_keyword(node["type"], loc)
    if "required" in node:
        _check_string_list(node["required"], loc, "required")
    if "x-redaction" in node:
        _check_redaction(node["x-redaction"], loc)

    if "$ref" in node:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#"):
            raise SchemaError(f"only local '$ref' ('#...') is allowed at {loc}")
        yield loc, ref[1:]

    if "properties" in node:
        props = node["properties"]
        if not isinstance(props, dict):
            raise SchemaError(f"invalid 'properties' at {loc}")
        for name, sub in props.items():
            yield from _walk(sub, f"{loc}/properties/{_escape(name)}", depth + 1)
    if "additionalProperties" in node:
        yield from _walk(
            node["additionalProperties"], f"{loc}/additionalProperties", depth + 1
        )
    if "items" in node:
        yield from _walk(node["items"], f"{loc}/items", depth + 1)
    if "prefixItems" in node:
        prefix = node["prefixItems"]
        if not isinstance(prefix, list):
            raise SchemaError(f"invalid 'prefixItems' at {loc}")
        for i, sub in enumerate(prefix):
            yield from _walk(sub, f"{loc}/prefixItems/{i}", depth + 1)
    for kw in ("allOf", "anyOf", "oneOf"):
        if kw in node:
            branches = node[kw]
            if not isinstance(branches, list) or not branches:
                raise SchemaError(f"invalid '{kw}' at {loc}: non-empty array required")
            for i, sub in enumerate(branches):
                yield from _walk(sub, f"{loc}/{kw}/{i}", depth + 1)
    if "$defs" in node:
        defs = node["$defs"]
        if not isinstance(defs, dict):
            raise SchemaError(f"invalid '$defs' at {loc}")
        for name, sub in defs.items():
            yield from _walk(sub, f"{loc}/$defs/{_escape(name)}", depth + 1)


def _check_ref_cycles(doc: Any, refs: list[tuple[str, str]]) -> None:
    """在有限指针图上检测 $ref 循环，保证终止。

    若位置 L 的子树内出现指向 T 的 $ref，则展开 L 依赖展开 T（边 L -> T）。
    图中存在环 <=> 展开可能无限递归 => 拒绝。
    """
    # 位置 -> 直接依赖的目标位置集合
    edges: dict[str, set[str]] = {}
    validated_targets: set[str] = set()
    for loc, pointer in refs:
        # 解析目标位置：目标是文档内某个子 schema 的指针
        target = "#" + (pointer if pointer else "")
        # 校验可解析（不可解析在此报错）
        target_node = resolve_pointer(doc, pointer)
        # 目标本身必须是合法 schema（防止指向 #/required/0 等非 schema 位置）
        if target not in validated_targets:
            validated_targets.add(target)
            list(_walk(target_node, target))
        # loc 及其所有祖先位置都依赖该目标
        parts = loc.split("/")
        for i in range(1, len(parts) + 1):
            ancestor = "/".join(parts[:i]) or "#"
            edges.setdefault(ancestor, set()).add(target)

    # 迭代式 DFS 三色标记，避免递归深度限制，保证终止
    color: dict[str, int] = {}  # 0=未访问 1=访问中 2=完成
    for start in edges:
        if color.get(start) == 2:
            continue
        stack: list[tuple[str, Iterator[str]]] = [(start, iter(edges.get(start, ())))]
        color[start] = 1
        while stack:
            node, it = stack[-1]
            advanced = False
            for nxt in it:
                c = color.get(nxt, 0)
                if c == 1:
                    raise SchemaError(
                        f"cyclic $ref detected involving {nxt}: recursive contracts "
                        "are not supported"
                    )
                if c == 0:
                    color[nxt] = 1
                    stack.append((nxt, iter(edges.get(nxt, ()))))
                    advanced = True
                    break
            if not advanced:
                color[node] = 2
                stack.pop()


def validate_contract_schema(doc: Any) -> None:
    """校验契约 schema。非法时抛 SchemaError（ValueError 子类）。"""
    if not isinstance(doc, (dict, bool)):
        raise SchemaError("contract schema must be a JSON object or boolean")
    refs = list(_walk(doc, "#"))
    _check_ref_cycles(doc, refs)
