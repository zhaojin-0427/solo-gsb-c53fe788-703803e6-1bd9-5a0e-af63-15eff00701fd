"""受限 JSON Schema Draft 2020-12 契约编译器与实例校验器。

只支持以下关键字（其余一律拒绝）：
  元关键字：$schema / $id / $ref / $defs
  类型与结构：type / properties / required / additionalProperties /
             items / prefixItems
  组合：allOf / anyOf / oneOf
  扩展：x-redaction（敏感节点声明，{"actions": [...]}）

约束：
- $ref 只允许本地引用："#" 或 "#/$defs/<name>"；悬空引用拒绝；
- 引用图允许成环，编译期折叠为节点图，消费方（compliance）必须带
  已访问集合 / 深度预算终止遍历；
- 布尔 schema（true/false）支持。

本模块只依赖标准库，不接触业务数据，也不做任何持久化。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"

BASIC_TYPES = ("null", "boolean", "object", "array", "number", "string", "integer")
REDACTION_ACTIONS = ("delete", "mask", "tokenize")

_ALLOWED_KEYS = {
    "$schema",
    "$id",
    "$ref",
    "$defs",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "prefixItems",
    "allOf",
    "anyOf",
    "oneOf",
    "x-redaction",
}


class ContractSchemaError(ValueError):
    """契约 schema 结构非法。pointer 为出错子 schema 的 JSON Pointer。"""

    def __init__(self, pointer: str, reason: str):
        self.pointer = pointer or "#"
        self.reason = reason
        super().__init__(f"{self.pointer}: {reason}")


def escape_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _unescape_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


@dataclass
class Node:
    # JSON Pointer（不含前导 #；根为 ""），用于报错与分支定位
    pointer: str
    # None 表示未约束；否则为 BASIC_TYPES 子集（"integer" 与 "number" 可并存）
    types: frozenset[str] | None = None
    properties: dict[str, "Node"] = field(default_factory=dict)
    required: frozenset[str] = frozenset()
    # additionalProperties：None=未约束 / False 布尔 / Node 子 schema
    additional: "Node | bool | None" = None
    prefix: list["Node"] = field(default_factory=list)
    items: "Node | None" = None
    # $ref 在编译完成后折叠进 all_of（2020-12 中 $ref 与同级关键字为 AND）
    all_of: list["Node"] = field(default_factory=list)
    any_of: list["Node"] = field(default_factory=list)
    one_of: list["Node"] = field(default_factory=list)
    # None=未声明敏感；否则为允许动作集合
    actions: frozenset[str] | None = None
    # 布尔 schema 标记（共享哨兵 TRUE/FALSE 时为 True/False）
    boolean: bool | None = None


class Schema:
    def __init__(self, root: Node, nodes_by_pointer: dict[str, Node]):
        self.root = root
        self.nodes_by_pointer = nodes_by_pointer

    def schema_path(self, node: Node) -> str:
        return "#" + node.pointer if node.pointer else "#"


# 共享布尔哨兵（pointer 仅用于展示）
TRUE = Node(pointer="#true", boolean=True)
FALSE = Node(pointer="#false", boolean=False)


class _Compiler:
    def __init__(self, raw: Any):
        self.raw = raw
        self.nodes_by_pointer: dict[str, Node] = {}
        # (node, ref_string)，编译全部结束后统一解析
        self._pending_refs: list[tuple[Node, str]] = []

    def compile(self) -> Schema:
        root = self._build(self.raw, "")
        self._resolve_refs()
        return Schema(root, self.nodes_by_pointer)

    # ---- 结构校验 + 节点构建 ----
    def _build(self, raw: Any, pointer: str) -> Node:
        if isinstance(raw, bool):
            return TRUE if raw else FALSE
        if not isinstance(raw, dict):
            raise ContractSchemaError(pointer, "schema must be object or boolean")

        unknown = set(raw.keys()) - _ALLOWED_KEYS
        if unknown:
            raise ContractSchemaError(
                pointer,
                f"unsupported keyword(s): {sorted(unknown)}; only the documented "
                "Draft 2020-12 subset and x-redaction are allowed",
            )

        schema_value = raw.get("$schema")
        if schema_value is not None and schema_value != DRAFT_2020_12:
            raise ContractSchemaError(
                pointer, "$schema must be the Draft 2020-12 meta-schema URL"
            )

        id_value = raw.get("$id")
        if id_value is not None and not isinstance(id_value, str):
            raise ContractSchemaError(pointer, "$id must be a string")

        node = Node(pointer=pointer)
        # 先登记，保证成环引用也能在编译期取到节点对象
        self.nodes_by_pointer[pointer] = node

        node.types = self._parse_types(raw.get("type"), pointer)

        if "properties" in raw:
            props = raw["properties"]
            if not isinstance(props, dict) or not all(
                isinstance(k, str) and isinstance(v, (dict, bool))
                for k, v in props.items()
            ):
                raise ContractSchemaError(
                    f"{pointer}/properties",
                    "properties must be an object mapping names to schemas",
                )
            node.properties = {
                k: self._build(v, f"{pointer}/properties/{escape_token(k)}")
                for k, v in props.items()
            }

        if "required" in raw:
            req = raw["required"]
            if (
                not isinstance(req, list)
                or not all(isinstance(x, str) for x in req)
                or len(set(req)) != len(req)
            ):
                raise ContractSchemaError(
                    f"{pointer}/required",
                    "required must be an array of unique strings",
                )
            node.required = frozenset(req)

        if "additionalProperties" in raw:
            ap = raw["additionalProperties"]
            if isinstance(ap, bool):
                node.additional = ap
            else:
                node.additional = self._build(ap, f"{pointer}/additionalProperties")

        if "items" in raw:
            items = raw["items"]
            if isinstance(items, list):
                # items 数组是 draft-04 元组形式，不属于 2020-12
                raise ContractSchemaError(
                    f"{pointer}/items",
                    "items must be a single schema (use prefixItems for tuples)",
                )
            node.items = self._build(items, f"{pointer}/items")

        if "prefixItems" in raw:
            prefix = raw["prefixItems"]
            if not isinstance(prefix, list) or not all(
                isinstance(x, (dict, bool)) for x in prefix
            ):
                raise ContractSchemaError(
                    f"{pointer}/prefixItems",
                    "prefixItems must be an array of schemas",
                )
            node.prefix = [
                self._build(x, f"{pointer}/prefixItems/{i}")
                for i, x in enumerate(prefix)
            ]

        for kw in ("allOf", "anyOf", "oneOf"):
            if kw in raw:
                branches = raw[kw]
                if not isinstance(branches, list) or not all(
                    isinstance(x, (dict, bool)) for x in branches
                ):
                    raise ContractSchemaError(
                        f"{pointer}/{kw}", f"{kw} must be an array of schemas"
                    )
                children = [
                    self._build(x, f"{pointer}/{kw}/{i}")
                    for i, x in enumerate(branches)
                ]
                setattr(node, {"allOf": "all_of", "anyOf": "any_of", "oneOf": "one_of"}[kw], children)

        if "x-redaction" in raw:
            node.actions = self._parse_redaction(raw["x-redaction"], pointer)

        if "$ref" in raw:
            ref = raw["$ref"]
            if not isinstance(ref, str) or not (
                ref == "#" or ref.startswith("#/$defs/")
            ):
                raise ContractSchemaError(
                    f"{pointer}/$ref",
                    "only local refs are allowed: '#' or '#/$defs/<name>'",
                )
            self._pending_refs.append((node, ref))

        if "$defs" in raw:
            defs = raw["$defs"]
            if not isinstance(defs, dict) or not all(
                isinstance(k, str) and isinstance(v, (dict, bool))
                for k, v in defs.items()
            ):
                raise ContractSchemaError(
                    f"{pointer}/$defs", "$defs must be an object of schemas"
                )
            for k, v in defs.items():
                self._build(v, f"{pointer}/$defs/{escape_token(k)}")

        return node

    def _parse_types(self, value: Any, pointer: str) -> frozenset[str] | None:
        if value is None:
            return None
        types = [value] if isinstance(value, str) else value
        if (
            not isinstance(types, list)
            or not types
            or any(t not in BASIC_TYPES for t in types)
            or len(set(types)) != len(types)
        ):
            raise ContractSchemaError(
                f"{pointer}/type",
                f"type must be one of (or a unique non-empty array of) {BASIC_TYPES}",
            )
        return frozenset(types)

    def _parse_redaction(self, value: Any, pointer: str) -> frozenset[str]:
        if not isinstance(value, dict) or set(value.keys()) != {"actions"}:
            raise ContractSchemaError(
                f"{pointer}/x-redaction",
                "x-redaction must be an object with exactly an 'actions' array",
            )
        actions = value["actions"]
        if (
            not isinstance(actions, list)
            or not actions
            or any(a not in REDACTION_ACTIONS for a in actions)
            or len(set(actions)) != len(actions)
        ):
            raise ContractSchemaError(
                f"{pointer}/x-redaction/actions",
                f"actions must be a non-empty unique array of {REDACTION_ACTIONS}",
            )
        return frozenset(actions)

    def _resolve_refs(self) -> None:
        for node, ref in self._pending_refs:
            if ref == "#":
                target_pointer = ""
            else:
                token = ref[len("#/$defs/"):]
                target_pointer = "/$defs/" + _unescape_token(token)
            target = self.nodes_by_pointer.get(target_pointer)
            if target is None:
                raise ContractSchemaError(
                    node.pointer + "/$ref", f"dangling $ref: {ref}"
                )
            if target is not node and target not in node.all_of:
                # 自引用 / 成环引用允许：折叠为图边，消费方按环图终止
                node.all_of.append(target)


def compile_contract(raw: Any) -> Schema:
    """校验并编译原始契约 JSON（Python dict / bool），失败抛 ContractSchemaError。"""
    return _Compiler(raw).compile()


# ---------------------------------------------------------------------------
# 实例校验：用于验证静态分析合成的 witness 确实符合契约。
# JSON 文档有限，递归始终随实例下降，模式成环不会导致不终止。
# ---------------------------------------------------------------------------

def _type_matches(t: str, value: Any) -> bool:
    if t == "null":
        return value is None
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
        )
    if t == "string":
        return isinstance(value, str)
    if t == "array":
        return isinstance(value, list)
    if t == "object":
        return isinstance(value, dict)
    return False


def instance_valid(node: Node, value: Any) -> bool:
    if node is TRUE:
        return True
    if node is FALSE:
        return False

    if node.types is not None and not any(
        _type_matches(t, value) for t in node.types
    ):
        return False

    if isinstance(value, dict):
        for k, sub in node.properties.items():
            if k in value and not instance_valid(sub, value[k]):
                return False
        if any(k not in value for k in node.required):
            return False
        if node.additional is False:
            if any(k not in node.properties for k in value):
                return False
        elif isinstance(node.additional, Node):
            for k, v in value.items():
                if k not in node.properties and not instance_valid(node.additional, v):
                    return False

    if isinstance(value, list):
        for i, sub in enumerate(node.prefix):
            if i < len(value) and not instance_valid(sub, value[i]):
                return False
        if node.items is not None:
            for i in range(len(node.prefix), len(value)):
                if not instance_valid(node.items, value[i]):
                    return False

    if node.all_of and not all(instance_valid(sub, value) for sub in node.all_of):
        return False
    if node.any_of and not any(instance_valid(sub, value) for sub in node.any_of):
        return False
    if node.one_of:
        if sum(1 for sub in node.one_of if instance_valid(sub, value)) != 1:
            return False
    return True


def instance_valid_all(nodes: list[Node], value: Any) -> bool:
    return all(instance_valid(n, value) for n in nodes)
