"""发布门禁静态分析。

在发布事务内对**待发布规则**与**不可变契约版本**做纯静态分析：按引擎既有的
首条命中、祖先动作上提（删除/遮盖/令牌化祖先节点即决定整个子树的命运）与数组
索引语义，检查契约中每个 `x-redaction` 敏感节点的所有可满足分支是否都被
**允许动作**覆盖。全部覆盖才允许生成 revision；否则返回违规列表，每条包含
最短具体路径、分支、相关规则与符合该分支的最小 witness 文档。

分析为纯函数：不执行任何脱敏转换，不读取/保存任何业务数据（witness 由契约
结构合成，只含类型占位值）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from typing import Any, Iterator
import json

from . import pathlang
from .contractschema import resolve_pointer
from .pathlang import WILDCARD

# 分析上限（防御性，正常契约远达不到；超限则门禁失败，宁可拒绝发布）
_MAX_WORLDS = 512        # allOf/anyOf/oneOf 展开后的分支世界上限
_MAX_COMBOS = 4096       # 单个敏感模式的实例化组合上限
_MAX_VIOLATIONS = 100    # 返回的违规条数上限

_ALL_TYPES = ("object", "array", "string", "number", "integer", "boolean", "null")


class _AnalysisLimit(Exception):
    pass


@dataclass(frozen=True)
class PSeg:
    """实例模式的一段：具体键 / 具体下标 / 任意下标 / 任意键。"""

    kind: str  # "key" | "index" | "any_index" | "any_key"
    value: Any = None
    min_index: int = 0        # any_index：可取的最小下标（prefixItems 之后）
    excluded: frozenset = frozenset()  # any_key：不可取的键（properties ∪ required）


@dataclass(frozen=True)
class _Conj:
    """一个合取项：实例必须同时满足所有合取项。loc 为契约内 JSON Pointer。"""

    node: dict
    loc: str


@dataclass
class _World:
    """一个可满足分支世界：到达某一实例模式路径时生效的合取项集合。"""

    path: tuple[PSeg, ...]
    conjuncts: tuple[_Conj, ...]
    branch: tuple[dict, ...]
    parent: "_World | None"
    via: PSeg | None
    flat: tuple[_Conj, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class _GateRule:
    index: int  # 声明序（首条命中语义）
    id: str
    path: str
    action: str
    segments: tuple


def _normalize(
    conjuncts: list[_Conj], root: Any
) -> tuple[list[_Conj] | None, tuple[str, list[tuple[Any, str]], str] | None]:
    """展开 $ref / allOf；遇到 anyOf/oneOf 时返回分支点。

    返回 (carried, split)：
    - carried 为 None：合取项含 false，世界不可满足；
    - split 为 None：全部合取项已稳定（只剩基础关键字）；
    - 否则 split = (keyword, options, owner_loc)，carried 为需带入各分支的合取项。
    """
    flat: list[_Conj] = []
    work = list(conjuncts)
    while work:
        conj = work.pop(0)
        node, loc = conj.node, conj.loc
        if node is True:
            continue
        if node is False:
            return None, None
        if "$ref" in node:
            pointer = node["$ref"][1:]
            target = resolve_pointer(root, pointer)
            target_loc = "#" + pointer if pointer else "#"
            remainder = {
                k: v for k, v in node.items() if k not in ("$ref", "$defs", "$schema")
            }
            work.insert(0, _Conj(target, target_loc))
            if remainder:
                work.insert(1, _Conj(remainder, loc))
            continue
        if "allOf" in node:
            remainder = {
                k: v for k, v in node.items() if k not in ("allOf", "$defs", "$schema")
            }
            for i, sub in enumerate(node["allOf"]):
                work.insert(i, _Conj(sub, f"{loc}/allOf/{i}"))
            if remainder:
                work.insert(len(node["allOf"]), _Conj(remainder, loc))
            continue
        for kw in ("anyOf", "oneOf"):
            if kw in node:
                remainder = {
                    k: v for k, v in node.items() if k not in (kw, "$defs", "$schema")
                }
                carried = flat + ([_Conj(remainder, loc)] if remainder else []) + work
                options = [
                    (sub, f"{loc}/{kw}/{i}") for i, sub in enumerate(node[kw])
                ]
                return carried, (kw, options, loc)
        cleaned = {k: v for k, v in node.items() if k not in ("$defs", "$schema")}
        if cleaned:
            flat.append(_Conj(cleaned, loc))
    return flat, None


def _stabilize(world: _World, root: Any, budget: list[int]) -> list[_World]:
    """把世界的合取项完全展开（含 anyOf/oneOf 分支），返回稳定世界列表。"""
    carried, split = _normalize(list(world.conjuncts), root)
    if carried is None:
        return []
    if split is None:
        world.flat = tuple(carried)
        budget[0] += 1
        if budget[0] > _MAX_WORLDS:
            raise _AnalysisLimit("too many schema branches")
        return [world]
    kw, options, owner_loc = split
    out: list[_World] = []
    for i, (sub, sub_loc) in enumerate(options):
        branch_entry = {"keyword": kw, "index": i, "schema_path": owner_loc}
        child = _World(
            path=world.path,
            conjuncts=tuple(carried) + (_Conj(sub, sub_loc),),
            branch=world.branch + (branch_entry,),
            parent=world.parent,
            via=world.via,
        )
        out.extend(_stabilize(child, root, budget))
    return out


def _type_set(flat: tuple[_Conj, ...]) -> set[str]:
    ts: set[str] | None = None
    for c in flat:
        t = c.node.get("type")
        if t is None:
            continue
        s = {t} if isinstance(t, str) else set(t)
        ts = s if ts is None else (ts & s)
    return ts if ts is not None else set(_ALL_TYPES)


def _required_union(flat: tuple[_Conj, ...]) -> list[str]:
    out: list[str] = []
    for c in flat:
        for r in c.node.get("required", []):
            if r not in out:
                out.append(r)
    return out


def _properties(flat: tuple[_Conj, ...]) -> list[str]:
    out: list[str] = []
    for c in flat:
        props = c.node.get("properties")
        if isinstance(props, dict):
            for name in props:
                if name not in out:
                    out.append(name)
    return out


def _unsatisfiable_required(flat: tuple[_Conj, ...]) -> bool:
    """additionalProperties:false 却要求未声明的属性 => 无可满足实例。"""
    required = _required_union(flat)
    if not required:
        return False
    for c in flat:
        if c.node.get("additionalProperties") is False:
            props = c.node.get("properties") or {}
            if any(r not in props for r in required):
                return True
    return False


def _child_conjuncts(flat: tuple[_Conj, ...], name: str) -> list[_Conj]:
    out: list[_Conj] = []
    for c in flat:
        props = c.node.get("properties") or {}
        if name in props:
            out.append(_Conj(props[name], f"{c.loc}/properties/{name}"))
        elif isinstance(c.node.get("additionalProperties"), dict):
            out.append(
                _Conj(c.node["additionalProperties"], f"{c.loc}/additionalProperties")
            )
    return out


def _elem_conjuncts(flat: tuple[_Conj, ...], index: int) -> list[_Conj]:
    out: list[_Conj] = []
    for c in flat:
        prefix = c.node.get("prefixItems") or []
        if index < len(prefix):
            out.append(_Conj(prefix[index], f"{c.loc}/prefixItems/{index}"))
        elif isinstance(c.node.get("items"), dict):
            out.append(_Conj(c.node["items"], f"{c.loc}/items"))
    return out


def _children(world: _World, root: Any) -> Iterator[_World]:
    """生成子世界（对象属性 / 任意附加键 / 元组下标 / 任意下标）。"""
    flat = world.flat
    types = _type_set(flat)
    path, branch = world.path, world.branch

    if "object" in types:
        propnames = _properties(flat)
        required = _required_union(flat)
        for name in propnames:
            # 某合取项禁止该附加键 => 该属性不可能出现
            if any(
                c.node.get("additionalProperties") is False
                and name not in (c.node.get("properties") or {})
                for c in flat
            ):
                continue
            yield _World(
                path=path + (PSeg("key", name),),
                conjuncts=tuple(_child_conjuncts(flat, name)),
                branch=branch,
                parent=world,
                via=PSeg("key", name),
            )
        # 任意附加键：所有合取项都允许附加键，且至少一个给出了附加键 schema
        ap_schemas = [
            _Conj(c.node["additionalProperties"], f"{c.loc}/additionalProperties")
            for c in flat
            if isinstance(c.node.get("additionalProperties"), dict)
        ]
        if ap_schemas and not any(
            c.node.get("additionalProperties") is False for c in flat
        ):
            via = PSeg(
                "any_key", excluded=frozenset(set(propnames) | set(required))
            )
            yield _World(
                path=path + (via,),
                conjuncts=tuple(ap_schemas),
                branch=branch,
                parent=world,
                via=via,
            )

    if "array" in types:
        max_prefix = 0
        for c in flat:
            prefix = c.node.get("prefixItems") or []
            max_prefix = max(max_prefix, len(prefix))
        for i in range(max_prefix):
            # 某合取项 items:false 且下标超出其 prefixItems => 该下标不可能存在
            if any(
                c.node.get("items") is False
                and i >= len(c.node.get("prefixItems") or [])
                for c in flat
            ):
                continue
            yield _World(
                path=path + (PSeg("index", i),),
                conjuncts=tuple(_elem_conjuncts(flat, i)),
                branch=branch,
                parent=world,
                via=PSeg("index", i),
            )
        # 任意下标（items 管辖，下标 >= max_prefix）
        item_schemas = [
            _Conj(c.node["items"], f"{c.loc}/items")
            for c in flat
            if isinstance(c.node.get("items"), dict)
        ]
        if item_schemas and not any(c.node.get("items") is False for c in flat):
            via = PSeg("any_index", min_index=max_prefix)
            yield _World(
                path=path + (via,),
                conjuncts=tuple(item_schemas),
                branch=branch,
                parent=world,
                via=via,
            )


# ---------------------------------------------------------------- 覆盖判定


def _rule_seg_compatible(rseg: Any, pseg: PSeg) -> bool:
    """规则段是否可能与模式段的某一实例匹配。"""
    if pseg.kind == "key":
        return rseg == pseg.value
    if pseg.kind == "index":
        return rseg == pseg.value or rseg == WILDCARD
    if pseg.kind == "any_index":
        if rseg == WILDCARD:
            return True
        return isinstance(rseg, int) and rseg >= pseg.min_index
    # any_key：实例是字符串键，规则通配只匹配数组下标，永不匹配
    return isinstance(rseg, str) and rseg != WILDCARD


def _compatible(rsegs: tuple, path: tuple[PSeg, ...], skip: int | None = None) -> bool:
    if len(rsegs) > len(path):
        return False
    return all(
        _rule_seg_compatible(rsegs[j], path[j])
        for j in range(len(rsegs))
        if j != skip
    )


def _seg_matches_concrete(rseg: Any, cseg: Any) -> bool:
    if isinstance(rseg, str):
        if rseg == WILDCARD:
            return isinstance(cseg, int)
        return cseg == rseg
    return cseg == rseg


def _matches_concrete(rsegs: tuple, concrete: tuple) -> bool:
    return all(
        _seg_matches_concrete(rsegs[j], concrete[j]) for j in range(len(rsegs))
    )


def _path_sort_key(concrete: tuple) -> tuple:
    return tuple((0, v) if isinstance(v, int) else (1, v) for v in concrete)


def _fate(concrete: tuple, candidates: list[_GateRule]) -> tuple[_GateRule, int] | None:
    """具体路径的命运：最浅被命中节点上的首条规则（声明序）。"""
    for ell in range(len(concrete) + 1):
        for r in candidates:
            if len(r.segments) == ell and _matches_concrete(r.segments, concrete):
                return r, ell
    return None


def _fresh_key(mentioned: set[str], excluded: frozenset) -> str:
    n = 0
    while True:
        cand = f"k{n}"
        if cand not in mentioned and cand not in excluded:
            return cand
        n += 1


def _coverage_violations(
    world: _World,
    allowed: set[str],
    rules: list[_GateRule],
    root: Any,
    schema_loc: str,
) -> list[dict]:
    """检查一个敏感模式：对每个实例化，最浅命中规则的动作为允许动作。"""
    path = world.path
    candidates = [r for r in rules if _compatible(r.segments, path)]

    # 通配/任意键位置的相关取值：规则提到的具体值 + 一个全新值
    choice_lists: list[list] = []
    for i, pseg in enumerate(path):
        if pseg.kind == "any_index":
            mentioned = {
                r.segments[i]
                for r in rules
                if len(r.segments) > i
                and isinstance(r.segments[i], int)
                and r.segments[i] >= pseg.min_index
                and _compatible(r.segments, path, skip=i)
            }
            fresh = pseg.min_index
            while fresh in mentioned:
                fresh += 1
            choice_lists.append(sorted(mentioned) + [fresh])
        elif pseg.kind == "any_key":
            mentioned = {
                r.segments[i]
                for r in rules
                if len(r.segments) > i
                and isinstance(r.segments[i], str)
                and r.segments[i] != WILDCARD
                and r.segments[i] not in pseg.excluded
                and _compatible(r.segments, path, skip=i)
            }
            choice_lists.append(
                sorted(mentioned) + [_fresh_key(mentioned, pseg.excluded)]
            )

    combos = 1
    for ch in choice_lists:
        combos *= len(ch)
    if combos > _MAX_COMBOS:
        raise _AnalysisLimit("too many concrete index combinations")

    # 每种失败类型保留最短（字典序最小）的具体路径
    best: dict[str, tuple] = {}
    for combo in product(*choice_lists) if choice_lists else [()]:
        concrete = []
        it = iter(combo)
        for pseg in path:
            if pseg.kind in ("key", "index"):
                concrete.append(pseg.value)
            else:
                concrete.append(next(it))
        concrete = tuple(concrete)

        fate = _fate(concrete, candidates)
        if fate is None:
            kind, winner, shadowed = "uncovered", None, []
        else:
            winner, ell = fate
            if winner.action in allowed:
                continue
            shadowed = [
                r
                for r in candidates
                if len(r.segments) == ell
                and r.index > winner.index
                and r.action in allowed
                and _matches_concrete(r.segments, concrete)
            ]
            kind = "shadowed" if shadowed else "action_mismatch"
        key = _path_sort_key(concrete)
        current = best.get(kind)
        if current is None or key < current[0]:
            best[kind] = (key, concrete, winner, shadowed)

    out = []
    for kind, (_, concrete, winner, shadowed) in best.items():
        related = ([] if winner is None else [winner]) + list(shadowed)
        out.append(
            (
                len(concrete),
                {
                    "kind": kind,
                    "path": pathlang.format_path(concrete),
                    "allowed_actions": sorted(allowed),
                    "effective_action": winner.action if winner else None,
                    "schema_path": schema_loc,
                    "branch": [dict(b) for b in world.branch],
                    "rules": [
                        {"id": r.id, "path": r.path, "action": r.action}
                        for r in related
                    ],
                    "witness": _build_witness(world, concrete, root),
                },
            )
        )
    return out


# ---------------------------------------------------------------- witness


def _normalize_pick_first(conjuncts: list[_Conj], root: Any) -> list[_Conj] | None:
    """witness 构造用的归一化：anyOf/oneOf 确定性地取第一个分支。"""
    work = list(conjuncts)
    for _ in range(10000):  # 防御性上限；无环契约必然在此之前收敛
        carried, split = _normalize(work, root)
        if carried is None:
            return None
        if split is None:
            return carried
        kw, options, _loc = split
        work = carried + [_Conj(options[0][0], options[0][1])]
    return None


def _minimal_value(raw_nodes: list[Any], root: Any) -> Any:
    """按类型构造最小占位值（witness 叶子，不含任何业务数据）。"""
    flat = _normalize_pick_first([_Conj(n, "#") for n in raw_nodes], root)
    if flat is None:
        return None
    flat_t = tuple(flat)
    types = _type_set(flat_t)
    if "string" in types:
        return ""
    if "integer" in types or "number" in types:
        return 0
    if "boolean" in types:
        return False
    if "object" in types:
        return {
            r: _minimal_value([c.node for c in _child_conjuncts(flat_t, r)], root)
            for r in _required_union(flat_t)
        }
    if "array" in types:
        return []
    return None


def _build_witness(world: _World, concrete: tuple, root: Any) -> Any:
    """符合该分支的最小文档：只含敏感路径与各级 required 兄弟。"""
    chain: list[_World] = []
    w: _World | None = world
    while w is not None:
        chain.append(w)
        w = w.parent
    chain.reverse()
    return _witness_node(chain, 0, concrete, root)


def _witness_node(chain: list[_World], depth: int, concrete: tuple, root: Any) -> Any:
    world = chain[depth]
    if depth == len(concrete):
        return _minimal_value([c.node for c in world.flat], root)
    cseg = concrete[depth]
    if isinstance(cseg, str):
        obj: dict[str, Any] = {}
        for r in _required_union(world.flat):
            if r != cseg:
                obj[r] = _minimal_value(
                    [c.node for c in _child_conjuncts(world.flat, r)], root
                )
        obj[cseg] = _witness_node(chain, depth + 1, concrete, root)
        return obj
    arr = [
        _minimal_value([c.node for c in _elem_conjuncts(world.flat, i)], root)
        for i in range(cseg)
    ]
    arr.append(_witness_node(chain, depth + 1, concrete, root))
    return arr


# ---------------------------------------------------------------- 入口


def _pattern_text(path: tuple[PSeg, ...]) -> str:
    out = "$"
    for s in path:
        if s.kind == "key":
            out += f".{s.value}"
        elif s.kind == "index":
            out += f"[{s.value}]"
        elif s.kind == "any_index":
            out += "[*]"
        else:
            out += ".*"
    return out


def analyze_contract(schema: Any, rules: list[dict]) -> list[dict]:
    """静态分析待发布规则是否满足契约。返回违规列表（空 = 通过）。

    每条违规包含：kind（uncovered/action_mismatch/shadowed/analysis_limit）、
    最短具体路径 path、分支 branch、相关规则 rules、允许动作、实际生效动作、
    契约位置 schema_path 与符合该分支的最小 witness 文档。
    """
    gate_rules = [
        _GateRule(i, r["id"], r["path"], r["action"], tuple(pathlang.parse_path(r["path"])))
        for i, r in enumerate(rules)
    ]
    budget = [0]
    found: list[tuple[int, dict]] = []
    visited: set = set()
    root_world = _World(
        path=(), conjuncts=(_Conj(schema, "#"),), branch=(), parent=None, via=None
    )
    worklist = [root_world]
    try:
        while worklist:
            w = worklist.pop(0)
            for sw in _stabilize(w, schema, budget):
                flat = sw.flat
                if not _type_set(flat) or _unsatisfiable_required(flat):
                    continue
                fingerprint = (
                    sw.path,
                    tuple(
                        sorted(
                            json.dumps(c.node, sort_keys=True, separators=(",", ":"))
                            for c in flat
                        )
                    ),
                )
                if fingerprint in visited:
                    continue
                visited.add(fingerprint)
                xreds = [c for c in flat if "x-redaction" in c.node]
                if xreds:
                    allowed: set[str] | None = None
                    for c in xreds:
                        actions = set(c.node["x-redaction"]["actions"])
                        allowed = actions if allowed is None else (allowed & actions)
                    found.extend(
                        _coverage_violations(
                            sw, allowed or set(), gate_rules, schema, xreds[0].loc
                        )
                    )
                worklist.extend(_children(sw, schema))
    except _AnalysisLimit:
        return [
            {
                "kind": "analysis_limit",
                "path": None,
                "allowed_actions": [],
                "effective_action": None,
                "schema_path": None,
                "branch": [],
                "rules": [],
                "witness": None,
            }
        ]

    # 去重（同一最短路径同一类型只保留首次），按路径长度/字典序排序
    seen: set = set()
    violations: list[dict] = []
    for seg_count, v in sorted(found, key=lambda t: (t[0], t[1]["path"], t[1]["kind"])):
        key = (v["kind"], v["path"])
        if key in seen:
            continue
        seen.add(key)
        violations.append(v)
        if len(violations) >= _MAX_VIOLATIONS:
            break
    return violations
