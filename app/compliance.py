"""发布门禁：规则集相对不可变契约版本的静态合规分析。

判定方式（与脱敏引擎的执行语义一致）：
- 在**原始文档**上命中：规则 path 的每个节点都必须存在才命中；
- 同一具体节点多条规则命中时**首条声明规则生效**，后续为 duplicate；
- 祖先节点被首条 delete 删除时，后代命中全部 skipped（后代敏感实例
  因此不会出现在输出中，视为被覆盖）；
- 数组按具体索引判定，[*] 覆盖该数组所有元素。

分析器枚举契约中所有“可满足分支”里的敏感实例（x-redaction 声明），
合成**符合该分支的最小 witness 文档**来暴露违规，自身绝不执行脱敏转换、
不读取或保存任何业务数据。

三种失败：
- uncovered  敏感实例在 witness 上没有任何规则命中；
- mismatch   首条命中的动作不在契约允许动作内，且没有前序规则遮蔽；
- shadowed   前序规则（相同节点的 duplicate，或祖先的 delete）使一条
             本可允许的规则失效；返回相关的遮蔽/被遮蔽规则。

循环引用：枚举带深度预算（取规则最长路径、契约最近敏感声明深度与 3
的最大值，硬顶 64），环上递归必然终止。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product
from typing import Any, Iterator

from . import pathlang
from .contracts import (
    FALSE,
    TRUE,
    Node,
    Schema,
    instance_valid_all,
)

# 环上递归的深度硬顶：循环安全本身由 on_path 访问集合保证（图有限），
# 硬顶仅用于限制非循环的超深静态结构带来的分析成本。
_MAX_DEPTH_CAP = 64
# 返回给调用方的失败明细上限（首条为最短路径）
_MAX_VIOLATIONS = 5
# 数组索引候选组合上限
_MAX_INDEX_COMBOS = 12

ALL_ACTIONS = frozenset({"delete", "mask", "tokenize"})
EXTRA_KEY = "extra"

# 抽象段：str 字段名 / int 具体索引 / ITEMS_TAIL 表示 items 尾部任意元素
ITEMS_TAIL = "__items_tail__"


@dataclass(frozen=True)
class BranchCrumb:
    # anyOf | oneOf
    combinator: str
    index: int
    # 该组合节点的 schema 路径（#/$defs/... 形式）
    schema_path: str


@dataclass
class Frame:
    """一个 flat world（某分支下当前位置全部 AND 适用节点）的合并视图。"""

    nodes: list[Node]
    types: frozenset[str] | None
    required: frozenset[str]
    properties: dict[str, list[Node]]
    # None=未约束 / False=禁止附加属性 / list[Node]=附加属性约束
    additional: Any
    prefix: list[list[Node]]
    items: list[Node] | None
    actions: frozenset[str] | None


@dataclass(frozen=True)
class Target:
    """一个可满足分支中的敏感实例。"""

    abstract: tuple  # 抽象路径段
    allowed: frozenset[str]
    crumbs: tuple[BranchCrumb, ...]
    # 沿路径每一层选中的 flat world（节点列表），chain[-1] 为敏感节点本身
    chain: tuple[tuple[Node, ...], ...]


@dataclass
class Violation:
    kind: str  # uncovered | mismatch | shadowed
    # 具体路径（合规路径语法），如 $.users[1].tax_id
    path: str
    allowed_actions: list[str]
    branch: list[dict]
    witness: Any
    # 相关规则（仅 id/path/action/顺序，绝无业务值）
    rules: list[dict] = field(default_factory=list)


class ComplianceError(ValueError):
    """分析器输入本身有问题（规则路径无法解析）。"""


# ---------------------------------------------------------------------------
# flat world：AND 节点（含 $ref 折叠边、allOf）与 anyOf/oneOf 选择的展开。
# on_path 记录 AND 链上已出现的节点指针，循环 $ref 在此终止。
# ---------------------------------------------------------------------------

def flat_worlds(
    nodes: list[Node],
    depth_budget: int,
) -> list[tuple[list[Node], tuple[BranchCrumb, ...]]]:
    worlds: list[tuple[list[Node], tuple[BranchCrumb, ...]]] = []
    seen: set[tuple] = set()

    def expand(
        pending: tuple[Node, ...],
        acc: list[Node],
        crumbs: tuple[BranchCrumb, ...],
        depth: int,
        on_path: frozenset[str],
    ) -> Iterator[None]:
        if depth > depth_budget:
            key = (tuple(n.pointer for n in acc + list(pending)), crumbs)
            if key not in seen:
                seen.add(key)
                worlds.append((acc + list(pending), crumbs))
            return
        if not pending:
            key = (tuple(n.pointer for n in acc), crumbs)
            if key not in seen:
                seen.add(key)
                worlds.append((acc, crumbs))
            return

        node = pending[0]
        rest = pending[1:]

        if node is TRUE:
            expand(rest, acc, crumbs, depth + 1, on_path)
            return
        if node is FALSE:
            return  # 该分支不可满足

        forks: list[tuple[str, list[Node]]] = []
        if node.any_of:
            forks.append(("anyOf", node.any_of))
        if node.one_of:
            forks.append(("oneOf", node.one_of))

        # $ref 已在编译期折叠进 all_of；环上重复节点不再展开
        and_subs = [
            sub for sub in node.all_of if sub.pointer not in on_path
        ]

        if not forks:
            expand(
                tuple(and_subs) + rest,
                acc + [node],
                crumbs,
                depth + 1,
                on_path | {node.pointer},
            )
            return

        groups = [f[1] for f in forks]
        kinds = [f[0] for f in forks]
        for combo in product(*groups):
            new_crumbs = list(crumbs)
            for kind, siblings, sub in zip(kinds, groups, combo):
                new_crumbs.append(
                    BranchCrumb(
                        combinator=kind,
                        index=siblings.index(sub),
                        schema_path="#" + node.pointer if node.pointer else "#",
                    )
                )
            expand(
                tuple(combo) + tuple(and_subs) + rest,
                acc + [node],
                tuple(new_crumbs),
                depth + 1,
                on_path | {node.pointer},
            )

    expand(tuple(nodes), [], (), 0, frozenset())
    return worlds


# ---------------------------------------------------------------------------
# 合并 flat world → Frame
# ---------------------------------------------------------------------------

def _merge_types(sets: list[frozenset[str] | None]) -> frozenset[str] | None:
    constrained = [s for s in sets if s is not None]
    if not constrained:
        return None
    result: frozenset[str] | None = None
    for s in constrained:
        result = s if result is None else (result & s)
    return result


def merge_frame(nodes: list[Node]) -> Frame:
    types = _merge_types([n.types for n in nodes])
    required = (
        frozenset().union(*(n.required for n in nodes)) if nodes else frozenset()
    )

    props: dict[str, list[Node]] = {}
    for n in nodes:
        for k, sub in n.properties.items():
            props.setdefault(k, []).append(sub)

    additional: Any = None
    extra_nodes: list[Node] = []
    for n in nodes:
        if n.additional is None:
            continue
        if n.additional is False:
            additional = False
            break
        if isinstance(n.additional, Node):
            extra_nodes.append(n.additional)
    if additional is not False and extra_nodes:
        additional = extra_nodes

    prefix_len = max((len(n.prefix) for n in nodes), default=0)
    prefix: list[list[Node]] = []
    for i in range(prefix_len):
        group: list[Node] = []
        for n in nodes:
            if i < len(n.prefix):
                group.append(n.prefix[i])
            elif n.items is not None:
                group.append(n.items)
        prefix.append(group)

    items_groups = [n.items for n in nodes if n.items is not None]

    actions_sets = [n.actions for n in nodes if n.actions is not None]
    actions = (
        ALL_ACTIONS.intersection(*actions_sets) if actions_sets else None
    )

    return Frame(
        nodes=nodes,
        types=types,
        required=required,
        properties=props,
        additional=additional,
        prefix=prefix,
        items=items_groups or None,
        actions=actions,
    )


def _is_object_like(types: frozenset[str] | None) -> bool:
    return types is None or "object" in types


def _is_array_like(types: frozenset[str] | None) -> bool:
    return types is None or "array" in types


# ---------------------------------------------------------------------------
# 敏感实例枚举（BFS，浅路径先出队 => 最短违规优先）
# ---------------------------------------------------------------------------

@dataclass
class _QueueItem:
    abstract: tuple
    depth: int
    crumbs: tuple[BranchCrumb, ...]
    chain: tuple[tuple[Node, ...], ...]


def _child_abstract_segments(frame: Frame) -> list:
    segs = []
    if _is_object_like(frame.types):
        segs.extend(frame.properties.keys())
        # additionalProperties 只以“新鲜键”枚举：任何固定名规则都不应
        # 覆盖它（附加属性键名不受契约约束）
        if frame.additional is not False:
            segs.append(EXTRA_KEY)
    if _is_array_like(frame.types):
        for i, group in enumerate(frame.prefix):
            if group:
                segs.append(i)
        if frame.items is not None:
            segs.append(ITEMS_TAIL)
    return segs


def _child_nodes(frame: Frame, seg) -> list[Node]:
    if seg == EXTRA_KEY:
        if isinstance(frame.additional, list):
            return frame.additional
        return [frame.additional] if isinstance(frame.additional, Node) else []
    if seg == ITEMS_TAIL:
        return frame.items or []
    if isinstance(seg, str):
        return frame.properties.get(seg, [])
    return frame.prefix[seg]


def enumerate_targets(
    schema: Schema, depth_budget: int
) -> Iterator[Target]:
    queue: list[_QueueItem] = [
        _QueueItem((), 0, crumbs, (tuple(world),))
        for world, crumbs in flat_worlds([schema.root], depth_budget)
    ]

    while queue:
        item = queue.pop(0)
        frame = merge_frame(list(item.chain[-1]))
        # 类型交空的世界不可满足：丢弃
        if frame.types is not None and not frame.types:
            continue

        if frame.actions is not None:
            yield Target(
                abstract=item.abstract,
                allowed=frame.actions,
                crumbs=item.crumbs,
                chain=item.chain,
            )
            # 敏感叶子内部不再枚举：策略只能作用于该节点本身
            continue

        if item.depth >= depth_budget:
            continue

        for seg in _child_abstract_segments(frame):
            child_nodes = _child_nodes(frame, seg)
            if not child_nodes:
                continue
            for world, crumbs in flat_worlds(
                child_nodes, depth_budget - item.depth - 1
            ):
                child_frame = merge_frame(world)
                if child_frame.types is not None and not child_frame.types:
                    continue
                queue.append(
                    _QueueItem(
                        item.abstract + (seg,),
                        item.depth + 1,
                        item.crumbs + crumbs,
                        item.chain + (tuple(world),),
                    )
                )


# ---------------------------------------------------------------------------
# ITEMS_TAIL → 具体数组索引候选；EXTRA_KEY → 规则未覆盖的新鲜键
# ---------------------------------------------------------------------------

def _fresh_key_avoiding(used: set[str]) -> str:
    name, i = EXTRA_KEY, 0
    while name in used:
        i += 1
        name = f"{EXTRA_KEY}{i}"
    return name


def _concretize(
    abstract: tuple, parsed_rules: list[tuple[str, tuple]]
) -> list[tuple]:
    """把 ITEMS_TAIL 具体化为索引、EXTRA_KEY 具体化为规则未用的新鲜键。"""
    tail_positions = [i for i, s in enumerate(abstract) if s == ITEMS_TAIL]
    extra_positions = [i for i, s in enumerate(abstract) if s == EXTRA_KEY]

    # 每个尾部位置：枚举规则在该位置使用过的所有具体索引，以及一个
    # “越界”索引（max+1），用于暴露只覆盖固定索引而漏掉后续元素的规则集。
    choices: list[list] = []
    positions: list[int] = []
    for pos in tail_positions:
        used = {
            segs[pos]
            for _rid, segs in parsed_rules
            if pos < len(segs) and isinstance(segs[pos], int)
        }
        cands = sorted(set(range(0, max(used) + 2))) if used else [0]
        choices.append(cands)
        positions.append(pos)
    for pos in extra_positions:
        used = {
            segs[pos]
            for _rid, segs in parsed_rules
            if pos < len(segs) and isinstance(segs[pos], str)
        }
        # 附加属性键不受契约约束：用任何规则都没写过的键，暴露 fixed-name 缺口
        choices.append([_fresh_key_avoiding(set(used))])
        positions.append(pos)

    if not positions:
        return [abstract]

    order = sorted(positions)
    choice_by_pos = dict(zip(positions, choices))
    combos: list[tuple] = []
    for vals in product(*(choice_by_pos[p] for p in order)):
        concrete = list(abstract)
        for pos, v in zip(order, vals):
            concrete[pos] = v
        combos.append(tuple(concrete))
        if len(combos) >= _MAX_INDEX_COMBOS:
            break
    return combos


# ---------------------------------------------------------------------------
# witness 构造：沿目标分支链自上而下合成最小合法文档
# ---------------------------------------------------------------------------

def _prefer_type(frame: Frame) -> str | None:
    if frame.types is None:
        return None
    for t in ("string", "integer", "boolean", "null", "number", "object", "array"):
        if t in frame.types:
            return t
    return None


def _scalar_value(t: str | None) -> Any:
    if t == "string" or t is None:
        return "x"
    if t in ("integer", "number"):
        return 0
    if t == "boolean":
        return True
    if t == "null":
        return None
    if t == "object":
        return {}
    if t == "array":
        return []
    return "x"


def _first_feasible_frame(
    nodes: list[Node], budget: int
) -> Frame | None:
    for world, _crumbs in flat_worlds(nodes, max(budget, 1)):
        f = merge_frame(world)
        if f.types is None or f.types:
            return f
    return None


def _fresh_key(frame: Frame) -> str:
    used = set(frame.properties) | set(frame.required)
    name, i = EXTRA_KEY, 0
    while name in used:
        i += 1
        name = f"{EXTRA_KEY}{i}"
    return name


def _independent_scalar(frame: Frame, budget: int) -> Any:
    """兄弟位置的最小满足值（不在目标路径上）。"""
    t = _prefer_type(frame)
    if t not in ("object", "array"):
        return _scalar_value(t)
    if t == "array":
        return []
    obj: dict[str, Any] = {}
    for k in sorted(frame.required):
        group = frame.properties.get(k)
        if group:
            cf = _first_feasible_frame(group, max(budget - 1, 1))
            if cf is None:
                continue
            obj[k] = _independent_scalar(cf, max(budget - 1, 1))
        elif frame.additional is not False:
            obj[k] = "x"
    return obj


def _frame_for_array_slot(frame: Frame, index: int, budget: int) -> Frame | None:
    """prefixItems 优先，否则回落到 items；无约束返回空 frame。"""
    if index < len(frame.prefix) and frame.prefix[index]:
        return _first_feasible_frame(frame.prefix[index], budget)
    if frame.items is not None:
        return _first_feasible_frame(frame.items, budget)
    return merge_frame([])


def _required_sibling_object(
    frame: Frame, skip: str, budget: int
) -> dict | None:
    """除目标键外的 required 兄弟字段的最小满足值。"""
    obj: dict[str, Any] = {}
    for k in sorted(frame.required):
        if k == skip:
            continue
        group = frame.properties.get(k)
        if group:
            cf = _first_feasible_frame(group, max(budget - 1, 1))
            if cf is None:
                return None
            obj[k] = _independent_scalar(cf, max(budget - 1, 1))
        elif frame.additional is False:
            return None
        else:
            obj[k] = "x"
    return obj


def _type_conflicting_value(types: frozenset[str] | None) -> Any | None:
    if types is None:
        return None
    for bad in ("__other_branch__", 0, True, None, [], {}):
        if not any(_type_matches_contract(t, bad) for t in types):
            return bad
    return None


def _type_matches_contract(t: str, value: Any) -> bool:
    if t == "null":
        return value is None
    if t == "boolean":
        return isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "string":
        return isinstance(value, str)
    if t == "array":
        return isinstance(value, list)
    if t == "object":
        return isinstance(value, dict)
    return False


def _oneof_discriminators(frame: Frame, target_key: str) -> list[dict]:
    """为 frame 上每个 oneOf 合成一个让“非目标分支”校验失败的判别字段。

    目标选中的分支通过其 properties 包含目标键识别；若无法识别则跳过
    （保守不加判别字段，交由顶层实例校验筛选）。
    """
    discs: list[dict] = []
    for n in frame.nodes:
        if not n.one_of:
            continue
        chosen_idx = next(
            (i for i, b in enumerate(n.one_of) if target_key in b.properties),
            None,
        )
        if chosen_idx is None:
            continue
        for i, branch in enumerate(n.one_of):
            if i == chosen_idx:
                continue
            for other_key, sub in branch.properties.items():
                if other_key in n.one_of[chosen_idx].properties:
                    continue
                bad = _type_conflicting_value(sub.types)
                if bad is not None:
                    discs.append({other_key: bad})
                    break
    return discs


def _build_witness_candidates(
    schema: Schema,
    target: Target,
    concrete: tuple,
    budget: int,
) -> Iterator[Any]:
    """沿目标分支链自下而上生成候选（可能多份，供校验筛选）。"""

    def at(depth: int) -> list[Any]:
        frame = merge_frame(list(target.chain[depth]))
        remain = max(budget - depth, 1)

        if depth == len(target.chain) - 1:
            return [_scalar_value(_prefer_type(frame))]

        seg = concrete[depth]
        child_cands = at(depth + 1)

        if isinstance(seg, int):
            if not _is_array_like(frame.types):
                return []
            prefix_vals: list[Any] = []
            for i in range(seg):
                cf = _frame_for_array_slot(frame, i, max(remain - 1, 1))
                if cf is None:
                    return []
                prefix_vals.append(_independent_scalar(cf, max(remain - 1, 1)))
            return [prefix_vals + [cv] for cv in child_cands]

        if not _is_object_like(frame.types):
            return []

        # seg 可能是声明字段，或已具体化的附加属性新鲜键（不在 properties）
        if seg not in frame.properties:
            if frame.additional is False:
                return []
        key = seg

        sibling = _required_sibling_object(frame, key, remain)
        if sibling is None:
            return []

        # 若该层存在 oneOf，尽量合成让“非目标分支”失效的判别字段，
        # 使 witness 恰好满足目标分支；无法判别（兄弟分支无 required 区分）
        # 时退化为仅保证目标分支有效（见 build_witness 的两级筛选）。
        discs = _oneof_discriminators(frame, key)
        out: list[Any] = []
        for cv in child_cands:
            obj = dict(sibling)
            obj[key] = cv
            out.append(obj)
        if discs:
            merged_disc: dict[str, Any] = {}
            for disc in discs:
                merged_disc.update(disc)
            for cv in child_cands:
                obj = dict(sibling)
                obj[key] = cv
                obj.update(merged_disc)
                out.append(obj)
        return out

    yield from at(0)


def _target_branch_schemas(target: Target) -> list[Node]:
    """目标在每个 oneOf/anyOf 节点上选中的分支节点（按 crumbs 顺序）。"""
    chosen: list[Node] = []
    for crumb in target.crumbs:
        # 通过 schema_path 找到组合节点
        parent = None
        for chain_level in target.chain:
            for n in chain_level:
                path = "#" + n.pointer if n.pointer else "#"
                if path == crumb.schema_path:
                    siblings = (
                        n.one_of if crumb.combinator == "oneOf" else n.any_of
                    )
                    if crumb.index < len(siblings):
                        parent = siblings[crumb.index]
        if parent is not None:
            chosen.append(parent)
    return chosen


def build_witness(schema: Schema, target: Target, concrete: tuple) -> Any | None:
    budget = min(_MAX_DEPTH_CAP, max(len(concrete), 3))
    branch_nodes = _target_branch_schemas(target)
    fallback: Any | None = None
    for cand in _build_witness_candidates(schema, target, concrete, budget):
        # 首选：witness 对整个根 schema 有效（oneOf 恰好一支等全部满足）
        if instance_valid_all([schema.root], cand):
            return cand
        # 退化：witness 至少对目标选中的每个分支节点有效
        if fallback is None and branch_nodes and instance_valid_all(
            branch_nodes, cand
        ):
            fallback = cand
    return fallback


# ---------------------------------------------------------------------------
# 覆盖检查（与 engine 的首条命中 / 祖先删除 / 数组索引语义一致）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RuleHit:
    order: int
    id: str
    path: str
    action: str
    segments: tuple


def _path_matches(segs: tuple, concrete: tuple) -> bool:
    if len(segs) != len(concrete):
        return False
    for s, c in zip(segs, concrete):
        if s == "*":
            if not isinstance(c, int):
                return False
        elif s != c:
            return False
    return True


def check_coverage(
    concrete: tuple,
    allowed: frozenset[str],
    rules: list[RuleHit],
) -> Violation | None:
    # 1. 祖先的首条 delete 覆盖整棵后代子树
    for depth in range(len(concrete) - 1, -1, -1):
        prefix = concrete[:depth]
        winner = next((r for r in rules if _path_matches(r.segments, prefix)), None)
        if winner is not None and winner.action == "delete":
            return None

    # 2. 节点自身：首条命中规则生效
    winner = next((r for r in rules if _path_matches(r.segments, concrete)), None)
    if winner is None:
        return Violation(
            kind="uncovered",
            path=pathlang.format_path(concrete),
            allowed_actions=sorted(allowed),
            branch=[],
            witness=None,
            rules=[],
        )

    if winner.action in allowed:
        return None

    later_allowed = next(
        (
            r
            for r in rules
            if r.order > winner.order
            and _path_matches(r.segments, concrete)
            and r.action in allowed
        ),
        None,
    )
    if later_allowed is not None:
        return Violation(
            kind="shadowed",
            path=pathlang.format_path(concrete),
            allowed_actions=sorted(allowed),
            branch=[],
            witness=None,
            rules=[
                {
                    "order": winner.order,
                    "id": winner.id,
                    "path": winner.path,
                    "action": winner.action,
                    "role": "preceding",
                },
                {
                    "order": later_allowed.order,
                    "id": later_allowed.id,
                    "path": later_allowed.path,
                    "action": later_allowed.action,
                    "role": "shadowed",
                },
            ],
        )

    return Violation(
        kind="mismatch",
        path=pathlang.format_path(concrete),
        allowed_actions=sorted(allowed),
        branch=[],
        witness=None,
        rules=[
            {
                "order": winner.order,
                "id": winner.id,
                "path": winner.path,
                "action": winner.action,
                "role": "first_hit",
            }
        ],
    )


def _crumbs_to_branch(crumbs: tuple[BranchCrumb, ...]) -> list[dict]:
    return [
        {
            "combinator": c.combinator,
            "index": c.index,
            "schema_path": c.schema_path,
        }
        for c in crumbs
    ]


# ---------------------------------------------------------------------------
# 顶层入口
# ---------------------------------------------------------------------------

def _min_redaction_depth(schema: Schema) -> int | None:
    """契约图中最近的 x-redaction 节点的结构深度（DFS，循环安全）。

    用于让深度预算覆盖“无规则时仍须发现深层敏感声明”的场景。
    """
    best: list[int | None] = [None]

    def walk(node: Node, depth: int, seen: frozenset[str]) -> None:
        if node is TRUE or node is FALSE:
            return
        if best[0] is not None and depth >= best[0]:
            return
        if node.actions is not None:
            best[0] = depth if best[0] is None else min(best[0], depth)
            return
        nxt_seen = seen | {node.pointer}
        children: list[Node] = []
        children.extend(node.all_of)
        children.extend(node.any_of)
        children.extend(node.one_of)
        children.extend(node.properties.values())
        children.extend(node.prefix)
        if node.items is not None:
            children.append(node.items)
        if isinstance(node.additional, Node):
            children.append(node.additional)
        for child in children:
            if child.pointer in nxt_seen:
                continue
            walk(child, depth + 1, nxt_seen)

    walk(schema.root, 0, frozenset())
    return best[0]


def analyze_publish(
    schema: Schema,
    raw_rules: list[dict],
    max_violations: int = _MAX_VIOLATIONS,
) -> list[Violation]:
    """静态分析待发布规则；返回违规列表（最短路径优先）。不执行转换。"""
    parsed: list[tuple[str, tuple]] = []
    hits: list[RuleHit] = []
    for i, r in enumerate(raw_rules):
        rid = r.get("id", str(i))
        try:
            segs = pathlang.parse_path(r["path"])
        except (KeyError, pathlang.PathSyntaxError, TypeError) as exc:
            raise ComplianceError(str(exc)) from exc
        parsed.append((rid, segs))
        hits.append(
            RuleHit(
                order=i,
                id=rid,
                path=r["path"],
                action=r["action"],
                segments=segs,
            )
        )

    rule_depth = max((len(s) for _rid, s in parsed), default=0)
    # 预算须同时覆盖：最长规则路径、契约中最近敏感声明的深度；硬顶保证
    # 递归 $ref（无限深树）的枚举必然终止。
    contract_depth = _min_redaction_depth(schema)
    lower = max(rule_depth, contract_depth or 0, 3)
    depth_budget = min(_MAX_DEPTH_CAP, lower)

    violations: list[Violation] = []
    seen_keys: set[tuple] = set()

    for target in enumerate_targets(schema, depth_budget):
        for concrete in _concretize(target.abstract, parsed):
            v = check_coverage(concrete, target.allowed, hits)
            if v is None:
                continue
            key = (v.kind, v.path)
            if key in seen_keys:
                continue
            witness = build_witness(schema, target, concrete)
            if witness is None:
                # 无合法 witness 的候选不可达，不做无证据判定
                continue
            v.branch = _crumbs_to_branch(target.crumbs)
            v.witness = witness
            seen_keys.add(key)
            violations.append(v)

    violations.sort(key=lambda v: (len(v.path), v.path, v.kind))
    return violations[:max_violations]


def violation_to_detail(v: Violation) -> dict:
    return {
        "kind": v.kind,
        "path": v.path,
        "allowed_actions": v.allowed_actions,
        "branch": v.branch,
        "witness": v.witness,
        "rules": v.rules,
    }
