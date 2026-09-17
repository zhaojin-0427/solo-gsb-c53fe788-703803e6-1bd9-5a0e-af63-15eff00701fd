"""规则执行引擎。

执行顺序（严格遵守需求）：
1. 在**原始文档**上计算全部规则命中（通配在当前数组长度上展开）。
2. 同一具体节点按规则声明顺序只保留首条命中。
3. 标记因祖先删除而失效的后代命中为 skipped。
4. 先应用遮盖/令牌化，再删除；数组删除按索引**降序**执行。
轨迹只含规则 id、路径、动作、命中节点位置与命中/跳过数量，绝不包含任何值。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import pathlang
from .jcs import canonicalize
from .pathlang import Hit
from .security import mask_value, tokenize_value

_MISSING = object()


@dataclass(frozen=True)
class RuleSpec:
    id: str
    path: str
    action: str  # delete | mask | tokenize
    keep_prefix: int = 0
    keep_suffix: int = 0


@dataclass
class _Win:
    rule_id: str
    action: str
    hit: Hit
    status: str = "applied"  # applied | skipped
    keep_prefix: int = 0
    keep_suffix: int = 0


@dataclass
class _HitRecord:
    prefix: tuple
    status: str  # applied | skipped | duplicate
    winner_rule_id: str | None = None


@dataclass
class _RuleTrace:
    rule: RuleSpec
    hits: list[_HitRecord] = field(default_factory=list)


def _is_prefix(ancestor: tuple, descendant: tuple) -> bool:
    return len(ancestor) < len(descendant) and descendant[: len(ancestor)] == ancestor


def apply_document(document: Any, rules: list[RuleSpec]) -> dict:
    rule_traces: list[_RuleTrace] = []

    # 1. 原始文档上计算全部命中
    parsed: list[tuple[RuleSpec, list[Hit]]] = []
    for rule in rules:
        segments = pathlang.parse_path(rule.path)
        hits = pathlang.match(document, segments)
        parsed.append((rule, hits))

    # 2. 同一节点按声明顺序只取首条
    winners_by_prefix: dict[tuple, _Win] = {}
    for rule, hits in parsed:
        trace = _RuleTrace(rule=rule)
        for hit in hits:
            existing = winners_by_prefix.get(hit.prefix)
            if existing is not None:
                trace.hits.append(
                    _HitRecord(
                        prefix=hit.prefix,
                        status="duplicate",
                        winner_rule_id=existing.rule_id,
                    )
                )
                continue
            win = _Win(
                rule_id=rule.id,
                action=rule.action,
                hit=hit,
                keep_prefix=rule.keep_prefix,
                keep_suffix=rule.keep_suffix,
            )
            winners_by_prefix[hit.prefix] = win
            trace.hits.append(_HitRecord(prefix=hit.prefix, status="applied"))
        rule_traces.append(trace)

    winners = list(winners_by_prefix.values())

    # 3. 祖先删除后，后代命中标为 skipped
    delete_prefixes = sorted(
        (w.hit.prefix for w in winners if w.action == "delete"),
        key=len,
    )
    for w in winners:
        for ap in delete_prefixes:
            if ap != w.hit.prefix and _is_prefix(ap, w.hit.prefix):
                w.status = "skipped"
                break

    # 4a. 先执行遮盖 / 令牌化（在原始引用上原地改写）
    root_deleted = False
    for w in winners:
        if w.status == "skipped" or w.action == "delete":
            continue
        if not w.hit.prefix:
            if w.action == "mask":
                document = mask_value(
                    w.hit.node, keep_prefix=w.keep_prefix, keep_suffix=w.keep_suffix
                )
            else:
                document = tokenize_value(w.hit.node, canonicalize(w.hit.node))
            continue
        parent, term = w.hit.parent, w.hit.term
        if isinstance(parent, dict):
            current = parent.get(term, _MISSING)
            if current is _MISSING:
                w.status = "skipped"
                continue
            parent[term] = (
                mask_value(
                    current, keep_prefix=w.keep_prefix, keep_suffix=w.keep_suffix
                )
                if w.action == "mask"
                else tokenize_value(current, canonicalize(current))
            )
        elif isinstance(parent, list):
            if term >= len(parent):
                w.status = "skipped"
                continue
            current = parent[term]
            parent[term] = (
                mask_value(
                    current, keep_prefix=w.keep_prefix, keep_suffix=w.keep_suffix
                )
                if w.action == "mask"
                else tokenize_value(current, canonicalize(current))
            )

    # 4b. 删除：根删除直接置空；其余按父容器分组，数组索引降序
    root_delete_winner = next(
        (w for w in winners if w.action == "delete" and not w.hit.prefix), None
    )
    if root_delete_winner is not None:
        root_deleted = True
        document = None
    else:
        groups: dict[int, list[_Win]] = {}
        for w in winners:
            if w.status != "skipped" and w.action == "delete" and w.hit.prefix:
                groups.setdefault(id(w.hit.parent), []).append(w)
        for group in groups.values():
            parent = group[0].hit.parent
            if isinstance(parent, dict):
                for w in group:
                    if w.hit.term in parent:
                        del parent[w.hit.term]
                    else:
                        w.status = "skipped"
            else:
                for w in sorted(group, key=lambda x: x.hit.term, reverse=True):
                    idx = w.hit.term
                    if idx < len(parent):
                        del parent[idx]
                    else:
                        w.status = "skipped"

    # 汇总轨迹（按声明顺序，不含任何值）
    traces_out: list[dict] = []
    for trace in rule_traces:
        hit_out = []
        applied = skipped = 0
        for h in trace.hits:
            if h.status == "duplicate":
                hit_out.append(
                    {
                        "path": pathlang.format_path(h.prefix),
                        "status": "duplicate",
                        "rule_id": h.winner_rule_id,
                    }
                )
                continue
            win = winners_by_prefix[h.prefix]
            status = "skipped" if root_deleted and h.prefix else win.status
            if status == "skipped":
                skipped += 1
            else:
                applied += 1
            hit_out.append({"path": pathlang.format_path(h.prefix), "status": status})
        traces_out.append(
            {
                "rule_id": trace.rule.id,
                "path": trace.rule.path,
                "action": trace.rule.action,
                "matched": len(trace.hits),
                "applied": applied,
                "skipped": skipped,
                "hits": hit_out,
            }
        )

    return {"document": document, "trace": traces_out}
