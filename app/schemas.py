from __future__ import annotations

import re
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import pathlang

_RULE_ID_RE = re.compile(r"[A-Za-z0-9_\-.:]{1,64}")
_NAME_RE = re.compile(r"[A-Za-z0-9_\-.:]{1,128}")


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64)
    path: str = Field(min_length=1, max_length=1024)
    action: Literal["delete", "mask", "tokenize"]
    keep_prefix: int = Field(default=0, ge=0, le=4096)
    keep_suffix: int = Field(default=0, ge=0, le=4096)

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _RULE_ID_RE.fullmatch(v):
            raise ValueError("rule id allows [A-Za-z0-9_-.:] up to 64 chars")
        return v

    @field_validator("path")
    @classmethod
    def _check_path(cls, v: str) -> str:
        # 语法检查：只允许 $ / .name / [n] / [*]
        pathlang.parse_path(v)
        return v


def normalize_rules(rules: list[RuleIn | dict]) -> list[dict]:
    """把入参规则归一化为存储形式，并做跨字段校验。"""
    norm: list[dict] = []
    seen_ids: set[str] = set()
    for r in rules:
        d = r.model_dump() if isinstance(r, RuleIn) else RuleIn(**r).model_dump()
        if d["id"] in seen_ids:
            raise ValueError(f"duplicate rule id: {d['id']}")
        seen_ids.add(d["id"])
        if d["action"] != "mask" and (d["keep_prefix"] or d["keep_suffix"]):
            # 非遮盖动作不允许携带保留长度，保持语义清晰
            d["keep_prefix"] = 0
            d["keep_suffix"] = 0
        norm.append(d)
    return norm


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    rules: list[RuleIn] = Field(default_factory=list)
    # 可选：绑定不可变契约版本，绑定后发布须经门禁静态分析
    contract_id: uuid.UUID | None = None
    contract_revision: int | None = Field(default=None, ge=1)

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not _NAME_RE.fullmatch(v):
            raise ValueError("name allows [A-Za-z0-9_\\-.:] up to 128 chars")
        return v

    @model_validator(mode="after")
    def _check_contract_pair(self):
        if (self.contract_id is None) != (self.contract_revision is None):
            raise ValueError("contract_id and contract_revision must be set together")
        return self


class PolicyDraftUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # 乐观锁：必须等于当前 draft_revision
    expected_draft_revision: int = Field(ge=0)
    rules: list[RuleIn]
    # 可选：同时变更契约绑定（两个字段必须同时提供；不提供则保持原绑定）
    contract_id: uuid.UUID | None = None
    contract_revision: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check_contract_pair(self):
        if (self.contract_id is None) != (self.contract_revision is None):
            raise ValueError("contract_id and contract_revision must be set together")
        return self


class PolicyPublish(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # 发布 CAS：必须等于当前已发布 revision（首次发布为 0）
    expected_revision: int = Field(ge=0)


class PolicyOut(BaseModel):
    id: uuid.UUID
    name: str
    draft_rules: list[dict]
    draft_revision: int
    current_revision: int
    contract_id: uuid.UUID | None = None
    contract_revision: int | None = None


class PolicyVersionOut(BaseModel):
    policy_id: uuid.UUID
    revision: int
    rules: list[dict]


class ContractCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(min_length=1, max_length=128)
    # JSON 字段名为 "schema"（pydantic 保留名，故用别名）
    schema_doc: dict | bool = Field(alias="schema")

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        if not _NAME_RE.fullmatch(v):
            raise ValueError("name allows [A-Za-z0-9_\\-.:] up to 128 chars")
        return v


class ContractVersionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # 追加版本 CAS：必须等于当前契约版本号
    expected_revision: int = Field(ge=0)
    schema_doc: dict | bool = Field(alias="schema")


class ContractOut(BaseModel):
    id: uuid.UUID
    name: str
    current_revision: int


class ContractVersionOut(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    contract_id: uuid.UUID
    revision: int
    schema_doc: dict | bool = Field(alias="schema", serialization_alias="schema")


class TransformRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)
    document: Any
    # 必携带策略版本；只能使用已存在的不可变发布版本
    revision: int = Field(ge=1)


class RuleTraceHit(BaseModel):
    path: str
    status: Literal["applied", "skipped", "duplicate"]
    rule_id: str | None = None


class RuleTrace(BaseModel):
    rule_id: str
    path: str
    action: Literal["delete", "mask", "tokenize"]
    matched: int
    applied: int
    skipped: int
    hits: list[RuleTraceHit]


class TransformResponse(BaseModel):
    result: Any
    trace: list[RuleTrace]
    version: dict
