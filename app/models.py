"""ORM 模型。

policy              策略主体，保存可变草稿（draft_rules / draft_revision）
policy_version      不可变发布版本（revision CAS）；携带发布时门禁绑定的
                    不可变契约版本（仅记录，门禁只在发布事务内做静态分析）
compliance_contract       合规契约主体：可变草稿 schema + 不可变版本链
contract_version          不可变契约版本（保存冻结的 JSON Schema 文本）
idempotency_record 版本内幂等键：只存输入摘要与最终响应，不存任何原始值
audit_event         审计：仅安全字段
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Policy(Base):
    __tablename__ = "policy"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    draft_rules: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # 草稿修订计数，每次写草稿 +1，作为乐观并发的期望值
    draft_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # 当前已发布 revision；从未发布时为 0
    current_revision: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class PolicyVersion(Base):
    __tablename__ = "policy_version"
    __table_args__ = (
        UniqueConstraint("policy_id", "revision"),
        ForeignKeyConstraint(
            ["contract_id", "contract_version"],
            ["contract_version.contract_id", "contract_version.version"],
            ondelete="RESTRICT",
        ),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policy.id", ondelete="CASCADE"),
        primary_key=True,
    )
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    rules: Mapped[list] = mapped_column(JSONB, nullable=False)
    # 发布门禁绑定的不可变契约版本；未启用契约门禁时为 NULL
    contract_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    contract_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ComplianceContract(Base):
    __tablename__ = "compliance_contract"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # 可变草稿 schema（受限于 JSON Schema Draft 2020-12 子集）
    draft_schema: Mapped[dict] = mapped_column(JSONB, nullable=False)
    draft_revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # 当前已冻结契约版本；从未冻结时为 0
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class ContractVersion(Base):
    __tablename__ = "contract_version"
    __table_args__ = (UniqueConstraint("contract_id", "version"),)

    contract_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("compliance_contract.id", ondelete="CASCADE"),
        primary_key=True,
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    # 冻结的契约 JSON（不可变；查询接口只读取，永不改写）
    schema_: Mapped[dict] = mapped_column("schema", JSONB, nullable=False)
    published_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_record"
    __table_args__ = (
        UniqueConstraint("policy_id", "revision", "key", name="uq_idem_version_key"),
        Index("ix_idem_status", "status"),
        ForeignKeyConstraint(
            ["policy_id", "revision"],
            ["policy_version.policy_id", "policy_version.revision"],
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    # pending：占位（事务未提交则随回滚消失）；completed：已有最终响应
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    response: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = (
        Index("ix_audit_policy_version", "policy_id", "revision"),
        ForeignKeyConstraint(
            ["policy_id", "revision"],
            ["policy_version.policy_id", "policy_version.revision"],
            ondelete="CASCADE",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    revision: Mapped[int] = mapped_column(Integer, nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    # 仅记录错误码；成功为 NULL。绝不记录原始/脱敏值
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
