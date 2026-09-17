"""合规契约 API。

契约与策略一样包含可变草稿与不可变版本链：
- POST   /v1/contracts                     创建契约（草稿即校验）
- GET    /v1/contracts/{id}                草稿 + 当前版本号
- PUT    /v1/contracts/{id}/draft          修改草稿（草稿 CAS）
- POST   /v1/contracts/{id}/versions       冻结不可变契约版本（版本 CAS）
- GET    /v1/contracts/{id}/versions/{v}   读取不可变历史版本（只读，不改写）

契约版本保存的是冻结的 JSON Schema Draft 2020-12 文档；敏感节点用
x-redaction 声明允许动作。所有 GET 均为只读，历史版本永不被改写。
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models
from ..contracts import ContractSchemaError, compile_contract
from ..database import session
from ..exceptions import ClientError
from ..logging_config import get_logger
from ..schemas import (
    ContractCreate,
    ContractDraftUpdate,
    ContractFreeze,
    ContractOut,
    ContractVersionOut,
)

router = APIRouter(prefix="/v1/contracts", tags=["contracts"])
logger = get_logger("gateway.contracts")


def _compile_or_422(raw_schema: object) -> None:
    try:
        compile_contract(raw_schema)
    except ContractSchemaError as exc:
        raise ClientError(
            "CONTRACT_SCHEMA_INVALID",
            "contract schema is not a supported JSON Schema Draft 2020-12 document",
            status_code=422,
            details={"pointer": exc.pointer, "reason": exc.reason},
        ) from exc


def _to_out(c: models.ComplianceContract) -> ContractOut:
    return ContractOut(
        id=c.id,
        name=c.name,
        draft_schema=c.draft_schema,
        draft_revision=c.draft_revision,
        current_version=c.current_version,
    )


@router.post("", response_model=ContractOut, status_code=201)
async def create_contract(
    body: ContractCreate, db: AsyncSession = Depends(session)
) -> ContractOut:
    raw_schema = body.model_dump(by_alias=True)["schema"]
    _compile_or_422(raw_schema)

    contract = models.ComplianceContract(
        name=body.name, draft_schema=raw_schema, draft_revision=0
    )
    db.add(contract)
    await db.commit()
    await db.refresh(contract)
    logger.info("contract_created", policy_id=str(contract.id), version="draft")
    return _to_out(contract)


@router.get("/{contract_id}", response_model=ContractOut)
async def get_contract(
    contract_id: uuid.UUID, db: AsyncSession = Depends(session)
) -> ContractOut:
    contract = await db.get(models.ComplianceContract, contract_id)
    if contract is None:
        raise ClientError("CONTRACT_NOT_FOUND", "contract not found", status_code=404)
    return _to_out(contract)


@router.put("/{contract_id}/draft", response_model=ContractOut)
async def update_contract_draft(
    contract_id: uuid.UUID,
    body: ContractDraftUpdate,
    db: AsyncSession = Depends(session),
) -> ContractOut:
    raw_schema = body.model_dump(by_alias=True)["schema"]
    _compile_or_422(raw_schema)

    async with db.begin():
        contract = await db.get(
            models.ComplianceContract, contract_id, with_for_update=True
        )
        if contract is None:
            raise ClientError(
                "CONTRACT_NOT_FOUND", "contract not found", status_code=404
            )
        if contract.draft_revision != body.expected_draft_revision:
            raise ClientError(
                "CONTRACT_DRAFT_REVISION_CONFLICT",
                "contract draft was modified concurrently; refetch and retry",
                status_code=409,
            )
        contract.draft_schema = raw_schema
        contract.draft_revision += 1

    fresh = await db.get(models.ComplianceContract, contract_id)
    return _to_out(fresh)


@router.post(
    "/{contract_id}/versions",
    response_model=ContractVersionOut,
    status_code=201,
)
async def freeze_contract(
    contract_id: uuid.UUID,
    body: ContractFreeze,
    db: AsyncSession = Depends(session),
) -> ContractVersionOut:
    async with db.begin():
        contract = await db.get(
            models.ComplianceContract, contract_id, with_for_update=True
        )
        if contract is None:
            raise ClientError(
                "CONTRACT_NOT_FOUND", "contract not found", status_code=404
            )
        if contract.current_version != body.expected_version:
            raise ClientError(
                "CONTRACT_VERSION_CONFLICT",
                "contract was frozen concurrently; refetch current version",
                status_code=409,
            )

        # 冻结前重新编译草稿（兜底直接写入 JSONB 的非法结构）；
        # 编译器只用于校验，不改变文档，分析过程不写任何数据。
        try:
            compile_contract(contract.draft_schema)
        except ContractSchemaError as exc:
            raise ClientError(
                "CONTRACT_SCHEMA_INVALID",
                "contract draft is not a supported JSON Schema Draft 2020-12 document",
                status_code=422,
                details={"pointer": exc.pointer, "reason": exc.reason},
            ) from exc

        # 在事务内捕获快照，避免提交后访问 expired 属性
        frozen_schema = contract.draft_schema
        new_version = contract.current_version + 1
        db.add(
            models.ContractVersion(
                contract_id=contract.id,
                version=new_version,
                schema_=frozen_schema,
            )
        )
        contract.current_version = new_version

    logger.info(
        "contract_frozen",
        policy_id=str(contract_id),
        version=f"{contract_id}@{new_version}",
    )
    return ContractVersionOut(
        contract_id=contract_id,
        version=new_version,
        schema=frozen_schema,
    )


@router.get("/{contract_id}/versions/{version}", response_model=ContractVersionOut)
async def get_contract_version(
    contract_id: uuid.UUID,
    version: int,
    db: AsyncSession = Depends(session),
) -> ContractVersionOut:
    row = await db.get(
        models.ContractVersion,
        {"contract_id": contract_id, "version": version},
    )
    if row is None:
        raise ClientError(
            "CONTRACT_VERSION_NOT_FOUND", "contract version not found", status_code=404
        )
    # 纯只读：直接返回冻结内容，不更新任何历史版本
    return ContractVersionOut(
        contract_id=row.contract_id, version=row.version, schema=row.schema_
    )
