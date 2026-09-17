"""合规契约 API。

契约是受限 JSON Schema（Draft 2020-12）文档，以**不可变版本**保存：
- 创建契约即生成 revision 1；之后只能以 CAS 方式追加新版本；
- 不提供任何修改/删除接口，查询永不改写历史版本。
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models
from ..contractschema import SchemaError, validate_contract_schema
from ..database import session
from ..exceptions import ClientError
from ..logging_config import get_logger
from ..schemas import (
    ContractCreate,
    ContractOut,
    ContractVersionCreate,
    ContractVersionOut,
)

router = APIRouter(prefix="/v1/contracts", tags=["contracts"])
logger = get_logger("gateway.contracts")


def _validate_schema(schema_doc) -> None:
    try:
        validate_contract_schema(schema_doc)
    except SchemaError as exc:
        raise ClientError(
            "CONTRACT_SCHEMA_INVALID", str(exc), status_code=422
        ) from exc


@router.post("", response_model=ContractOut, status_code=201)
async def create_contract(
    body: ContractCreate, db: AsyncSession = Depends(session)
) -> ContractOut:
    _validate_schema(body.schema_doc)
    async with db.begin():
        contract = models.Contract(name=body.name, current_revision=1)
        db.add(contract)
        await db.flush()
        db.add(
            models.ContractVersion(
                contract_id=contract.id,
                revision=1,
                schema_doc=body.schema_doc,
            )
        )
    logger.info(
        "contract_created",
        contract_id=str(contract.id),
        version=f"{contract.id}@1",
    )
    return ContractOut(
        id=contract.id, name=contract.name, current_revision=1
    )


@router.get("/{contract_id}", response_model=ContractOut)
async def get_contract(
    contract_id: uuid.UUID, db: AsyncSession = Depends(session)
) -> ContractOut:
    contract = await db.get(models.Contract, contract_id)
    if contract is None:
        raise ClientError("CONTRACT_NOT_FOUND", "contract not found", status_code=404)
    return ContractOut(
        id=contract.id,
        name=contract.name,
        current_revision=contract.current_revision,
    )


@router.post(
    "/{contract_id}/versions", response_model=ContractVersionOut, status_code=201
)
async def create_contract_version(
    contract_id: uuid.UUID,
    body: ContractVersionCreate,
    db: AsyncSession = Depends(session),
) -> ContractVersionOut:
    _validate_schema(body.schema_doc)
    async with db.begin():
        contract = await db.get(models.Contract, contract_id, with_for_update=True)
        if contract is None:
            raise ClientError(
                "CONTRACT_NOT_FOUND", "contract not found", status_code=404
            )
        if contract.current_revision != body.expected_revision:
            raise ClientError(
                "REVISION_CONFLICT",
                "contract was versioned concurrently; refetch current revision",
                status_code=409,
            )
        new_revision = contract.current_revision + 1
        db.add(
            models.ContractVersion(
                contract_id=contract.id,
                revision=new_revision,
                schema_doc=body.schema_doc,
            )
        )
        contract.current_revision = new_revision
    logger.info(
        "contract_version_created",
        contract_id=str(contract_id),
        version=f"{contract_id}@{new_revision}",
    )
    return ContractVersionOut(
        contract_id=contract_id,
        revision=new_revision,
        schema=body.schema_doc,
    )


@router.get("/{contract_id}/versions/{revision}", response_model=ContractVersionOut)
async def get_contract_version(
    contract_id: uuid.UUID,
    revision: int,
    db: AsyncSession = Depends(session),
) -> ContractVersionOut:
    # 只读查询：历史版本永不改写
    version = await db.get(
        models.ContractVersion,
        {"contract_id": contract_id, "revision": revision},
    )
    if version is None:
        raise ClientError(
            "CONTRACT_VERSION_NOT_FOUND",
            "contract version not found",
            status_code=404,
        )
    return ContractVersionOut(
        contract_id=version.contract_id,
        revision=version.revision,
        schema=version.schema_doc,
    )
