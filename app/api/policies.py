from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models
from ..database import session
from ..exceptions import ClientError
from ..logging_config import get_logger
from ..schemas import (
    PolicyCreate,
    PolicyDraftUpdate,
    PolicyOut,
    PolicyPublish,
    PolicyVersionOut,
    normalize_rules,
)

router = APIRouter(prefix="/v1/policies", tags=["policies"])
logger = get_logger("gateway.policies")


def _to_out(p: models.Policy) -> PolicyOut:
    return PolicyOut(
        id=p.id,
        name=p.name,
        draft_rules=p.draft_rules,
        draft_revision=p.draft_revision,
        current_revision=p.current_revision,
    )


@router.post("", response_model=PolicyOut, status_code=201)
async def create_policy(
    body: PolicyCreate, db: AsyncSession = Depends(session)
) -> PolicyOut:
    try:
        rules = normalize_rules(body.rules)
    except ValueError as exc:
        raise ClientError("INVALID_RULES", str(exc), status_code=400) from exc

    policy = models.Policy(name=body.name, draft_rules=rules, draft_revision=0)
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    logger.info("policy_created", policy_id=str(policy.id), version="draft")
    return _to_out(policy)


@router.get("/{policy_id}", response_model=PolicyOut)
async def get_policy(
    policy_id: uuid.UUID, db: AsyncSession = Depends(session)
) -> PolicyOut:
    policy = await db.get(models.Policy, policy_id)
    if policy is None:
        raise ClientError("POLICY_NOT_FOUND", "policy not found", status_code=404)
    return _to_out(policy)


@router.put("/{policy_id}/draft", response_model=PolicyOut)
async def update_draft(
    policy_id: uuid.UUID,
    body: PolicyDraftUpdate,
    db: AsyncSession = Depends(session),
) -> PolicyOut:
    try:
        rules = normalize_rules(body.rules)
    except ValueError as exc:
        raise ClientError("INVALID_RULES", str(exc), status_code=400) from exc

    async with db.begin():
        policy = await db.get(models.Policy, policy_id, with_for_update=True)
        if policy is None:
            raise ClientError(
                "POLICY_NOT_FOUND", "policy not found", status_code=404
            )
        if policy.draft_revision != body.expected_draft_revision:
            raise ClientError(
                "DRAFT_REVISION_CONFLICT",
                "draft was modified concurrently; refetch and retry",
                status_code=409,
            )
        policy.draft_rules = rules
        policy.draft_revision += 1

    logger.info(
        "draft_updated",
        policy_id=str(policy_id),
        version=f"draft#{body.expected_draft_revision + 1}",
    )
    # 提交后重新读取，避免访问 expired 属性
    fresh = await db.get(models.Policy, policy_id)
    return _to_out(fresh)


@router.post(
    "/{policy_id}/publish", response_model=PolicyVersionOut, status_code=201
)
async def publish(
    policy_id: uuid.UUID,
    body: PolicyPublish,
    db: AsyncSession = Depends(session),
) -> PolicyVersionOut:
    async with db.begin():
        policy = await db.get(models.Policy, policy_id, with_for_update=True)
        if policy is None:
            raise ClientError(
                "POLICY_NOT_FOUND", "policy not found", status_code=404
            )
        if policy.current_revision != body.expected_revision:
            raise ClientError(
                "REVISION_CONFLICT",
                "policy was published concurrently; refetch current revision",
                status_code=409,
            )
        # 发布前再次保证草稿规则合法（JSONB 直接写入的兜底）
        try:
            frozen_rules = normalize_rules(policy.draft_rules)
        except ValueError as exc:
            raise ClientError(
                "INVALID_RULES", str(exc), status_code=400
            ) from exc

        new_revision = policy.current_revision + 1
        db.add(
            models.PolicyVersion(
                policy_id=policy.id,
                revision=new_revision,
                rules=frozen_rules,
            )
        )
        policy.current_revision = new_revision

    logger.info(
        "policy_published",
        policy_id=str(policy_id),
        version=f"{policy_id}@{new_revision}",
    )
    return PolicyVersionOut(
        policy_id=policy_id, revision=new_revision, rules=frozen_rules
    )


@router.get("/{policy_id}/versions/{revision}", response_model=PolicyVersionOut)
async def get_version(
    policy_id: uuid.UUID,
    revision: int,
    db: AsyncSession = Depends(session),
) -> PolicyVersionOut:
    version = await db.get(
        models.PolicyVersion,
        {"policy_id": policy_id, "revision": revision},
    )
    if version is None:
        raise ClientError("VERSION_NOT_FOUND", "version not found", status_code=404)
    return PolicyVersionOut(
        policy_id=version.policy_id,
        revision=version.revision,
        rules=version.rules,
    )
