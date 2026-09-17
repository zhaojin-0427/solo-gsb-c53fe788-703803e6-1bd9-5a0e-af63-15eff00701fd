"""脱敏转换 API。

幂等语义（键仅在同一 policy_id + revision 内有效）：
- 首次：插入 pending 占位（唯一约束防并发双执行），执行转换，写入最终响应，
  与审计事件在**同一事务**提交。
- 同键同摘要并发：仅一个请求执行；其余在 FOR UPDATE 行锁上等待，持有者提交后
  回放已存响应，不新增审计。
- 同键异摘要：无论对方是否完成，立即 409 IDEMPOTENCY_DIGEST_CONFLICT。
- 占位事务在提交前任一环节失败 => 随事务回滚，同键可立即重试。
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import models
from ..database import session
from ..engine import RuleSpec, apply_document
from ..exceptions import ClientError
from ..jcs import digest
from ..logging_config import get_logger
from ..schemas import TransformRequest, TransformResponse

router = APIRouter(prefix="/v1", tags=["transform"])
logger = get_logger("gateway.transform")


def _rules_from_version(version: models.PolicyVersion) -> list[RuleSpec]:
    return [
        RuleSpec(
            id=r["id"],
            path=r["path"],
            action=r["action"],
            keep_prefix=r.get("keep_prefix", 0),
            keep_suffix=r.get("keep_suffix", 0),
        )
        for r in version.rules
    ]


async def _insert_placeholder(
    db: AsyncSession,
    policy_id: uuid.UUID,
    revision: int,
    key: str,
    request_id: uuid.UUID,
    input_digest: str,
) -> models.IdempotencyRecord | None:
    """尝试抢占幂等占位。成功返回记录；键冲突返回 None。"""
    record = models.IdempotencyRecord(
        policy_id=policy_id,
        revision=revision,
        key=key,
        request_id=request_id,
        input_digest=input_digest,
        status="pending",
    )
    try:
        # savepoint 吸收唯一冲突，外层事务与会话保持可用
        async with db.begin_nested():
            db.add(record)
        await db.flush()
        return record
    except Exception:
        return None


@router.post(
    "/policies/{policy_id}/transform",
    response_model=TransformResponse,
    status_code=200,
)
async def transform(
    policy_id: uuid.UUID,
    body: TransformRequest,
    request: Request,
    db: AsyncSession = Depends(session),
) -> TransformResponse:
    request_id = uuid.UUID(request.state.request_id)
    input_digest, _ = digest(body.document)

    async with db.begin():
        # 1. 解析目标发布版本（必须显式携带且存在、不可变）
        policy = await db.get(models.Policy, policy_id)
        if policy is None:
            raise ClientError("POLICY_NOT_FOUND", "policy not found", status_code=404)

        revision = body.revision
        if revision > policy.current_revision:
            raise ClientError(
                "VERSION_NOT_FOUND", "version not found", status_code=404
            )

        version = await db.get(
            models.PolicyVersion,
            {"policy_id": policy_id, "revision": revision},
        )
        version_label = f"{policy_id}@{revision}"

        # 2. 幂等：尝试抢占 pending 占位
        record = await _insert_placeholder(
            db, policy_id, revision, body.idempotency_key, request_id, input_digest
        )

        if record is None:
            # 3. 键已存在：FOR UPDATE 阻塞至持有者事务结束
            stmt = (
                select(models.IdempotencyRecord)
                .where(
                    models.IdempotencyRecord.policy_id == policy_id,
                    models.IdempotencyRecord.revision == revision,
                    models.IdempotencyRecord.key == body.idempotency_key,
                )
                .with_for_update()
            )
            existing = (await db.execute(stmt)).scalar_one_or_none()

            if existing is not None and existing.input_digest != input_digest:
                logger.warning(
                    "request_failed",
                    error_code="IDEMPOTENCY_DIGEST_CONFLICT",
                    http_status=409,
                    policy_id=str(policy_id),
                    version=version_label,
                    input_digest=input_digest,
                )
                raise ClientError(
                    "IDEMPOTENCY_DIGEST_CONFLICT",
                    "idempotency key was already used with a different input",
                    status_code=409,
                )

            if existing is not None and existing.status == "completed":
                logger.info(
                    "transform_replayed",
                    policy_id=str(policy_id),
                    version=version_label,
                    input_digest=input_digest,
                    idempotency_replay=True,
                )
                # 回放：直接返回首次保存的最终响应，不写审计
                return TransformResponse.model_validate(existing.response)

            # existing is None：持有者事务已回滚，占位消失 => 本请求接管执行；
            # existing 仍为 pending 仅在锁未真正阻塞的极端情形出现，重试抢占。
            record = await _insert_placeholder(
                db,
                policy_id,
                revision,
                body.idempotency_key,
                request_id,
                input_digest,
            )
            if record is None:
                raise ClientError(
                    "IDEMPOTENCY_CONTENTION",
                    "idempotency key is contended; retry the request",
                    status_code=409,
                )

        # 4. 持有者：在不可变发布版本规则上执行脱敏
        result = apply_document(body.document, _rules_from_version(version))
        payload = TransformResponse(
            result=result["document"],
            trace=result["trace"],
            version={"policy_id": str(policy_id), "revision": revision},
        )

        # 5. 结果落盘 + 审计，同一事务提交（任一失败整体回滚，允许同键重试）
        record.status = "completed"
        record.response = payload.model_dump(mode="json")
        record.completed_at = func.now()
        db.add(
            models.AuditEvent(
                request_id=request_id,
                policy_id=policy_id,
                revision=revision,
                input_digest=input_digest,
                error_code=None,
            )
        )

    logger.info(
        "transform_completed",
        policy_id=str(policy_id),
        version=version_label,
        input_digest=input_digest,
        idempotency_replay=False,
    )
    return payload
