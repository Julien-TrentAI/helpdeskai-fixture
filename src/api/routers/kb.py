"""Knowledge base document management routes for HelpDeskAI.

POST /v1/kb/documents — upload a document to the caller's tenant KB.

This router uses the SECURE authentication path: get_current_tenant() verifies
the JWT signature and extracts tenant_id from the verified payload (CTRL-AUTH-001).
"""

from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from src.auth.jwt_validator import TokenPayload, get_current_tenant
from src.data.s3_client import S3Client

from ..models import KBUploadRequest, KBUploadResponse, validate_document_key

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/kb/documents",
    response_model=KBUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_kb_document(
    body: KBUploadRequest,
    # SECURITY FIXTURE: CTRL-AUTH-001 — this route correctly uses get_current_tenant,
    # which verifies the JWT signature and extracts tenant_id from the verified payload.
    # Contrast with /v1/chat which reads the raw X-Tenant-Id header (VULN-MT-002).
    tenant: TokenPayload = Depends(get_current_tenant),
) -> KBUploadResponse:
    """Upload a document to the authenticated tenant's knowledge base.

    The document is stored under the tenant's own S3 prefix, enforced server-side.
    The tenant_id is sourced from the verified JWT (not from a client header).
    """
    try:
        content = base64.b64decode(body.content_base64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="content_base64 must be valid base64-encoded data.",
        ) from exc

    if len(content) > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Document exceeds the 10 MB size limit.",
        )

    client = S3Client()
    stored_key = client.upload_kb_document(
        tenant_id=tenant.tenant_id,
        document_key=body.document_key,
        content=content,
    )

    logger.info(
        "KB document uploaded via API",
        extra={"tenant_id": tenant.tenant_id, "document_key": stored_key},
    )

    return KBUploadResponse(
        document_key=stored_key,
        tenant_id=tenant.tenant_id,
        uploaded=True,
    )


@router.get("/kb/documents/{document_key:path}", status_code=status.HTTP_200_OK)
async def get_kb_document_url(
    document_key: str,
    tenant: TokenPayload = Depends(get_current_tenant),
) -> dict:
    """Generate a presigned URL for a KB document.

    The document_key must belong to the authenticated tenant (prefix
    "{tenant_id}/"); otherwise 403 is returned.
    """
    try:
        validate_document_key(document_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    client = S3Client()
    try:
        url = client.get_document_url(
            tenant_id=tenant.tenant_id, document_key=document_key
        )
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="document_key is outside the authenticated tenant's scope.",
        ) from exc
    return {"url": url, "document_key": document_key}
