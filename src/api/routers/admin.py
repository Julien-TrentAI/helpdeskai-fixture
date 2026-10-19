"""Admin route handlers for HelpDeskAI.

Every route on this router requires a verified JWT carrying the admin role.
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, status

import boto3

from src.auth.jwt_validator import TokenPayload, get_current_tenant

from ..models import TenantInfo

logger = logging.getLogger(__name__)



async def require_admin(
    tenant: TokenPayload = Depends(get_current_tenant),
) -> TokenPayload:
    """FastAPI dependency: allow only callers whose verified JWT role is admin."""
    if tenant.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )
    return tenant


router = APIRouter(dependencies=[Depends(require_admin)])

_AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
_TENANT_TABLE = "helpdeskAI-tenant-config"


@router.get(
    "/admin/tenants",
    response_model=list[TenantInfo],
    status_code=status.HTTP_200_OK,
)
async def list_all_tenants() -> list[TenantInfo]:
    """List all tenants registered in the system (admin role required)."""
    dynamodb = boto3.resource("dynamodb", region_name=_AWS_REGION)
    table = dynamodb.Table(_TENANT_TABLE)

    # Scan the entire tenant config table — returns all tenants.
    response = table.scan(
        ProjectionExpression="tenant_id, #n, plan, created_at",
        ExpressionAttributeNames={"#n": "name"},
    )
    items = response.get("Items", [])

    while "LastEvaluatedKey" in response:
        response = table.scan(
            ProjectionExpression="tenant_id, #n, plan, created_at",
            ExpressionAttributeNames={"#n": "name"},
            ExclusiveStartKey=response["LastEvaluatedKey"],
        )
        items.extend(response.get("Items", []))

    return [
        TenantInfo(
            tenant_id=item.get("tenant_id", ""),
            name=item.get("name", ""),
            plan=item.get("plan", "free"),
            created_at=str(item.get("created_at", "")),
        )
        for item in items
    ]
