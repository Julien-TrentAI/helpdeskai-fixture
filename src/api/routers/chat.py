"""Chat route handler for HelpDeskAI.

POST /v1/chat — accepts a customer message and returns the agent reply.

The tenant_id is taken exclusively from the signature-verified JWT bearer
token (see src.auth.jwt_validator.get_current_tenant); client-supplied
headers are never used for tenant resolution.
"""

from __future__ import annotations

import html
import logging
import uuid

from fastapi import APIRouter, Depends, status

from src.auth.jwt_validator import TokenPayload, get_current_tenant
from src.agent.orchestrator import create_orchestrator

from ..models import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/chat", response_model=ChatResponse, status_code=status.HTTP_200_OK)
async def chat(
    body: ChatRequest,
    tenant: TokenPayload = Depends(get_current_tenant),
) -> ChatResponse:
    """Process a customer chat message and return the agent reply.

    The tenant context comes from the verified JWT claim only.
    """
    tenant_id = tenant.tenant_id
    thread_id = body.thread_id or str(uuid.uuid4())

    orchestrator = create_orchestrator()
    reply = orchestrator.invoke(
        message=body.message,
        tenant_id=tenant_id,
        thread_id=thread_id,
    )
    reply = html.escape(reply)

    return ChatResponse(
        reply=reply,
        thread_id=thread_id,
        tenant_id=tenant_id,
    )
