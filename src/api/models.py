"""Pydantic request and response models for the HelpDeskAI API."""

from __future__ import annotations

import uuid
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    thread_id: Optional[str] = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")

    @field_validator("message")
    @classmethod
    def _message_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must not be blank")
        return value


class ChatResponse(BaseModel):
    reply: str
    thread_id: str
    tenant_id: str


class KBUploadRequest(BaseModel):
    document_key: str = Field(min_length=1, max_length=512)
    # base64 inflates by ~4/3; 10 MB decoded limit is enforced again in the route.
    content_base64: str = Field(min_length=1, max_length=14 * 1024 * 1024)

    @field_validator("document_key")
    @classmethod
    def _safe_document_key(cls, value: str) -> str:
        if value.startswith("/") or "\\" in value or "\x00" in value:
            raise ValueError("document_key must be a relative path without backslashes or null bytes")
        if any(part in ("..", "") for part in value.split("/")):
            raise ValueError("document_key must not contain empty or '..' path segments")
        return value


class KBUploadResponse(BaseModel):
    document_key: str
    tenant_id: str
    uploaded: bool


class TenantInfo(BaseModel):
    tenant_id: str
    name: str
    plan: str
    created_at: str
