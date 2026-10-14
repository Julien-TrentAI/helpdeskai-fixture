"""Pydantic request and response models for the HelpDeskAI API."""

from __future__ import annotations

import uuid
from typing import Optional

from pydantic import BaseModel, Field, field_validator


MAX_MESSAGE_LENGTH = 4000
MAX_DOCUMENT_KEY_LENGTH = 512
# ~10 MB of raw bytes encodes to ~13.4 MB of base64.
MAX_CONTENT_BASE64_LENGTH = 14 * 1024 * 1024


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    thread_id: Optional[str] = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"
    )

    @field_validator("message")
    @classmethod
    def _message_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must not be blank")
        return v


class ChatResponse(BaseModel):
    reply: str
    thread_id: str
    tenant_id: str


class KBUploadRequest(BaseModel):
    document_key: str = Field(min_length=1, max_length=MAX_DOCUMENT_KEY_LENGTH)
    content_base64: str = Field(min_length=1, max_length=MAX_CONTENT_BASE64_LENGTH)

    @field_validator("document_key")
    @classmethod
    def _safe_document_key(cls, v: str) -> str:
        if v.startswith("/") or "\\" in v or "\x00" in v:
            raise ValueError("document_key must be a relative path without backslashes")
        if any(part in ("", ".", "..") for part in v.split("/")):
            raise ValueError("document_key must not contain empty, '.' or '..' segments")
        return v


class KBUploadResponse(BaseModel):
    document_key: str
    tenant_id: str
    uploaded: bool


class TenantInfo(BaseModel):
    tenant_id: str
    name: str
    plan: str
    created_at: str
