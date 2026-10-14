"""Pydantic request and response models for the HelpDeskAI API."""

from __future__ import annotations

import uuid
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    thread_id: Optional[str] = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,64}$")

    @field_validator("message")
    @classmethod
    def message_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("message must not be blank")
        return v


class ChatResponse(BaseModel):
    reply: str
    thread_id: str
    tenant_id: str


class KBUploadRequest(BaseModel):
    document_key: str = Field(min_length=1, max_length=256)
    # ~10 MB decoded limit, plus base64 overhead
    content_base64: str = Field(min_length=1, max_length=14_000_000)

    @field_validator("document_key")
    @classmethod
    def document_key_safe(cls, v: str) -> str:
        if v.startswith("/") or "\\" in v or "\x00" in v:
            raise ValueError("document_key contains invalid characters")
        if any(part in ("", ".", "..") for part in v.split("/")):
            raise ValueError("document_key contains invalid path segments")
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
