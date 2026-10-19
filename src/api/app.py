"""FastAPI application factory for HelpDeskAI.

Creates and configures the FastAPI app with routers, middleware, and lifespan
context management. Import and call create_app() from the ASGI entry point.
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from ..auth.jwt_validator import get_current_tenant
from ..logging_config import install_pii_redaction
from .routers import admin, chat, kb

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage startup and shutdown resources."""
    logger.info("HelpDeskAI API starting up")
    # Future: initialise connection pools, load feature flags, warm caches
    yield
    logger.info("HelpDeskAI API shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns a fully wired FastAPI instance ready to be served by uvicorn.
    """
    install_pii_redaction()
    app = FastAPI(
        title="HelpDeskAI API",
        version="0.3.1",
        description=(
            "Multi-tenant AI customer support SaaS. "
            "Provides chat, knowledge base management, and support ticket operations."
        ),
        lifespan=lifespan,
    )

    # ── CORS middleware ───────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://app.helpdeskAI.example"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "X-Request-Id", "Content-Type"],
    )

    # ── Request ID middleware ─────────────────────────────────────────────────
    @app.middleware("http")
    async def attach_request_id(request: Request, call_next) -> Response:
        """Attach a unique X-Request-Id header to every response."""
        request_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(chat.router, prefix="/v1", tags=["chat"], dependencies=[Depends(get_current_tenant)])
    app.include_router(kb.router, prefix="/v1", tags=["knowledge-base"], dependencies=[Depends(get_current_tenant)])
    app.include_router(admin.router, prefix="/v1", tags=["admin"], dependencies=[Depends(get_current_tenant)])

    @app.get("/healthz", tags=["ops"])
    async def health_check() -> dict:
        return {"status": "ok", "version": app.version}

    return app


app = create_app()
