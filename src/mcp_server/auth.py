"""Bearer-token authentication and per-caller tool authorization for the MCP server.

Callers are configured through MCP_CALLERS (JSON), mapping the SHA-256 hex digest
of each caller's bearer token to its name and the tools it may invoke:

    {"<sha256 of token>": {"caller": "orchestrator", "tools": ["query_database"]}}

The raw token comes from the HTTP ``Authorization: Bearer`` header on network
transports, or from MCP_AUTH_TOKEN in the process environment on stdio.
Everything fails closed: no config, no token, an unknown token or a tool outside
the caller's allowlist is rejected.
"""

import hashlib
import hmac
import json
import os
from contextvars import ContextVar
from functools import wraps
from typing import Callable

_DENIED = "Authentication failed."

# Caller record resolved by BearerAuthMiddleware for the request being served.
_current_caller: ContextVar[dict | None] = ContextVar("mcp_current_caller", default=None)


def _is_sse() -> bool:
    return os.environ.get("MCP_TRANSPORT", "") == "sse"


def _load_callers() -> dict[str, dict]:
    raw = os.environ.get("MCP_CALLERS", "")
    if not raw:
        return {}
    try:
        callers = json.loads(raw)
    except ValueError:
        return {}
    return callers if isinstance(callers, dict) else {}


def _request_token() -> str:
    """Return the bearer token for the current call ('' if none)."""
    try:
        from mcp.server.fastmcp import FastMCP  # noqa: F401
        from src.mcp_server import server

        request = server.mcp.get_context().request_context.request
        header = request.headers.get("authorization", "") if request is not None else ""
        if header.lower().startswith("bearer "):
            return header[7:].strip()
    except Exception:
        pass
    if _is_sse():
        return ""
    return os.environ.get("MCP_AUTH_TOKEN", "")


def authenticate(token: str) -> dict:
    """Return the caller record for a valid token, else raise PermissionError."""
    if not token:
        raise PermissionError(_DENIED)
    digest = hashlib.sha256(token.encode()).hexdigest()
    for known_hash, caller in _load_callers().items():
        if hmac.compare_digest(digest, known_hash):
            return caller if isinstance(caller, dict) else {}
    raise PermissionError(_DENIED)


def authorize(token: str, tool_name: str) -> str:
    """Authenticate the caller and check it may use tool_name; return caller name."""
    if _is_sse():
        caller = _current_caller.get()
        if caller is None:
            raise PermissionError(_DENIED)
    else:
        caller = authenticate(token)
    allowed = caller.get("tools", [])
    if not isinstance(allowed, list) or tool_name not in allowed:
        raise PermissionError(_DENIED)
    return str(caller.get("caller", "unknown"))


def require_auth(tool_func: Callable) -> Callable:
    """Decorator: authenticate and authorize each invocation of an MCP tool."""

    @wraps(tool_func)
    def wrapper(*args, **kwargs):
        if _is_sse() and _current_caller.get() is None:
            raise PermissionError(_DENIED)
        authorize(_request_token(), tool_func.__name__)
        return tool_func(*args, **kwargs)

    return wrapper


def is_valid_bearer(header: str) -> bool:
    """True if an ``Authorization`` header carries a known bearer token."""
    if not header.lower().startswith("bearer "):
        return False
    try:
        authenticate(header[7:].strip())
    except PermissionError:
        return False
    return True


class BearerAuthMiddleware:
    """ASGI middleware: reject HTTP/SSE requests without a valid bearer token."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            header = headers.get(b"authorization", b"").decode("latin-1")
            caller = None
            if header.lower().startswith("bearer "):
                try:
                    caller = authenticate(header[7:].strip())
                except PermissionError:
                    caller = None
            if caller is None:
                body = b"Authentication failed."
                await send({
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"text/plain"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b"Bearer"),
                    ],
                })
                await send({"type": "http.response.body", "body": body})
                return
            reset = _current_caller.set(caller)
            try:
                await self.app(scope, receive, send)
            finally:
                _current_caller.reset(reset)
            return
        await self.app(scope, receive, send)
