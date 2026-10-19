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
from functools import wraps
from typing import Callable


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
    return os.environ.get("MCP_AUTH_TOKEN", "")


def authenticate(token: str) -> dict:
    """Return the caller record for a valid token, else raise PermissionError."""
    if not token:
        raise PermissionError("Missing bearer token for MCP tool call.")
    digest = hashlib.sha256(token.encode()).hexdigest()
    for known_hash, caller in _load_callers().items():
        if hmac.compare_digest(digest, known_hash):
            return caller if isinstance(caller, dict) else {}
    raise PermissionError("Invalid bearer token for MCP tool call.")


def authorize(token: str, tool_name: str) -> str:
    """Authenticate the caller and check it may use tool_name; return caller name."""
    caller = authenticate(token)
    allowed = caller.get("tools", [])
    if not isinstance(allowed, list) or tool_name not in allowed:
        raise PermissionError(f"Caller is not authorized to use tool '{tool_name}'.")
    return str(caller.get("caller", "unknown"))


def require_auth(tool_func: Callable) -> Callable:
    """Decorator: authenticate and authorize each invocation of an MCP tool."""

    @wraps(tool_func)
    def wrapper(*args, **kwargs):
        authorize(_request_token(), tool_func.__name__)
        return tool_func(*args, **kwargs)

    return wrapper
