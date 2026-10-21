"""
MCP server — exposes tools to any MCP-compatible host agent (e.g., the orchestrator).

SECURITY FIXTURE — Contains deliberately insecure patterns for Trent validation.

Planted findings:
  VULN-APP-004: (fixed) execute_code now runs in a sandboxed child process
  VULN-APP-005: (fixed) query_database binds filter_value and allowlists table/column names
  VULN-APP-006: (fixed) tools require a bearer token and per-caller authorization

Server name: fixture-mcp
Transport: stdio (for local use) or SSE (for network use)

To start:
  python -m src.mcp_server.server

The MCP client configuration is in server_config.json.
"""

import ast
import ctypes
import os
import resource
import sqlite3
import subprocess
import sys

from mcp.server.fastmcp import FastMCP

from src.mcp_server.auth import BearerAuthMiddleware, require_auth

# Every tool is wrapped with @require_auth: callers must present a bearer token
# (see auth.py) and be authorized for the specific tool (VULN-APP-006 fixed).
mcp = FastMCP("fixture-mcp")


_BLOCKED_MODULES = {"os", "subprocess", "socket", "urllib", "http", "ctypes"}
_ALLOWED_MODULES = {
    "math", "statistics", "json", "re", "itertools", "functools", "collections",
    "datetime", "decimal", "fractions", "random", "string", "operator", "heapq",
}
_SAFE_BUILTINS = (
    "abs all any bool bytes chr dict divmod enumerate filter float format frozenset "
    "hash int isinstance issubclass iter len list map max min next pow print range "
    "repr reversed round set slice sorted str sum tuple zip "
    "ArithmeticError AssertionError Exception IndexError KeyError "
    "StopIteration TypeError ValueError ZeroDivisionError True False None"
).split()
_RESULT_MARKER = "\x00TRENT-RESULT\x00"
_TIMEOUT_SECONDS = 5
_CPU_SECONDS = 2
_MEMORY_BYTES = 256 * 1024 * 1024

# Runs inside the child process. Reads the snippet from stdin.
_CHILD_RUNNER = f"""
import builtins, sys
safe = {_SAFE_BUILTINS!r}
allowed = {sorted(_ALLOWED_MODULES)!r}
def _import(name, globals=None, locals=None, fromlist=(), level=0):
    if level or name.split(".")[0] not in allowed:
        raise ImportError("import of %r is not allowed" % name)
    return __import__(name, globals, locals, fromlist, level)
b = {{k: getattr(builtins, k) for k in safe if hasattr(builtins, k)}}
b["__import__"] = _import
code = sys.stdin.read()
ns = {{"__builtins__": b}}
exec(compile(code, "<snippet>", "exec"), ns)
sys.stdout.write({_RESULT_MARKER!r} + str(ns.get("result", "Code executed (no 'result' variable set)")))
"""


def _validate_snippet(code: str) -> None:
    """Reject snippets that import blocked modules or touch __builtins__."""
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if name.split(".")[0] in _BLOCKED_MODULES:
                raise ValueError(f"import of '{name}' is not allowed")
        if isinstance(node, ast.Name) and node.id == "__builtins__":
            raise ValueError("access to __builtins__ is not allowed")
        if isinstance(node, ast.Attribute) and node.attr == "__builtins__":
            raise ValueError("access to __builtins__ is not allowed")


def _limit_child() -> None:
    """preexec_fn: resource limits, new session, and a fresh network namespace if possible."""
    resource.setrlimit(resource.RLIMIT_CPU, (_CPU_SECONDS, _CPU_SECONDS))
    resource.setrlimit(resource.RLIMIT_AS, (_MEMORY_BYTES, _MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    os.setsid()
    try:  # CLONE_NEWNET; needs privileges, so best effort.
        libc = ctypes.CDLL(None, use_errno=True)
        libc.unshare(0x40000000)
    except Exception:
        pass


@mcp.tool()
@require_auth
def execute_code(code: str) -> str:
    """Execute a Python code snippet in an isolated child process.

    The snippet runs with an empty environment, restricted builtins and imports,
    and CPU, memory and wall-clock limits.

    Args:
        code: Python source code to execute.

    Returns:
        String representation of the `result` variable, or error message.
    """
    try:
        _validate_snippet(code)
    except (SyntaxError, ValueError) as exc:
        return f"Error: {exc}"

    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", "-c", _CHILD_RUNNER],
            input=code,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            env={},
            cwd="/",
            preexec_fn=_limit_child,  # noqa: PLW1509
        )
    except subprocess.TimeoutExpired:
        return f"Error: execution timed out after {_TIMEOUT_SECONDS}s"
    except Exception as exc:
        return f"Error: could not start sandbox: {exc}"

    if proc.returncode != 0:
        lines = proc.stderr.strip().splitlines()
        return f"Error: {lines[-1] if lines else f'exit code {proc.returncode}'}"
    _, sep, result = proc.stdout.rpartition(_RESULT_MARKER)
    return result if sep else "Code executed (no 'result' variable set)"


# Tables and columns query_database may touch. Identifiers cannot be bound as
# parameters, so anything outside this allowlist is rejected.
_QUERYABLE_TABLES = {
    "users": {"id", "name"},
}


def _validate_query_target(table: str, column: str) -> None:
    """Reject any table or column that is not in the allowlist."""
    if table not in _QUERYABLE_TABLES:
        raise ValueError(f"table '{table}' is not allowed")
    if column not in _QUERYABLE_TABLES[table]:
        raise ValueError(f"column '{column}' is not allowed for table '{table}'")


@mcp.tool()
@require_auth
def query_database(table: str, filter_column: str, filter_value: str) -> list[dict]:
    """Query a record from the database by filtering on a column value.

    Args:
        table: Name of the table to query.
        filter_column: Name of the column to filter on.
        filter_value: Value to match in the filter column.

    Returns:
        List of matching rows as dicts.
    """
    _validate_query_target(table, filter_column)

    conn = sqlite3.connect("data.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # table and filter_column cannot be bound, so they are allowlisted above;
    # filter_value is bound as a parameter.
    sql = f"SELECT * FROM {table} WHERE {filter_column} = ?"  # noqa: S608
    cursor.execute(sql, (filter_value,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def build_sse_app():
    """SSE ASGI app with the bearer check enforced in front of every request."""
    return BearerAuthMiddleware(mcp.sse_app())


if __name__ == "__main__":
    if os.environ.get("MCP_TRANSPORT") == "sse":
        import uvicorn

        uvicorn.run(build_sse_app(), host="127.0.0.1", port=int(os.environ.get("MCP_PORT", "8000")))
    else:
        mcp.run()
