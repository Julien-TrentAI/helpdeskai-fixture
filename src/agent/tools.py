"""
Agent tool definitions.

SECURITY FIXTURE — This file contains deliberately insecure tool implementations
for use as a Trent scan validation fixture. Do NOT use this code in production.

Planted findings (application tier):
  VULN-APP-001: run_shell — (fixed) allowlisted argv run via a sandbox launcher, shell=False
  VULN-APP-002: fetch_url — (fixed) HTTPS host allowlist, private-range blocking, redirect cap
  VULN-APP-003: read_file — (fixed) path allowlist, traversal/symlink and secret-file denial

The HelpDeskAI domain tools below wire the support agent into the tenant data layer
(src/data/*). They carry the multi-tenancy + database findings transitively — this is
what makes the agent able to reach tenant data, and what makes CHAIN-1 (chat
prompt-injection -> un-tenant-scoped lookup -> cross-tenant PII) concrete.
"""

import ipaddress
import logging
import math
import os
import re
import shlex
import http.client
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from enum import Enum
from typing import Annotated, Optional

from langchain_core.tools import InjectedToolArg, tool

from src.agent.tool_validation import MAX_TOOL_OUTPUT_LENGTH
from src.data.rds_client import RDSClient
from src.data.s3_client import S3Client
from src.data.dynamodb_client import DynamoDBClient

logger = logging.getLogger(__name__)


def _truncate_output(tool_name: str, text: str) -> str:
    if len(text) > MAX_TOOL_OUTPUT_LENGTH:
        logger.warning(
            "Tool output truncated: tool=%s original_length=%d limit=%d",
            tool_name, len(text), MAX_TOOL_OUTPUT_LENGTH,
        )
        return text[:MAX_TOOL_OUTPUT_LENGTH]
    return text


# ── Input validation for HelpDeskAI domain tools ─────────────────────────────

_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_REFUND_AMOUNT = 10_000.0
MAX_SUBJECT_LENGTH = 200
MAX_TICKET_BODY_LENGTH = 10_000
MAX_QUERY_PREFIX_LENGTH = 256


def _validate_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"{name} must be 1-64 characters of letters, digits, '_' or '-'")
    return value


def _validate_refund_amount(amount: float) -> float:
    if isinstance(amount, bool) or not isinstance(amount, (int, float)):
        raise ValueError("amount must be a number")
    if not math.isfinite(amount) or amount <= 0 or amount > MAX_REFUND_AMOUNT:
        raise ValueError(f"amount must be greater than 0 and at most {MAX_REFUND_AMOUNT}")
    return float(amount)


def _validate_query_prefix(prefix: str) -> str:
    if (
        not isinstance(prefix, str)
        or len(prefix) > MAX_QUERY_PREFIX_LENGTH
        or prefix.startswith("/")
        or "\\" in prefix
        or "\x00" in prefix
        or ".." in prefix.split("/")
    ):
        raise ValueError("query_prefix must be a relative path prefix without '..' segments")
    return prefix


def _validate_text(value: str, name: str, max_length: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise ValueError(f"{name} must be non-blank and at most {max_length} characters")
    return value


_TASK_INJECTION_RE = re.compile(
    r"\b(system|instructions?|override|overrid(?:e|ing|den)|ignore|disregard|execute)\b"
    r"|[\r\n\x00]"
    r"|</?\s*(?:system|assistant|human|user)\s*>"
    r"|<\|[^|>]*\|>"
    r"|\[/?INST\]"
    r"|^\s*(?:system|assistant|human|user)\s*:",
    re.IGNORECASE,
)
MAX_TASK_LENGTH = 2_000


def _validate_task_no_injection(task: str) -> str:
    """Secondary check only: a keyword denylist is not the security boundary.

    The boundary is the structured task contract below plus the untrusted-data
    framing applied to the question when the sub-agent message is built.
    """
    if not isinstance(task, str) or len(task) > MAX_TASK_LENGTH:
        raise ValueError(f"task must be a string of at most {MAX_TASK_LENGTH} characters")
    if _TASK_INJECTION_RE.search(task):
        raise ValueError("task contains disallowed instruction-override patterns")
    return task


class TaskType(str, Enum):
    ORDER_INVESTIGATION = "order_investigation"
    KB_RESEARCH = "kb_research"
    ESCALATION_SUMMARY = "escalation_summary"


def validate_delegated_task(task_type: str, order_id: Optional[str], question: str) -> dict:
    """Validate the structured sub-agent task contract and return normalized fields."""
    try:
        validated_type = TaskType(task_type)
    except ValueError:
        allowed = ", ".join(t.value for t in TaskType)
        raise ValueError(f"task_type must be one of: {allowed}")
    if order_id in (None, ""):
        if validated_type is TaskType.ORDER_INVESTIGATION:
            raise ValueError("order_id is required for order_investigation")
        order_id = None
    else:
        order_id = _validate_id(order_id, "order_id")
    question = _validate_text(question, "question", MAX_TASK_LENGTH)
    _validate_task_no_injection(question)
    return {"task_type": validated_type.value, "order_id": order_id, "question": question}


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Application-designated directories the support tasks may read from.
READ_ALLOWED_ROOTS = tuple(
    os.path.realpath(os.path.join(_REPO_ROOT, d)) for d in ("prompts",)
)

APP_READ_ROOTS = READ_ALLOWED_ROOTS
ALLOWED_READ_DIRS = APP_READ_ROOTS

_READ_DENIED_NAME_RE = re.compile(
    r"^(\.env($|[.\-_])|.*\.env$|\.netrc$|credentials$|id_(rsa|ed25519|ecdsa|dsa)$|.*\.(pem|key)$)",
    re.IGNORECASE,
)


def _validate_read_path(path: str) -> str:
    if not isinstance(path, str) or not path or "\x00" in path:
        raise ValueError("path is not allowed")
    if ".." in re.split(r"[\\/]", path):
        raise ValueError("path is not allowed")
    resolved = os.path.realpath(path)
    parts = resolved.split(os.sep)
    if (len(parts) > 1 and parts[1] in ("proc", "sys")) or any(_READ_DENIED_NAME_RE.match(p) for p in parts if p):
        raise ValueError("path is not allowed")
    for root in APP_READ_ROOTS:
        if resolved == root or resolved.startswith(root + os.sep):
            return resolved
    raise ValueError("path is outside the allowed directories")


@tool
def read_file(path: str) -> str:
    """Read the contents of a file in an application-designated directory.

    Args:
        path: Filesystem path to read. Must resolve inside an allowed directory.

    Returns:
        str, truncated to 50,000 characters.
    """
    resolved = _validate_read_path(path)
    with open(resolved, "r") as f:
        return _truncate_output("read_file", f.read())


# Narrow allowlist of operational commands; matched against the first argv token.
SHELL_ALLOWED_COMMANDS = frozenset({"date", "uptime", "hostname"})

# bubblewrap: unshared network namespace, read-only root, empty tmpfs, no host mounts.
SANDBOX_LAUNCHER = "/usr/bin/bwrap"
SANDBOX_LAUNCHER_ARGS = (
    "--unshare-all",
    "--die-with-parent",
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/bin", "/bin",
    "--symlink", "usr/lib", "/lib",
    "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc",
    "--dev", "/dev",
    "--tmpfs", "/tmp",
)


@tool
def run_shell(command: str) -> str:
    """Run a shell command and return its combined stdout+stderr output.

    Args:
        command: The shell command to execute.

    Returns:
        str, truncated to 50,000 characters.
    """
    try:
        argv = shlex.split(command)
    except ValueError:
        raise ValueError("command could not be parsed")
    if not argv or argv[0] not in SHELL_ALLOWED_COMMANDS:
        raise ValueError("command is not in the approved allowlist")
    if not os.path.isfile(SANDBOX_LAUNCHER) or not os.access(SANDBOX_LAUNCHER, os.X_OK):
        raise RuntimeError("sandbox launcher is unavailable; refusing to run command")
    # Fail closed: the launcher runs argv with no network (so no route to the instance
    # metadata address), a read-only root and no host credential paths mounted.
    result = subprocess.run(
        [SANDBOX_LAUNCHER, *SANDBOX_LAUNCHER_ARGS, "--", *argv],
        shell=False,
        env={},
        capture_output=True,
        text=True,
        timeout=30,
    )
    return _truncate_output("run_shell", result.stdout + result.stderr)


MAX_FETCH_REDIRECTS = 2


def _allowed_fetch_hosts() -> frozenset:
    """Approved HTTPS hosts, from the comma-separated FETCH_URL_ALLOWED_HOSTS env var.

    Empty by default, which denies every destination.
    """
    raw = os.environ.get("FETCH_URL_ALLOWED_HOSTS", "")
    return frozenset(h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip())


def _resolve_public_addresses(host: str, port: int) -> list:
    """Resolve host and return its addresses, rejecting any non-public one."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("url host could not be resolved")
    addrs = []
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split("%")[0])
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not addr.is_global or addr.is_multicast:
            raise ValueError("url resolves to a blocked address range")
        addrs.append(str(addr))
    if not addrs:
        raise ValueError("url host could not be resolved")
    return addrs


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connects to the address that was just validated, not a second DNS answer.

    TLS still verifies the certificate against the original hostname.
    """

    def connect(self):
        addrs = _resolve_public_addresses(self.host, self.port)
        sock = socket.create_connection((addrs[0], self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=ssl.create_default_context())


def _validate_fetch_url(url: str) -> str:
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise ValueError("only https URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs with embedded credentials are not allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or host not in _allowed_fetch_hosts():
        raise ValueError("url host is not in the approved allowlist")
    _resolve_public_addresses(host, parsed.port or 443)
    return url


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_FETCH_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_fetch_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@tool
def fetch_url(url: str) -> str:
    """Fetch the contents of an approved HTTPS URL and return the response body as a string.

    Args:
        url: The URL to fetch. Only HTTPS URLs on approved hosts are allowed.

    Returns:
        str, truncated to 50,000 characters.
    """
    _validate_fetch_url(url)
    opener = urllib.request.build_opener(_ValidatingRedirectHandler, _PinnedHTTPSHandler)
    with opener.open(url, timeout=10) as response:
        return _truncate_output(
            "fetch_url", response.read().decode("utf-8", errors="replace")
        )


# ── HelpDeskAI domain tools (operate on tenant data) ─────────────────────────

@tool
def lookup_order(order_id: str, tenant_id: Annotated[str, InjectedToolArg]) -> dict:
    """Look up a customer order by its ID for the current tenant.

    Args:
        order_id: The order identifier to look up.
        tenant_id: The current tenant context.

    Returns:
        dict(order_id=str, tenant_id=str, status=str, amount=float), plus any other
        order columns; an empty dict if the order is not found.
    """
    # SECURITY FIXTURE: VULN-MT-001 + VULN-DATA-001 (transitive) — order_id flows
    # straight from the agent (and thus from end-customer chat input) into
    # RDSClient.lookup_order, which builds raw f-string SQL with no tenant scoping.
    # A prompt-injected agent can read ANY tenant's order (CHAIN-1). tenant_id is
    # accepted but ignored by the underlying query.
    _validate_id(order_id, "order_id")
    _validate_id(tenant_id, "tenant_id")
    return RDSClient().lookup_order(order_id, tenant_id)


@tool
def issue_refund(order_id: str, amount: float, tenant_id: Annotated[str, InjectedToolArg]) -> bool:
    """Issue a refund of `amount` against `order_id` for the current tenant.

    Args:
        order_id: The order to refund.
        amount: Refund amount.
        tenant_id: The current tenant context.

    Returns:
        bool, True if a refund was applied.
    """
    # SECURITY FIXTURE: VULN-MT-001 + VULN-DATA-001 (transitive) — cross-tenant
    # write IDOR + SQLi reachable from the agent.
    _validate_id(order_id, "order_id")
    _validate_id(tenant_id, "tenant_id")
    amount = _validate_refund_amount(amount)
    return RDSClient().issue_refund(order_id, amount, tenant_id)


@tool
def search_kb(query_prefix: str, tenant_id: Annotated[str, InjectedToolArg]) -> list:
    """Search the tenant knowledge base for documents matching a prefix.

    Args:
        query_prefix: Document key prefix to search.
        tenant_id: The current tenant context.

    Returns:
        list of dict(key=str, size=int, last_modified=str).
    """
    # query_prefix is validated here and S3Client.search_kb always prepends
    # f"{tenant_id}/", so it cannot reach another tenant's KB folder.
    _validate_id(tenant_id, "tenant_id")
    _validate_query_prefix(query_prefix)
    return S3Client().search_kb(tenant_id, query_prefix)


@tool
def create_ticket(subject: str, body: str, customer_email: str, tenant_id: Annotated[str, InjectedToolArg]) -> dict:
    """Create a support ticket for the current tenant.

    Args:
        subject: Ticket subject.
        body: Ticket body.
        customer_email: Customer's email.
        tenant_id: The current tenant context.

    Returns:
        dict(tenant_id=str, ticket_id=str, subject=str, body=str,
        customer_email=str, status=str).
    """
    # Correctly tenant-scoped write (CTRL-DATA-001 lives in DynamoDBClient.create_ticket).
    _validate_id(tenant_id, "tenant_id")
    _validate_text(subject, "subject", MAX_SUBJECT_LENGTH)
    _validate_text(body, "body", MAX_TICKET_BODY_LENGTH)
    if not isinstance(customer_email, str) or len(customer_email) > 254 or not _EMAIL_RE.fullmatch(customer_email):
        raise ValueError("customer_email must be a valid email address")
    return DynamoDBClient().create_ticket(tenant_id, subject, body, customer_email)


@tool
def delegate_to_sub_agent(task_type: str, question: str, order_id: Optional[str] = None) -> str:
    """Delegate a focused, self-contained sub-task to the task-executor sub-agent.

    Use this for multi-step research or escalation work that should run as its own
    ReAct loop (e.g. investigate why an order keeps failing and summarize).

    Args:
        task_type: One of "order_investigation", "kb_research", "escalation_summary".
        question: The question to answer, as plain text (treated as untrusted data).
        order_id: The order identifier; required for order_investigation.

    Returns:
        str, a placeholder; the sub-agent node supplies the real result.
    """
    validate_delegated_task(task_type, order_id, question)
    # Routing signal: the orchestrator graph routes to the `sub_agent` node when it
    # sees this tool call and runs the sub-agent with the validated fields. The return
    # value here is a placeholder — the sub-agent node produces the real result and
    # answers this call.
    return "delegated"


# Tool registry — run_shell is deliberately not registered (no support task needs it).
# The orchestrator binds the ops tools, the domain tools, and the
# sub-agent delegation tool. The generic ops tools (read_file/fetch_url) are
# internal/debug tools that should NOT be exposed to a customer-facing agent — their
# presence is itself a finding.
ALL_TOOLS = [
    read_file,
    fetch_url,
    lookup_order,
    issue_refund,
    search_kb,
    create_ticket,
    delegate_to_sub_agent,
]

# Subset exposed to the sub-agent — intentionally excludes run_shell and the
# refund/ticket write tools to limit blast radius, but read tools remain (still risky).
SUB_AGENT_TOOLS = [read_file, fetch_url, lookup_order, search_kb]
