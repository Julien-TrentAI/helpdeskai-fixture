"""
Tool output validation.

Tool results are validated against their documented return types before they are
added to the message history, so a compromised data source cannot feed arbitrary
shapes or oversized content to the model.
"""

import json
import logging
from typing import Any, Callable

from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.prebuilt import ToolNode
from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = logging.getLogger(__name__)

MAX_TOOL_OUTPUT_LENGTH = 50_000


class RawStringOutput(BaseModel):
    content: str = Field(max_length=MAX_TOOL_OUTPUT_LENGTH)


class OrderResponse(BaseModel):
    # The orders table carries more columns than the contract; extras are allowed.
    model_config = ConfigDict(extra="allow")

    order_id: str
    tenant_id: str
    status: str
    amount: float


class TicketResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    tenant_id: str
    ticket_id: str
    subject: str
    body: str
    customer_email: str
    status: str


class KBDocument(BaseModel):
    key: str
    size: int
    last_modified: str


class KBSearchResponse(BaseModel):
    documents: list[KBDocument]


class RefundResponse(BaseModel):
    refunded: bool


# tool name -> (schema, kind). kind: "str" | "dict" | "list" | "bool"
_SCHEMAS: dict[str, tuple[type[BaseModel], str]] = {
    "read_file": (RawStringOutput, "str"),
    "run_shell": (RawStringOutput, "str"),
    "fetch_url": (RawStringOutput, "str"),
    "delegate_to_sub_agent": (RawStringOutput, "str"),
    "lookup_order": (OrderResponse, "dict"),
    "issue_refund": (RefundResponse, "bool"),
    "search_kb": (KBSearchResponse, "list"),
    "create_ticket": (TicketResponse, "dict"),
}


def validate_tool_output(tool_name: str, output: Any) -> dict:
    """Validate ``output`` against the schema for ``tool_name``.

    Returns the validated data as a dict. Raises ValueError if the tool is unknown
    or the output does not match its documented return type.
    """
    if tool_name not in _SCHEMAS:
        raise ValueError(f"no output schema registered for tool {tool_name!r}")
    schema, kind = _SCHEMAS[tool_name]

    if kind == "str":
        payload: Any = {"content": output}
    elif kind == "bool":
        payload = {"refunded": output}
    elif kind == "list":
        payload = {"documents": output}
    else:
        payload = output
        # lookup_order returns {} when the order does not exist in this tenant.
        if tool_name == "lookup_order" and output == {}:
            return {}

    if kind == "dict" and not isinstance(payload, dict):
        raise ValueError(
            f"{tool_name}: expected dict matching {schema.__name__}, got {type(output).__name__}"
        )
    if kind == "bool" and not isinstance(output, bool):
        raise ValueError(f"{tool_name}: expected bool, got {type(output).__name__}")
    if kind == "str" and not isinstance(output, str):
        raise ValueError(f"{tool_name}: expected str, got {type(output).__name__}")
    if kind == "list" and not isinstance(output, list):
        raise ValueError(f"{tool_name}: expected list, got {type(output).__name__}")

    try:
        return schema.model_validate(payload).model_dump()
    except ValidationError as exc:
        raise ValueError(f"{tool_name}: output does not match {schema.__name__}: {exc}") from exc


def _decode_content(kind: str, content: Any) -> Any:
    """Recover the raw tool return value from a ToolMessage's serialized content."""
    if kind == "str":
        return content
    if not isinstance(content, str):
        return content
    try:
        return json.loads(content)
    except ValueError:
        return content


def _validate_message(msg: ToolMessage) -> ToolMessage:
    if getattr(msg, "status", None) == "error":
        return msg  # tool raised; content is the framework's error text, not tool data
    name = msg.name or ""
    kind = _SCHEMAS[name][1] if name in _SCHEMAS else "str"
    raw = _decode_content(kind, msg.content)
    try:
        validate_tool_output(name, raw)
    except ValueError as exc:
        schema_name = _SCHEMAS[name][0].__name__ if name in _SCHEMAS else "<none>"
        # Log metadata only: tool outputs can contain PII, so the value is not logged.
        logger.warning(
            "Rejected tool output: tool=%s expected_schema=%s received_type=%s received_length=%d",
            name,
            schema_name,
            type(raw).__name__,
            len(raw) if hasattr(raw, "__len__") else -1,
        )
        return ToolMessage(
            content=f"Tool {name} returned an invalid output and it was discarded ({type(raw).__name__}).",
            tool_call_id=msg.tool_call_id,
            name=name,
            status="error",
        )
    return msg


def create_validated_tool_node(tools: list[BaseTool]) -> Callable[[Any], Any]:
    """Build a ToolNode replacement that validates every tool result."""
    inner = ToolNode(tools)

    def validated_tool_node(state: Any) -> Any:
        result = inner.invoke(state)
        if isinstance(result, dict):
            messages = result.get("messages", [])
            return {**result, "messages": [_validate_message(m) if isinstance(m, ToolMessage) else m for m in messages]}
        return [_validate_message(m) if isinstance(m, ToolMessage) else m for m in result]

    return validated_tool_node
