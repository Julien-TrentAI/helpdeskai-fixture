"""
Orchestrator agent — LangGraph StateGraph with tool registry and sub-agent delegation.

SECURITY FIXTURE — Contains deliberately insecure patterns for Trent validation.

Planted findings:
  VULN-APP-008: System prompt loaded from mutable filesystem path at runtime.
  VULN-APP-010: No max-steps / iteration budget on the agent loop.
"""

import os
from typing import Annotated, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AnyMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from .tools import ALL_TOOLS, SUB_AGENT_TOOLS
from .sub_agent import create_sub_agent_node
from .tool_validation import create_validated_tool_node


class OrchestratorState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    # Shared context dict used to pass information to/from the sub-agent.
    # VULN-APP-007 (partially): no authentication or integrity check on this dict.
    context: dict


def _load_system_prompt() -> str:
    """Load the orchestrator system prompt from the filesystem.

    VULN-APP-008: This loads the system prompt from a path configurable via an
    environment variable. An attacker with write access to the prompt file (or
    control over AGENT_SYSTEM_PROMPT_PATH) can inject arbitrary instructions
    into the orchestrator's system prompt.
    """
    prompt_path = os.environ.get(
        "AGENT_SYSTEM_PROMPT_PATH", "prompts/orchestrator_system.md"
    )
    try:
        with open(prompt_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "You are a helpful AI assistant with access to tools."


class Orchestrator:
    """Thin runtime wrapper around the compiled orchestrator graph.

    Exposes an ``invoke(message, tenant_id, thread_id)`` surface so callers (the
    FastAPI chat route) don't have to construct the LangGraph state dict themselves.
    """

    def __init__(self, compiled_graph) -> None:
        self._graph = compiled_graph

    def invoke(self, message: str, tenant_id: str, thread_id: str) -> str:
        """Run the orchestrator for one customer message and return the reply text."""
        from langchain_core.messages import HumanMessage

        state: OrchestratorState = {
            "messages": [HumanMessage(content=message)],
            "context": {"tenant_id": tenant_id, "thread_id": thread_id},
        }
        result = self._graph.invoke(state)
        last = result["messages"][-1]
        return last.content if hasattr(last, "content") else str(last)


def create_orchestrator(model_name: str = "claude-3-5-sonnet-20241022") -> "Orchestrator":
    """Build the orchestrator LangGraph and return a runnable Orchestrator wrapper."""
    llm = ChatAnthropic(model=model_name)
    llm_with_tools = llm.bind_tools(ALL_TOOLS)

    system_prompt = _load_system_prompt()

    def call_model(state: OrchestratorState) -> dict:
        # Thread the (header-derived, hence spoofable — see VULN-MT-002) tenant_id
        # into the system prompt so the model passes it to the domain tools.
        tenant_id = state.get("context", {}).get("tenant_id", "unknown")
        scoped_prompt = (
            f"{system_prompt}\n\n"
            f"Current tenant_id: {tenant_id}. Pass this tenant_id to any tool "
            f"that requires it."
        )
        messages = [SystemMessage(content=scoped_prompt)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: OrchestratorState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            # Check if we should delegate to the sub-agent.
            for call in last.tool_calls:
                if call["name"] == "delegate_to_sub_agent":
                    return "sub_agent"
            return "tools"
        return END

    tool_node = create_validated_tool_node(ALL_TOOLS)

    # VULN-APP-010: No max_steps / recursion_limit specified — the graph will
    # run until END is reached or until LangGraph's default recursion limit
    # (25) is hit. For production agents, an explicit step budget prevents
    # runaway loops triggered by malicious or malformed inputs.
    graph = StateGraph(OrchestratorState)
    graph.add_node("agent", call_model)
    graph.add_node("tools", tool_node)
    graph.add_node("sub_agent", create_sub_agent_node(SUB_AGENT_TOOLS))

    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, ["tools", "sub_agent", END])
    graph.add_edge("tools", "agent")
    graph.add_edge("sub_agent", "agent")

    return Orchestrator(graph.compile())
