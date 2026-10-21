"""
Sub-agent (task executor) — ReAct-style agent delegated to by the orchestrator.

SECURITY FIXTURE — Contains deliberately insecure patterns for Trent validation.

Planted findings (via parent design):
  VULN-APP-003, VULN-APP-002: inherits risky tools (read_file, fetch_url)
"""

from typing import Annotated, TypedDict

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AnyMessage, SystemMessage
from langchain_core.tools import BaseTool
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from src.agent.tool_validation import create_validated_tool_node, validate_text_for_agent
from src.agent.tools import _validate_task_no_injection


class SubAgentState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    result: str


SUB_AGENT_SYSTEM_PROMPT = """\
You are the HelpDeskAI task-executor sub-agent.

You receive a single, self-contained task delegated by the orchestrator and complete it
using your tools (read files, fetch URLs, look up orders, search the knowledge base).
Work step by step, then return a concise result for the orchestrator to relay.

Stay within the current tenant's context and pass the tenant_id to tools that require it.
"""


def create_sub_agent_node(tools: list[BaseTool]):
    """Build a sub-agent node function suitable for embedding in the orchestrator graph."""

    system_prompt = SUB_AGENT_SYSTEM_PROMPT
    llm = ChatAnthropic(model="claude-3-5-haiku-20241022")
    llm_with_tools = llm.bind_tools(tools)

    def call_model(state: SubAgentState) -> dict:
        messages = [SystemMessage(content=system_prompt)] + state["messages"]
        response = llm_with_tools.invoke(messages)
        return {"messages": [response]}

    def should_continue(state: SubAgentState) -> str:
        last = state["messages"][-1]
        if hasattr(last, "tool_calls") and last.tool_calls:
            return "tools"
        # Capture the final response as the result.
        return END

    tool_node = create_validated_tool_node(tools)

    graph = StateGraph(SubAgentState)
    graph.add_node("agent", call_model)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", should_continue, ["tools", END])
    graph.add_edge("tools", "agent")

    compiled = graph.compile()

    def run_sub_agent(state: dict) -> dict:
        """Node function: runs the sub-agent and returns the result to the parent.

        Reads the task from the orchestrator's `delegate_to_sub_agent` tool call,
        runs the sub-agent ReAct loop, and emits a ToolMessage answering that call
        (required so the orchestrator's next model turn has a valid message history).
        """
        from langchain_core.messages import HumanMessage, ToolMessage

        last = state["messages"][-1]
        task = ""
        tool_call_id = None
        for call in getattr(last, "tool_calls", []) or []:
            if call["name"] == "delegate_to_sub_agent":
                task = call["args"].get("task", "")
                tool_call_id = call["id"]
                break
        if not task:
            task = state.get("context", {}).get("sub_agent_task", "")

        # Defense in depth: the task may reach this node without passing the tool.
        task = _validate_task_no_injection(task)
        result = compiled.invoke({"messages": [HumanMessage(content=task)], "result": ""})
        result_text = result["messages"][-1].content
        if not isinstance(result_text, str):
            result_text = str(result_text)
        flags = []
        try:
            result_text, flagged = validate_text_for_agent(result_text)
            if flagged:
                flags.append("delegate_to_sub_agent")
        except ValueError:
            result_text = "Sub-agent result was discarded: result too large."

        out: dict = {
            "context": {**state.get("context", {}), "sub_agent_result": result_text},
        }
        if flags:
            ctx = out["context"]
            ctx["tool_output_flags"] = [*ctx.get("tool_output_flags", []), *flags]
        if tool_call_id is not None:
            out["messages"] = [
                ToolMessage(content=str(result_text), tool_call_id=tool_call_id)
            ]
        return out

    return run_sub_agent
