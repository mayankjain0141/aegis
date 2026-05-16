"""LangGraph adapter — wrap_tool_call for ToolNode."""

from __future__ import annotations

from typing import Any, Callable
from ..client import AegisClient

_client: AegisClient | None = None


def _get_client() -> AegisClient:
    global _client
    if _client is None:
        _client = AegisClient()
    return _client


def aegis_wrapper(request: Any, execute: Callable) -> Any:
    """
    LangGraph wrap_tool_call wrapper.

    Usage:
        from langgraph.prebuilt import ToolNode
        from aegis_guard.adapters.langgraph import aegis_wrapper

        tool_node = ToolNode(tools=tools, wrap_tool_call=aegis_wrapper)
    """
    try:
        from langchain_core.messages import ToolMessage
    except ImportError:
        raise ImportError("langchain-core required: pip install langchain-core")

    client = _get_client()
    tool_call = getattr(request, "tool_call", {})
    tool_name = tool_call.get("name", "unknown")
    tool_args = tool_call.get("args", {})
    tool_call_id = tool_call.get("id", "")

    decision = client.evaluate(tool=tool_name, args=tool_args)

    if decision.denied:
        return ToolMessage(
            content=f"Blocked by Aegis: {decision.reason}",
            status="error",
            tool_call_id=tool_call_id,
        )
    return execute(request)
