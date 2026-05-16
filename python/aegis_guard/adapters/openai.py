"""OpenAI Agents SDK adapter — @tool_input_guardrail decorator."""

from __future__ import annotations

from typing import Any
from ..client import AegisClient

_client: AegisClient | None = None


def _get_client() -> AegisClient:
    global _client
    if _client is None:
        _client = AegisClient()
    return _client


def aegis_guardrail(data: Any) -> Any:
    """
    OpenAI Agents SDK tool_input_guardrail function.

    Usage:
        from agents import Agent
        from aegis_guard.adapters.openai import aegis_guardrail

        agent = Agent(
            name="my-agent",
            tools=[...],
            input_guardrails=[tool_input_guardrail(aegis_guardrail)],
        )
    """
    try:
        from agents import ToolGuardrailFunctionOutput
    except ImportError:
        raise ImportError("openai-agents package required: pip install openai-agents")

    client = _get_client()
    tool_name = getattr(data.context, "tool_name", "unknown")
    tool_args = getattr(data.context, "tool_arguments", {})
    if isinstance(tool_args, str):
        import json
        try:
            tool_args = json.loads(tool_args)
        except Exception:
            tool_args = {"raw": tool_args}

    decision = client.evaluate(tool=tool_name, args=tool_args)

    if decision.denied:
        return ToolGuardrailFunctionOutput(
            output_info=decision.reason,
            tripwire_triggered=True,
        )
    return ToolGuardrailFunctionOutput(
        output_info="",
        tripwire_triggered=False,
    )
