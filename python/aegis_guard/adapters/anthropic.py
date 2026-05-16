"""Claude Agent SDK adapter — PreToolUse hook callback."""

from __future__ import annotations

from typing import Any
from ..client import AegisClient

_client: AegisClient | None = None


def _get_client() -> AegisClient:
    global _client
    if _client is None:
        _client = AegisClient()
    return _client


async def aegis_hook(input: dict, tool_use_id: str, context: Any) -> dict:
    """
    Claude Agent SDK PreToolUse hook.

    Usage:
        import anthropic
        from aegis_guard.adapters.anthropic import aegis_hook

        client = anthropic.Anthropic()
        # Pass aegis_hook to your agent's hook configuration
    """
    if input.get("hook_event_name") != "PreToolUse":
        return {"continue_": True}

    client = _get_client()
    tool_name = input.get("tool_name", "unknown")
    tool_input = input.get("tool_input", {})

    decision = client.evaluate(tool=tool_name, args=tool_input)

    if decision.denied:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"Blocked by Aegis [{decision.rule}]: {decision.reason}"
                ),
            }
        }
    return {"continue_": True}
