"""
aegis-guard: AI agent security guardrails for OpenAI Agents SDK, Claude Agent SDK, and LangGraph.

Quick start:
    from aegis_guard import AegisClient
    client = AegisClient()
    decision = client.evaluate(tool="Shell", args={"command": "git status"})
"""

from .client import AegisClient, Decision

__all__ = ["AegisClient", "Decision"]
__version__ = "2.0.0"
