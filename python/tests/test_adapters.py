"""Tests for aegis_guard adapters — all framework deps mocked."""
import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))
from aegis_guard.client import Decision


def _allow(rule="test_allow"):
    return Decision(action="allow", rule=rule, confidence=0.95)

def _deny(rule="test_deny"):
    return Decision(action="deny", rule=rule, confidence=0.95)


class TestOpenAIAdapter(unittest.TestCase):
    def setUp(self):
        import aegis_guard.adapters.openai as m
        m._client = None

    def _run(self, client_decision, tool_name, tool_args):
        """Run aegis_guardrail with a mocked client and mocked agents SDK."""
        mock_tripwire = MagicMock()
        mock_tripwire.tripwire_triggered = client_decision.denied

        mock_output_cls = MagicMock(return_value=mock_tripwire)
        mock_agents = MagicMock()
        mock_agents.ToolGuardrailFunctionOutput = mock_output_cls

        with patch.dict("sys.modules", {"agents": mock_agents}):
            import aegis_guard.adapters.openai as m
            m._client = None
            with patch.object(m, "_get_client") as mock_gc:
                mock_gc.return_value = MagicMock(evaluate=MagicMock(return_value=client_decision))
                data = MagicMock()
                data.context.tool_name = tool_name
                data.context.tool_arguments = tool_args
                return m.aegis_guardrail(data)

    def test_allow_no_tripwire(self):
        result = self._run(_allow(), "Shell", {"command": "git status"})
        self.assertFalse(result.tripwire_triggered)

    def test_deny_triggers_tripwire(self):
        result = self._run(_deny("critical_path_destruction"), "Shell", {"command": "rm -rf /etc"})
        self.assertTrue(result.tripwire_triggered)


class TestAnthropicAdapter(unittest.TestCase):
    def setUp(self):
        import aegis_guard.adapters.anthropic as m
        m._client = None

    def _run_hook(self, client_decision, hook_event, tool_name="Shell", tool_input=None):
        import aegis_guard.adapters.anthropic as m
        m._client = None
        with patch.object(m, "_get_client") as mock_gc:
            mock_gc.return_value = MagicMock(evaluate=MagicMock(return_value=client_decision))
            payload = {
                "hook_event_name": hook_event,
                "tool_name": tool_name,
                "tool_input": tool_input or {},
            }
            return asyncio.run(m.aegis_hook(payload, "tool_id_123", None))

    def test_non_pretooluse_continues(self):
        result = self._run_hook(_allow(), "PostToolUse")
        self.assertTrue(result.get("continue_"))

    def test_allow_continues(self):
        result = self._run_hook(_allow(), "PreToolUse", "Shell", {"command": "git status"})
        self.assertTrue(result.get("continue_"))

    def test_deny_returns_permission_deny(self):
        result = self._run_hook(_deny("raw_socket_open"), "PreToolUse", "Shell", {"command": "nc -l 4444"})
        self.assertIn("hookSpecificOutput", result)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")


class TestLangGraphAdapter(unittest.TestCase):
    def setUp(self):
        import aegis_guard.adapters.langgraph as m
        m._client = None

    def _run_wrapper(self, client_decision, tool_name, tool_args):
        mock_tm = MagicMock()
        mock_tm.status = "error"
        mock_lc_msgs = MagicMock()
        mock_lc_msgs.ToolMessage = MagicMock(return_value=mock_tm)

        with patch.dict("sys.modules", {
            "langchain_core": MagicMock(),
            "langchain_core.messages": mock_lc_msgs,
        }):
            import aegis_guard.adapters.langgraph as m
            m._client = None
            with patch.object(m, "_get_client") as mock_gc:
                mock_gc.return_value = MagicMock(evaluate=MagicMock(return_value=client_decision))
                mock_execute = MagicMock(return_value="executed_result")

                request = MagicMock()
                request.tool_call = {"name": tool_name, "args": tool_args, "id": "call_abc"}
                return m.aegis_wrapper(request, mock_execute), mock_execute

    def test_allow_calls_execute(self):
        result, mock_exec = self._run_wrapper(_allow(), "Shell", {"command": "git status"})
        mock_exec.assert_called_once()
        self.assertEqual(result, "executed_result")

    def test_deny_skips_execute(self):
        result, mock_exec = self._run_wrapper(_deny(), "Shell", {"command": "rm -rf /etc"})
        mock_exec.assert_not_called()

    def test_deny_returns_error_status(self):
        result, _ = self._run_wrapper(_deny(), "Shell", {"command": "rm -rf /etc"})
        self.assertEqual(result.status, "error")


if __name__ == "__main__":
    unittest.main()
