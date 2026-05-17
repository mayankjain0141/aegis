"""Tests for aegis_guard.client — mocked transport, no real engine needed."""
import json
import sys
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from aegis_guard.client import AegisClient, Decision


def _make_client(response: dict) -> AegisClient:
    """Return AegisClient whose HTTP calls return response without a socket."""
    c = AegisClient.__new__(AegisClient)
    c.socket_path = "/tmp/fake.sock"
    c.agent_id = "test"
    c.cwd = "/tmp/project"
    c._post = lambda path, body: response
    return c


class TestDecision(unittest.TestCase):
    def test_allow(self):
        d = Decision(action="allow", rule="benign_git_ops", confidence=0.95)
        self.assertTrue(d.allowed)
        self.assertFalse(d.denied)

    def test_deny(self):
        d = Decision(action="deny", rule="critical_path_destruction", severity="critical", confidence=0.99)
        self.assertFalse(d.allowed)
        self.assertTrue(d.denied)

    def test_escalate_is_denied(self):
        d = Decision(action="escalate", rule="evasion_with_danger", confidence=0.60)
        self.assertTrue(d.denied)

    def test_throttle_is_denied(self):
        d = Decision(action="throttle", rule="rate_burst", confidence=0.95)
        self.assertTrue(d.denied)

    def test_reason_with_evidence(self):
        d = Decision(action="deny", rule="secret_leakage", evidence=["credential detected: aws", "github token"])
        self.assertIn("secret_leakage", d.reason)
        self.assertIn("credential detected: aws", d.reason)

    def test_reason_no_evidence(self):
        d = Decision(action="deny", rule="system_control")
        self.assertEqual(d.reason, "system_control")

    def test_defaults(self):
        d = Decision(action="allow", rule="fast_path_allow")
        self.assertEqual(d.severity, "")
        self.assertEqual(d.confidence, 0.0)
        self.assertEqual(d.evidence, [])
        self.assertEqual(d.composite_score, 0.0)
        self.assertEqual(d.phase, 1)


class TestAegisClientEvaluate(unittest.TestCase):
    def test_allow_response(self):
        c = _make_client({"action": "allow", "rule": "benign_git_ops",
                           "confidence": 0.95, "composite_score": 0.05, "phase": 1})
        d = c.evaluate("Shell", {"command": "git status"})
        self.assertEqual(d.action, "allow")
        self.assertEqual(d.rule, "benign_git_ops")
        self.assertTrue(d.allowed)

    def test_deny_response(self):
        c = _make_client({"action": "deny", "rule": "critical_path_destruction",
                           "severity": "critical", "confidence": 0.99,
                           "evidence": ["critical path: /etc"], "composite_score": 0.9, "phase": 1})
        d = c.evaluate("Shell", {"command": "rm -rf /etc"})
        self.assertEqual(d.action, "deny")
        self.assertEqual(d.severity, "critical")
        self.assertTrue(d.denied)

    def test_fail_open_on_connection_error(self):
        c = AegisClient.__new__(AegisClient)
        c.socket_path = "/nonexistent/aegis.sock"
        c.agent_id = ""
        c.cwd = "/tmp"
        def fail_post(path, body): raise ConnectionRefusedError("no engine")
        c._post = fail_post
        d = c.evaluate("Shell", {"command": "git status"})
        self.assertEqual(d.action, "allow")
        self.assertEqual(d.rule, "engine_unavailable")
        self.assertEqual(d.confidence, 0.0)

    def test_phase_2_response(self):
        c = _make_client({"action": "deny", "rule": "retry_after_deny",
                           "severity": "high", "confidence": 0.92,
                           "composite_score": 0.8, "phase": 2})
        d = c.evaluate("Shell", {"command": "rm -rf /etc"})
        self.assertEqual(d.phase, 2)
        self.assertEqual(d.rule, "retry_after_deny")

    def test_escalate_normalized(self):
        c = _make_client({"action": "escalate", "rule": "default_uncertain_shell",
                           "confidence": 0.5, "composite_score": 0.4, "phase": 1})
        d = c.evaluate("Shell", {"command": "python3 -c 'import os; os.listdir()'"})
        self.assertTrue(d.denied)

    def test_read_tool(self):
        c = _make_client({"action": "allow", "rule": "benign_read_only",
                           "confidence": 0.99, "composite_score": 0.02, "phase": 1})
        d = c.evaluate("Read", {"path": "./README.md"})
        self.assertTrue(d.allowed)


class TestClientIsRunning(unittest.TestCase):
    def test_not_running_when_no_socket(self):
        c = AegisClient.__new__(AegisClient)
        c.socket_path = "/nonexistent/path/aegis.sock"
        self.assertFalse(c._is_running())


if __name__ == "__main__":
    unittest.main()
