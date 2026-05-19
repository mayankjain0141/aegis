"""HTTP client to the local aegis engine over Unix socket."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import urllib.request
import urllib.error

DEFAULT_SOCKET = "/tmp/aegis-engine.sock"
ENGINE_BINARY = str(Path(__file__).parent / "bin" / "aegis-engine")
STARTUP_TIMEOUT_S = 5


@dataclass
class Decision:
    action: str       # "allow", "deny", "escalate", "throttle"
    rule: str
    severity: str = ""
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    composite_score: float = 0.0
    stage: str = "static_rules"

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def denied(self) -> bool:
        return self.action in ("deny", "escalate", "throttle")

    @property
    def reason(self) -> str:
        return f"[{self.rule}] {'; '.join(self.evidence)}" if self.evidence else self.rule


class AegisClient:
    """Client for the local aegis engine HTTP API over Unix socket."""

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET,
        agent_id: str = "",
        cwd: str = "",
        auto_start: bool = True,
    ) -> None:
        self.socket_path = socket_path
        self.agent_id = agent_id
        self.cwd = cwd or os.getcwd()
        if auto_start and not self._is_running():
            self._start_engine()

    def evaluate(self, tool: str, args: dict[str, Any]) -> Decision:
        """Evaluate a tool call. Returns a Decision."""
        payload = json.dumps({
            "tool": tool,
            "args": args,
            "cwd": self.cwd,
            "agent_id": self.agent_id,
        }).encode()

        try:
            resp = self._post("/evaluate", payload)
            return Decision(**resp)
        except Exception as e:
            # Fail-open: if engine unavailable, allow with low confidence
            return Decision(action="allow", rule="engine_unavailable", confidence=0.0)

    def _post(self, path: str, body: bytes) -> dict:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        try:
            sock.connect(self.socket_path)
            request = (
                f"POST {path} HTTP/1.0\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"\r\n"
            ).encode() + body
            sock.sendall(request)

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        finally:
            sock.close()

        # Parse HTTP response
        header, _, body = response.partition(b"\r\n\r\n")
        return json.loads(body)

    def _is_running(self) -> bool:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(self.socket_path)
            sock.close()
            return True
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            return False

    def _start_engine(self) -> None:
        """Start the aegis engine as a background process."""
        binary = os.environ.get("AEGIS_ENGINE_BINARY", ENGINE_BINARY)
        if not Path(binary).exists():
            # Try to find in PATH
            import shutil
            binary = shutil.which("aegis-engine") or binary

        if not Path(binary).exists():
            return  # Engine not available; will fail-open on evaluate()

        subprocess.Popen(
            [binary, "--socket", self.socket_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for socket to appear
        deadline = time.monotonic() + STARTUP_TIMEOUT_S
        while time.monotonic() < deadline:
            if self._is_running():
                return
            time.sleep(0.1)
