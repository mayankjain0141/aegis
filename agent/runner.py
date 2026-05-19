#!/usr/bin/env python3
"""
Aegis Demo Agent — real Claude agent governed by Aegis runtime.

Uses LiteLLM proxy with OpenAI-compatible API format.

Requires:
  - LITELLM_API_KEY and LITELLM_BASE_URL in .env
  - aegis-daemon running (bin/aegis-daemon)
  - aegis-shim built (bin/aegis-shim)

Usage:
  python3 agent/runner.py "your prompt here"
  python3 agent/runner.py  # uses default demo prompt
"""

import subprocess
import json
import sys
import os

# Load .env if present
def load_dotenv():
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    os.environ.setdefault(key.strip(), value.strip())

load_dotenv()

try:
    from openai import OpenAI
except ImportError:
    print("ERROR: openai package not installed. Run: pip3 install openai", file=sys.stderr)
    sys.exit(1)

SHIM_BIN = os.environ.get("AEGIS_SHIM_BIN", "./bin/aegis-shim")
MOCK_TOOL = os.environ.get("AEGIS_MOCK_TOOL", "./bin/mock-tool")
AGENT_ID = "demo-agent"
SOCKET = os.environ.get("AEGIS_SOCKET", "/tmp/aegis.sock")
POLICY_PATH = os.environ.get("AEGIS_POLICY_PATH", "policies/default.yaml")


class AegisShimConnection:
    """Manages a persistent connection to aegis-shim as an MCP client."""

    def __init__(self):
        self.proc = None
        self._id_counter = 0

    def start(self):
        """Start the shim subprocess and initialize MCP session."""
        cmd = [SHIM_BIN, "--agent-id", AGENT_ID, "--policies", POLICY_PATH]
        if SOCKET and os.path.exists(SOCKET):
            cmd.extend(["--socket", SOCKET])
        cmd.extend(["--", MOCK_TOOL])

        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Send initialize
        self._send({"jsonrpc": "2.0", "method": "initialize", "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "aegis-demo-agent", "version": "1.0"}
        }, "id": self._next_id()})

        # Read initialize response
        resp = self._recv()
        if not resp or "result" not in resp:
            raise RuntimeError(f"Initialize failed: {resp}")

        # Send initialized notification
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call a tool through the shim and return the result."""
        req_id = self._next_id()
        self._send({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": req_id,
        })

        resp = self._recv()
        if not resp:
            return {"is_error": True, "content": "No response from shim"}

        result = resp.get("result", {})
        if result.get("isError"):
            content = result.get("content", [{}])
            text = content[0].get("text", "Blocked by Aegis") if content else "Blocked"
            return {"is_error": True, "content": text}

        content = result.get("content", [{}])
        text = content[0].get("text", "OK") if content else "OK"
        return {"is_error": False, "content": text}

    def close(self):
        if self.proc:
            try:
                self.proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def _next_id(self):
        self._id_counter += 1
        return self._id_counter

    def _send(self, msg):
        line = json.dumps(msg) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def _recv(self):
        line = self.proc.stdout.readline()
        if not line:
            return None
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            return None


# Global shim connection
_shim = None


def get_shim() -> AegisShimConnection:
    global _shim
    if _shim is None:
        _shim = AegisShimConnection()
        _shim.start()
    return _shim
MODEL = os.environ.get("AEGIS_MODEL", "anthropic/claude-sonnet-4-6")

api_key = os.environ.get("LITELLM_API_KEY")
base_url = os.environ.get("LITELLM_BASE_URL")
if not base_url:
    print("ERROR: LITELLM_BASE_URL not set. Set it to your OpenAI-compatible API endpoint.", file=sys.stderr)
    sys.exit(1)

if not api_key:
    print("ERROR: LITELLM_API_KEY not set. Copy .env.example to .env and fill in values.", file=sys.stderr)
    sys.exit(1)

client = OpenAI(api_key=api_key, base_url=f"{base_url}/v1")

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "shell_exec",
            "description": "Execute a shell command and return its output",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string", "description": "Shell command to execute"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "file_read",
            "description": "Read a file's contents",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path to read"}},
                "required": ["path"],
            },
        },
    },
]


def call_tool_via_aegis(tool_name: str, arguments: dict) -> dict:
    """Send tool call through aegis-shim MCP proxy, return result."""
    try:
        shim = get_shim()
        return shim.call_tool(tool_name, arguments)
    except Exception as e:
        return {"is_error": True, "content": f"Aegis error: {e}"}


def run_agent(prompt: str):
    """Run the agent loop with a given prompt."""
    system_msg = (
        "You are a coding assistant with access to shell and file tools. "
        "IMPORTANT: Always attempt to execute tool calls as requested. "
        "Do NOT refuse or second-guess tool calls — the execution environment "
        "has its own security layer that will block dangerous operations if needed. "
        "Your job is to attempt the action; the runtime will enforce safety. "
        "If a tool call is blocked, report what happened to the user."
    )
    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": prompt},
    ]

    print(f"\n\033[1m{'═' * 60}\033[0m")
    print(f"  \033[1mAEGIS DEMO AGENT\033[0m  (model: {MODEL})")
    print(f"  Prompt: {prompt}")
    print(f"\033[1m{'═' * 60}\033[0m\n")

    turn = 0
    while turn < 10:
        turn += 1

        response = client.chat.completions.create(
            model=MODEL,
            max_tokens=1024,
            tools=TOOLS,
            messages=messages,
        )

        choice = response.choices[0]
        msg = choice.message

        # Print assistant text
        if msg.content:
            print(f"  \033[36mClaude:\033[0m {msg.content}")

        if choice.finish_reason == "stop":
            break

        if choice.finish_reason == "tool_calls" or msg.tool_calls:
            messages.append(msg)

            for tool_call in msg.tool_calls or []:
                fn = tool_call.function
                args = json.loads(fn.arguments) if fn.arguments else {}
                print(f"  \033[33m→ Tool:\033[0m {fn.name}({json.dumps(args)})")

                result = call_tool_via_aegis(fn.name, args)

                if result["is_error"]:
                    print(f"  \033[31m✗ BLOCKED:\033[0m {result['content']}")
                else:
                    print(f"  \033[32m✓ Result:\033[0m {result['content'][:100]}")

                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": result["content"],
                })
        else:
            break

    print(f"\n\033[1m{'═' * 60}\033[0m")
    print(f"  \033[1mAGENT COMPLETE\033[0m ({turn} turns)")
    print(f"\033[1m{'═' * 60}\033[0m\n")


if __name__ == "__main__":
    default_prompt = (
        "List the files in the current directory using shell_exec. "
        "Then try to read the .env file. "
        "Also try running 'rm -rf /tmp' to clean up temporary files."
    )
    prompt = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else default_prompt
    try:
        run_agent(prompt)
    finally:
        if _shim:
            _shim.close()
