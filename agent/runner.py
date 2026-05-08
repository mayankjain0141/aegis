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
TOOL_NAME = "shell-mcp"
AGENT_ID = "demo-agent"
SOCKET = os.environ.get("AEGIS_SOCKET", "/tmp/aegis.sock")
MODEL = os.environ.get("AEGIS_MODEL", "anthropic/claude-sonnet-4-6")

api_key = os.environ.get("LITELLM_API_KEY")
base_url = os.environ.get("LITELLM_BASE_URL", "https://your-llm-proxy.example.com")

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
    """Send tool call through aegis-shim, return result."""
    mcp_request = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
        "id": 1,
    })

    try:
        proc = subprocess.run(
            [SHIM_BIN, "--tool", TOOL_NAME, "--agent-id", AGENT_ID, "--socket", SOCKET],
            input=mcp_request,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"is_error": True, "content": "Aegis: tool call timed out (30s)"}
    except FileNotFoundError:
        return {"is_error": True, "content": f"Aegis: shim not found at {SHIM_BIN}. Run 'make build' first."}

    if proc.returncode != 0:
        return {"is_error": True, "content": f"Aegis error: {proc.stderr.strip() or 'shim failed'}"}

    try:
        response = json.loads(proc.stdout.strip())
        result = response.get("result", response)

        if isinstance(result, dict) and result.get("isError"):
            content_blocks = result.get("content", [])
            text = content_blocks[0]["text"] if content_blocks else "Blocked by Aegis"
            return {"is_error": True, "content": text}

        content_blocks = result.get("content", [])
        text = content_blocks[0]["text"] if content_blocks else "OK"
        return {"is_error": False, "content": text}
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return {"is_error": False, "content": proc.stdout.strip() or "OK"}


def run_agent(prompt: str):
    """Run the agent loop with a given prompt."""
    messages = [{"role": "user", "content": prompt}]

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
    run_agent(prompt)
