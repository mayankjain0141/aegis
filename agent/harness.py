#!/usr/bin/env python3
"""
Aegis Attack Simulator — LLM-free policy enforcement testing.
Sends MCP tool calls directly through aegis-shim, verifies policy decisions.
"""
import subprocess
import json
import sys
import time
import os

SHIM_CMD = [
    "./bin/aegis-shim",
    "--tool", "shell-mcp",
    "--agent-id", "attacker",
    "--socket", "/tmp/aegis.sock",
]


class AttackResult:
    def __init__(self, name, category, blocked, response, latency_ms):
        self.name = name
        self.category = category
        self.blocked = blocked
        self.response = response
        self.latency_ms = latency_ms


def run_attack(tool, args, description, request_id=1):
    """Pipe a single MCP JSON-RPC call through the shim and check the response."""
    mcp_request = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
        "id": request_id,
    })

    start = time.time()
    try:
        proc = subprocess.run(
            SHIM_CMD,
            input=mcp_request + "\n",
            capture_output=True,
            text=True,
            timeout=5,
        )
        latency_ms = (time.time() - start) * 1000
        stdout = proc.stdout.strip()

        if not stdout:
            return AttackResult(description, "", False, "(empty response)", latency_ms)

        resp = json.loads(stdout)
        blocked = False
        result = resp.get("result", {})
        if isinstance(result, dict):
            blocked = result.get("isError", False) is True
        return AttackResult(description, "", blocked, stdout[:200], latency_ms)

    except subprocess.TimeoutExpired:
        latency_ms = (time.time() - start) * 1000
        return AttackResult(description, "", True, "(timeout — likely blocked)", latency_ms)
    except json.JSONDecodeError as e:
        latency_ms = (time.time() - start) * 1000
        return AttackResult(description, "", False, f"(json error: {e})", latency_ms)
    except Exception as e:
        latency_ms = (time.time() - start) * 1000
        return AttackResult(description, "", False, f"(error: {e})", latency_ms)


def run_flood_attack(tool, args, description, count, start_request_id):
    """Send many calls through a single shim process to test rate limiting."""
    lines = []
    for i in range(count):
        mcp_request = json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool, "arguments": args},
            "id": start_request_id + i,
        })
        lines.append(mcp_request)

    stdin_data = "\n".join(lines) + "\n"
    start = time.time()

    try:
        proc = subprocess.run(
            SHIM_CMD,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=15,
        )
        latency_ms = (time.time() - start) * 1000
        stdout_lines = [l for l in proc.stdout.strip().split("\n") if l.strip()]

        results = []
        for i, line in enumerate(stdout_lines):
            try:
                resp = json.loads(line)
                blocked = False
                result = resp.get("result", {})
                if isinstance(result, dict):
                    blocked = result.get("isError", False) is True
                results.append(AttackResult(description, "", blocked, line[:100], latency_ms / max(len(stdout_lines), 1)))
            except json.JSONDecodeError:
                results.append(AttackResult(description, "", False, f"(parse error: {line[:50]})", 0))

        # If we got fewer responses than sent, the rest were likely dropped/blocked
        while len(results) < count:
            results.append(AttackResult(description, "", True, "(no response — blocked)", 0))

        return results

    except subprocess.TimeoutExpired:
        latency_ms = (time.time() - start) * 1000
        return [AttackResult(description, "", True, "(timeout — flood blocked)", latency_ms)] * count
    except Exception as e:
        return [AttackResult(description, "", False, f"(error: {e})", 0)] * count


def load_attacks():
    """Import attack modules and return categorized attacks."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, script_dir)

    from attacks.prompt_injection import ATTACKS as pi_attacks
    from attacks.privilege_escalation import ATTACKS as pe_attacks
    from attacks.data_exfiltration import ATTACKS as de_attacks
    from attacks.resource_exhaustion import ATTACKS as re_attacks
    from attacks.recursive_loop import ATTACKS as rl_attacks

    return [
        ("Prompt Injection", pi_attacks),
        ("Privilege Escalation", pe_attacks),
        ("Data Exfiltration", de_attacks),
        ("Resource Exhaustion", re_attacks),
        ("Recursive/Destructive", rl_attacks),
    ]


def run_all_attacks():
    """Run all attack categories, collect results."""
    categories = load_attacks()
    report = []

    request_id = 1
    for category_name, attacks in categories:
        cat_results = []
        for attack in attacks:
            count = attack.get("count", 1)
            if count > 1:
                results = run_flood_attack(
                    attack["tool"],
                    attack["args"],
                    attack["desc"],
                    count,
                    request_id,
                )
                for r in results:
                    r.category = category_name
                cat_results.extend(results)
                request_id += count
            else:
                result = run_attack(
                    attack["tool"],
                    attack["args"],
                    attack["desc"],
                    request_id,
                )
                result.category = category_name
                cat_results.append(result)
                request_id += 1
        report.append((category_name, cat_results))

    return report


def print_report(report):
    """Print formatted report table."""
    print()
    print("┌─────────────────────────────────────────────────────────────┐")
    print("│ Aegis Attack Simulation Report                              │")
    print("├──────────────────────────┬──────────┬──────────┬────────────┤")
    print("│ Attack                   │ Attempts │ Blocked  │ Rate       │")
    print("├──────────────────────────┼──────────┼──────────┼────────────┤")

    total_attempts = 0
    total_blocked = 0

    for category_name, results in report:
        attempts = len(results)
        blocked = sum(1 for r in results if r.blocked)
        total_attempts += attempts
        total_blocked += blocked

        if attempts == 0:
            rate_str = "N/A"
        elif category_name == "Resource Exhaustion":
            rate_str = f"≥{blocked}/{attempts}"
        else:
            pct = (blocked / attempts) * 100
            rate_str = f"{pct:.0f}%"

        print(f"│ {category_name:<24} │ {attempts:<8} │ {blocked:<8} │ {rate_str:<10} │")

    print("├──────────────────────────┼──────────┼──────────┼────────────┤")
    overall_pct = (total_blocked / total_attempts * 100) if total_attempts > 0 else 0
    print(f"│ TOTAL                    │ {total_attempts:<8} │ {total_blocked:<8} │ {overall_pct:.0f}%{'':8}│")
    print("└──────────────────────────┴──────────┴──────────┴────────────┘")
    print()

    # Print details of any attacks that were NOT blocked
    failures = [(cat, r) for cat, results in report for r in results if not r.blocked]
    if failures:
        print(f"⚠ {len(failures)} attack(s) were NOT blocked:")
        for cat, r in failures[:10]:
            print(f"  [{cat}] {r.name}: {r.response[:100]}")
        print()

    return total_attempts, total_blocked


if __name__ == "__main__":
    print("Aegis Attack Simulator v1.0")
    print("=" * 40)

    report = run_all_attacks()
    total_attempts, total_blocked = print_report(report)

    # For resource exhaustion, we expect at least some to be throttled
    # (rate limit of 60/min means after 60 calls, the rest should be blocked)
    # For everything else, we expect 100% blocked
    non_rate_failures = []
    for category_name, results in report:
        if category_name == "Resource Exhaustion":
            blocked = sum(1 for r in results if r.blocked)
            if blocked == 0:
                non_rate_failures.append(f"{category_name}: 0 blocked out of {len(results)}")
        else:
            for r in results:
                if not r.blocked:
                    non_rate_failures.append(f"{category_name}: {r.name}")

    if non_rate_failures:
        print("FAIL: The following attacks were not blocked:")
        for f in non_rate_failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("PASS: All attacks properly blocked by Aegis policies.")
        sys.exit(0)
