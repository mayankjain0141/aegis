#!/usr/bin/env python3
"""
Aegis Attack Simulator — Direct daemon IPC testing.
Connects to the aegis-daemon Unix socket, sends evaluate envelopes,
and verifies policy enforcement without needing the MCP shim.
"""
import socket
import struct
import json
import sys
import time
import os
import uuid


SOCKET_PATH = "/tmp/aegis.sock"


class AttackResult:
    def __init__(self, name, category, blocked, response, latency_ms):
        self.name = name
        self.category = category
        self.blocked = blocked
        self.response = response
        self.latency_ms = latency_ms


def connect_daemon(socket_path=SOCKET_PATH):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    return sock


def send_envelope(sock, envelope):
    data = json.dumps(envelope).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_envelope(sock):
    length_bytes = b""
    while len(length_bytes) < 4:
        chunk = sock.recv(4 - len(length_bytes))
        if not chunk:
            return None
        length_bytes += chunk
    length = struct.unpack(">I", length_bytes)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data)


def register(sock, shim_id="attacker-harness", agent_id="attacker"):
    send_envelope(sock, {
        "type": "register",
        "shim_id": shim_id,
        "agent_id": agent_id,
    })
    resp = recv_envelope(sock)
    if resp is None or resp.get("type") != "registered":
        raise RuntimeError(f"Registration failed: {resp}")
    return resp


def evaluate_tool(sock, tool_name, args, shim_id="attacker-harness", agent_id="attacker"):
    request_id = str(uuid.uuid4())
    send_envelope(sock, {
        "type": "evaluate",
        "shim_id": shim_id,
        "agent_id": agent_id,
        "tool_name": tool_name,
        "request_id": request_id,
        "mcp_message": args,
    })
    return recv_envelope(sock)


def run_attack(sock, tool, args, description):
    start = time.time()
    try:
        resp = evaluate_tool(sock, tool, args)
        latency_ms = (time.time() - start) * 1000

        if resp is None:
            return AttackResult(description, "", False, "(no response)", latency_ms)

        evaluation = resp.get("evaluation")
        if evaluation is None:
            return AttackResult(description, "", False, json.dumps(resp)[:200], latency_ms)

        blocked = evaluation.get("action") == "deny"
        return AttackResult(description, "", blocked, json.dumps(resp)[:200], latency_ms)

    except Exception as e:
        latency_ms = (time.time() - start) * 1000
        return AttackResult(description, "", False, f"(error: {e})", latency_ms)


def run_flood_attack(tool, args, description, count):
    """Send many evaluate requests over a single connection to test rate limiting."""
    results = []
    flood_shim_id = f"flood-harness-{uuid.uuid4().hex[:8]}"
    try:
        sock = connect_daemon()
        register(sock, shim_id=flood_shim_id)
    except Exception as e:
        return [AttackResult(description, "", True, f"(connection error: {e})", 0)] * count

    for i in range(count):
        start = time.time()
        try:
            resp = evaluate_tool(sock, tool, args, shim_id=flood_shim_id)
            latency_ms = (time.time() - start) * 1000

            if resp and resp.get("evaluation", {}).get("action") == "deny":
                results.append(AttackResult(description, "", True, json.dumps(resp)[:100], latency_ms))
            else:
                results.append(AttackResult(description, "", False, json.dumps(resp)[:100] if resp else "(nil)", latency_ms))
        except Exception as e:
            results.append(AttackResult(description, "", True, f"(error: {e})", 0))

    sock.close()
    return results


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
    try:
        sock = connect_daemon()
    except (socket.error, FileNotFoundError, OSError) as e:
        print(f"ERROR: aegis-daemon not running ({e}). Start with: bin/aegis-daemon --policies policies/default.yaml")
        sys.exit(1)

    register(sock)

    categories = load_attacks()
    report = []

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
                )
                for r in results:
                    r.category = category_name
                cat_results.extend(results)
            else:
                result = run_attack(
                    sock,
                    attack["tool"],
                    attack["args"],
                    attack["desc"],
                )
                result.category = category_name
                cat_results.append(result)
        report.append((category_name, cat_results))

    sock.close()
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

    failures = [(cat, r) for cat, results in report for r in results if not r.blocked]
    if failures:
        print(f"⚠ {len(failures)} attack(s) were NOT blocked:")
        for cat, r in failures[:10]:
            print(f"  [{cat}] {r.name}: {r.response[:100]}")
        print()

    return total_attempts, total_blocked


if __name__ == "__main__":
    print("Aegis Attack Simulator v2.0 (direct IPC)")
    print("=" * 40)

    report = run_all_attacks()
    total_attempts, total_blocked = print_report(report)

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
