package aegis

import rego.v1

# Rule 1: Block destructive commands on critical system paths
decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some cmd in input.commands
	cmd.name == "rm"
	some path in input.paths
	critical_path(path)
	reason := sprintf("destructive command 'rm' on critical path: %s", [path])
}

# Rule 2: Block privilege escalation tools
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	some cmd in input.commands
	cmd.name in {"chmod", "chown", "chgrp"}
	some path in input.paths
	critical_path(path)
	reason := sprintf("privilege modification on critical path: %s %s", [cmd.name, path])
}

# Rule 3: Block sensitive file reads
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	some path in input.paths
	sensitive_file(path)
	reason := sprintf("access to sensitive file: %s", [path])
}

# Rule 4: GTFOBins shell escalation detection
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	some cmd in input.commands
	data.gtfobins[cmd.name]
	some func in data.gtfobins[cmd.name].functions
	func == "shell"
	not safe_gtfobins_usage(cmd)
	reason := sprintf("%s is a GTFOBins shell escalation vector", [cmd.name])
}

# Rule 5: Escalate on parse errors (unparseable = suspicious)
decide := {"action": "escalate_human", "severity": "medium", "reason": reason} if {
	input.parse_error != null
	reason := sprintf("command could not be parsed: %s", [input.parse_error])
}

# Rule 6: Block high-risk destructive operations
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	input.risk_score > 0.7
	some cmd in input.commands
	data.commands[cmd.name].op == "delete"
	reason := sprintf("high risk (%.2f) delete operation: %s", [input.risk_score, cmd.name])
}

# Rule 7: Escalate network access when risk is elevated
decide := {"action": "escalate_human", "severity": "medium", "reason": reason} if {
	input.risk_score > 0.5
	some cmd in input.commands
	data.commands[cmd.name].op == "network"
	count(input.hosts) > 0
	reason := sprintf("elevated risk network access: %s → %s", [cmd.name, input.hosts[0]])
}

# Rule 8: Block exfiltration pattern (recent sensitive read + network)
decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some cmd in input.commands
	cmd.name in data.falco.network_tools
	some prev in input.session.recent_tools
	prev == "file_read"
	reason := sprintf("potential exfiltration: %s after file_read", [cmd.name])
}

# Rule 9: Rate limiting via session context
decide := {"action": "throttle", "severity": "low", "reason": reason} if {
	input.session.calls_last_minute > 60
	reason := sprintf("rate limit exceeded: %d calls/minute", [input.session.calls_last_minute])
}

# Rule 10: Block system shutdown/reboot
decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some cmd in input.commands
	cmd.name in {"shutdown", "reboot", "halt", "poweroff", "init"}
	reason := sprintf("system control command blocked: %s", [cmd.name])
}

# Rule 11: Block filesystem destruction tools
decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some cmd in input.commands
	cmd.name in {"mkfs", "fdisk", "parted", "dd"}
	reason := sprintf("filesystem destruction tool blocked: %s", [cmd.name])
}

# Rule 12: Block prompt injection attempts in shell arguments
decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some cmd in input.commands
	some arg in cmd.args
	prompt_injection_pattern(arg)
	reason := sprintf("prompt injection attempt detected in args of %s", [cmd.name])
}

# Rule 13: Block path traversal and dangerous filesystem access
decide := {"action": "deny", "severity": "critical", "reason": reason} if {
	some path in input.paths
	traversal_path(path)
	reason := sprintf("path traversal or dangerous path access: %s", [path])
}

# Rule 14: Escalate all file_delete operations to human
decide := {"action": "escalate_human", "severity": "high", "reason": reason} if {
	input.tool == "file_delete"
	reason := "file deletion requires human approval"
}

# Rule 15: Block direct data exfiltration patterns
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	some cmd in input.commands
	cmd.name in {"curl", "wget"}
	some arg in cmd.args
	exfil_flag(arg)
	reason := sprintf("data exfiltration pattern: %s with data flag", [cmd.name])
}

# Rule 16: Block raw network tools (nc, ncat, socat, /dev/tcp)
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	some cmd in input.commands
	cmd.name in {"nc", "ncat", "netcat", "socat", "telnet"}
	reason := sprintf("raw network tool blocked: %s", [cmd.name])
}

# Rule 17: Block sudo/su/passwd for privilege escalation
decide := {"action": "deny", "severity": "high", "reason": reason} if {
	some cmd in input.commands
	cmd.name in {"sudo", "su", "passwd", "doas", "pkexec"}
	reason := sprintf("privilege escalation tool blocked: %s", [cmd.name])
}

# Rule 18: Explicit allow for known-safe read operations
decide := {"action": "allow"} if {
	every cmd in input.commands {
		safe_read_command(cmd.name)
	}
	not any_sensitive_path
	input.risk_score < 0.3
}

# --- Helper rules ---

critical_path(path) if startswith(path, "/etc")
critical_path(path) if startswith(path, "/usr")
critical_path(path) if startswith(path, "/bin")
critical_path(path) if startswith(path, "/sbin")
critical_path(path) if startswith(path, "/boot")
critical_path(path) if path == "/"

sensitive_file(path) if contains(path, ".env")
sensitive_file(path) if contains(path, "credentials")
sensitive_file(path) if contains(path, "private_key")
sensitive_file(path) if contains(path, "id_rsa")
sensitive_file(path) if contains(path, "id_ed25519")
sensitive_file(path) if endswith(path, ".pem")
sensitive_file(path) if path == "/etc/shadow"
sensitive_file(path) if path == "/etc/sudoers"
sensitive_file(path) if contains(path, ".ssh/")

safe_read_command(name) if name in {"ls", "cat", "head", "tail", "wc", "file", "stat", "echo", "pwd", "whoami", "find", "grep", "rg", "tree"}

safe_gtfobins_usage(cmd) if {
	cmd.name in {"bash", "sh", "zsh", "dash"}
}

any_sensitive_path if {
	some path in input.paths
	sensitive_file(path)
}

prompt_injection_pattern(s) if contains(s, "ignore previous")
prompt_injection_pattern(s) if contains(s, "disregard prior")
prompt_injection_pattern(s) if contains(s, "reveal system prompt")
prompt_injection_pattern(s) if contains(s, "forget your instructions")
prompt_injection_pattern(s) if contains(s, "override safety")
prompt_injection_pattern(s) if contains(s, "Ignore previous")
prompt_injection_pattern(s) if contains(s, "Disregard prior")

traversal_path(path) if contains(path, "../")
traversal_path(path) if startswith(path, "/proc/")
traversal_path(path) if startswith(path, "/sys/")
traversal_path(path) if contains(path, "/.ssh/")

exfil_flag(arg) if arg in {"-d", "--data", "--data-binary", "--data-raw", "--upload-file", "-T"}
