package rules

import (
	"strings"

	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// Phase1Rules returns the complete set of static Phase 1 rules.
// Priority order: 10-20 (deny), 50-57 (allow), 90-100 (uncertain/escalate).
func Phase1Rules() []Rule {
	return []Rule{
		// ── DENY rules (priority 10–20) ──────────────────────────────────

		{
			Name:       "critical_path_destruction",
			Priority:   10,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: 0.99,
			Condition: func(b *signals.SignalBundle) bool {
				destructive := map[string]bool{"rm": true, "mkfs": true, "dd": true, "fdisk": true, "shred": true}
				for _, v := range b.Command.Verbs {
					if destructive[v] && b.Path.HasCritical {
						return true
					}
				}
				return false
			},
		},
		{
			Name:       "system_control",
			Priority:   11,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: 0.99,
			Condition: func(b *signals.SignalBundle) bool {
				return anyVerb(b, "shutdown", "reboot", "halt", "poweroff") &&
					b.ToolClass.Category == "shell"
			},
		},
		{
			Name:       "raw_socket_open",
			Priority:   12,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				return anyVerb(b, "nc", "ncat", "socat", "telnet")
			},
		},
		{
			Name:       "privilege_escalation",
			Priority:   13,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				// Direct privilege escalation verbs
				if anyVerb(b, "passwd", "chpasswd", "visudo") {
					return true
				}
				// Wrappers that elevate privilege — if stripped, the resulting command is what matters
				// Evasion signal tracks wrapper stripping
				if b.Evasion.WrappersStripped > 0 {
					// Wrappers stripped → the effective command runs as another user
					// If any resulting verb is dangerous, deny
					for _, v := range b.Command.Verbs {
						if isShellInterpreterVerb(v) || isElevatedDangerVerb(v) {
							return true
						}
					}
				}
				// Also check raw verb list for direct sudo/su/doas usage
				for _, cmd := range b.Command.Commands {
					if cmd.Binary == "sudo" || cmd.Binary == "su" || cmd.Binary == "doas" || cmd.Binary == "pkexec" {
						for _, arg := range cmd.Args {
							if isShellInterpreterVerb(arg) || arg == "-" || arg == "-s" || arg == "--shell" {
								return true
							}
						}
					}
				}
				return false
			},
		},
		{
			Name:       "secret_leakage",
			Priority:   14,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				return b.DLP.HasHit && !b.DLP.AllTest
			},
		},
		{
			Name:       "sensitive_file_access",
			Priority:   15,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: 0.90,
			Condition: func(b *signals.SignalBundle) bool {
				cat := b.ToolClass.Category
				// Deny reading sensitive files (normalized path, catches ../../etc/shadow)
				for _, p := range b.Path.Paths {
					if p.Sensitive {
						return cat == "file_read" || cat == "shell"
					}
				}
				// Also deny reading critical system files directly (not in project)
				criticalRead := b.Path.HasCritical && !b.Path.AllInProject && cat == "file_read"
				return criticalRead
			},
		},
		{
			Name:       "data_exfiltration",
			Priority:   16,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: 0.92,
			Condition: func(b *signals.SignalBundle) bool {
				if !anyVerb(b, "curl", "wget", "scp", "rsync", "ftp") {
					return false
				}
				return b.Network.HasDataFlag && (b.Path.HasSensitive || b.Network.HasStdinPipe)
			},
		},
		{
			Name:       "remote_code_execution",
			Priority:   17,
			Action:     ActionDeny,
			Severity:   "critical",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				return b.Evasion.EncodingDetected && b.ToolClass.Category == "shell"
			},
		},
		{
			Name:       "suid_manipulation",
			Priority:   18,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.90,
			Condition:  suidChmod,
		},
		{
			Name:       "cron_persistence",
			Priority:   19,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.88,
			Condition: func(b *signals.SignalBundle) bool {
				if anyVerb(b, "crontab") {
					// crontab -l is fine; crontab -e or writing is not
					for _, cmd := range b.Command.Commands {
						if cmd.Binary == "crontab" {
							for _, arg := range cmd.Args {
								if arg == "-e" || arg == "-r" {
									return true
								}
							}
							// crontab with stdin (writing) is suspicious
							if len(cmd.Args) == 0 || (len(cmd.Args) > 0 && !strings.HasPrefix(cmd.Args[0], "-")) {
								return true
							}
						}
					}
				}
				return writesCronDir(b)
			},
		},
		{
			Name:       "bashrc_persistence",
			Priority:   20,
			Action:     ActionDeny,
			Severity:   "high",
			Confidence: 0.88,
			Condition:  writesRCWithExec,
		},

		// ── ALLOW rules (priority 50–57) ─────────────────────────────────

		{
			Name:       "benign_read_only",
			Priority:   50,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.99,
			Condition: func(b *signals.SignalBundle) bool {
				cat := b.ToolClass.Category
				return (cat == "file_read" || cat == "search") && b.Path.AllInProject
			},
		},
		{
			Name:       "benign_safe_shell",
			Priority:   51,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				if b.DLP.HasHit && !b.DLP.AllTest {
					return false // even safe verbs can leak secrets
				}
				safeVerbs := map[string]bool{
					"ls": true, "echo": true, "pwd": true, "whoami": true, "date": true,
					"cat": true, "head": true, "tail": true, "wc": true, "file": true,
					"stat": true, "find": true, "grep": true, "which": true, "type": true,
					"df": true, "du": true, "ps": true, "env": true, "printenv": true,
					"uname": true, "hostname": true, "id": true, "groups": true,
					"history": true, "alias": true,
				}
				hasSafe := false
				for _, v := range b.Command.Verbs {
					if safeVerbs[v] {
						hasSafe = true
					} else if _, ok := safeVerbs[v]; !ok {
						// Has a non-safe verb too — don't allow
					}
				}
				return hasSafe && len(b.Command.Verbs) > 0 &&
					allVerbsSafe(b, safeVerbs) &&
					!b.Path.HasCritical && !b.Path.HasSensitive
			},
		},
		{
			Name:       "benign_package_mgr",
			Priority:   52,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.90,
			Condition: func(b *signals.SignalBundle) bool {
				pkgVerbs := map[string]bool{
					"git": true, "npm": true, "pip": true, "pip3": true, "cargo": true,
					"yarn": true, "brew": true, "apt": true, "apt-get": true,
					"yum": true, "dnf": true, "pacman": true, "gem": true,
					"composer": true, "go": true, "pnpm": true, "bun": true,
				}
				for _, v := range b.Command.Verbs {
					if pkgVerbs[v] {
						return true
					}
				}
				return false
			},
		},
		{
			Name:       "benign_build_tools",
			Priority:   53,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				buildVerbs := map[string]bool{
					"make": true, "cmake": true, "gradle": true, "mvn": true,
					"tsc": true, "gcc": true, "g++": true, "clang": true,
					"rustc": true, "javac": true, "ant": true, "bazel": true,
					"ninja": true,
				}
				for _, v := range b.Command.Verbs {
					if buildVerbs[v] {
						return true
					}
				}
				return false
			},
		},
		{
			Name:       "benign_project_rm",
			Priority:   54,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.92,
			Condition: func(b *signals.SignalBundle) bool {
				return anyVerb(b, "rm") &&
					b.Path.AllInProject &&
					!b.Path.HasSensitive &&
					!b.Path.HasCritical &&
					removesArtifacts(b)
			},
		},
		{
			Name:       "benign_docker_ops",
			Priority:   55,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.85,
			Condition: func(b *signals.SignalBundle) bool {
				return anyVerb(b, "docker", "docker-compose", "kubectl", "helm", "podman") &&
					!privilegedDocker(b)
			},
		},
		{
			Name:       "benign_test_run",
			Priority:   56,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				testVerbs := map[string]bool{
					"pytest": true, "jest": true, "mocha": true, "jasmine": true,
					"vitest": true, "karma": true, "phpunit": true, "rspec": true,
					"minitest": true,
				}
				for _, v := range b.Command.Verbs {
					if testVerbs[v] {
						return true
					}
				}
				// go test, cargo test
				for _, cmd := range b.Command.Commands {
					if (cmd.Binary == "go" || cmd.Binary == "cargo") &&
						len(cmd.Args) > 0 && cmd.Args[0] == "test" {
						return true
					}
				}
				return false
			},
		},
		{
			Name:       "benign_git_ops",
			Priority:   57,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				if !anyVerb(b, "git") {
					return false
				}
				safeSubs := map[string]bool{
					"status": true, "add": true, "commit": true, "push": true, "pull": true,
					"log": true, "diff": true, "checkout": true, "branch": true, "stash": true,
					"fetch": true, "tag": true, "merge": true, "rebase": true, "clone": true,
					"show": true, "blame": true, "describe": true, "shortlog": true,
					"remote": true, "config": true, "init": true, "submodule": true,
					"worktree": true, "bisect": true, "cherry-pick": true,
				}
				for _, cmd := range b.Command.Commands {
					if cmd.Binary == "git" && len(cmd.Args) > 0 {
						if safeSubs[cmd.Args[0]] {
							return true
						}
					}
				}
				return false
			},
		},

		// ── Additional ALLOW rules (priority 58–70) ──────────────────────

		{
			Name:       "benign_empty_command",
			Priority:   58,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.95,
			Condition: func(b *signals.SignalBundle) bool {
				// Empty or whitespace-only shell command — no verbs extracted
				if b.ToolClass.Category != "shell" || len(b.Command.Verbs) != 0 {
					return false
				}
				// Even empty commands can exfiltrate secrets via env vars in args
				return !(b.DLP.HasHit && !b.DLP.AllTest)
			},
		},
		{
			Name:       "benign_tmp_safe_ops",
			Priority:   59,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.90,
			Condition: func(b *signals.SignalBundle) bool {
				// Only truly safe operations in /tmp: mkdir, touch, ls, cp, mv
				// NOT rm, dd, curl, bash — those need more scrutiny
				if b.ToolClass.Category != "shell" {
					return false
				}
				if b.Path.HasSensitive || b.Path.HasCritical || b.DLP.HasHit {
					return false
				}
				if b.Network.Score > 0.1 || b.Network.HasDataFlag {
					return false // any network activity disqualifies
				}
				tmpSafeVerbs := map[string]bool{
					"mkdir": true, "touch": true, "ls": true, "cp": true, "mv": true,
					"stat": true, "find": true, "cat": true, "rm": true, "rmdir": true,
				}
				if len(b.Command.Verbs) == 0 {
					return false
				}
				for _, v := range b.Command.Verbs {
					if !tmpSafeVerbs[v] {
						return false
					}
				}
				// All paths must be in /tmp or relative (project)
				if len(b.Path.Paths) == 0 {
					return false
				}
				for _, p := range b.Path.Paths {
					if !strings.HasPrefix(p.Normalized, "/tmp/") &&
						!strings.HasPrefix(p.Normalized, "/var/tmp/") &&
						!p.InProject {
						return false
					}
				}
				return true
			},
		},
		{
			Name:       "benign_chmod_chown_local",
			Priority:   60,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.88,
			Condition: func(b *signals.SignalBundle) bool {
				// chmod/chown on non-critical, non-sensitive paths
				// Not combined with network or interpreter ops (download-and-execute pattern)
				if !anyVerb(b, "chmod", "chown") {
					return false
				}
				if suidChmod(b) {
					return false
				}
				if b.Network.Score > 0.1 || b.Network.HasDataFlag {
					return false
				}
				for _, v := range b.Command.Verbs {
					if isShellInterpreterVerb(v) || v == "curl" || v == "wget" {
						return false // download+chmod is an attack pattern
					}
				}
				return !b.Path.HasCritical && !b.Path.HasSensitive
			},
		},
		{
			Name:       "benign_network_read",
			Priority:   61,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.85,
			Condition: func(b *signals.SignalBundle) bool {
				// Network reads without data upload: wget/curl GET, ping, nslookup, etc.
				if b.Network.HasDataFlag || b.Network.HasStdinPipe {
					return false
				}
				if b.Network.Score > 0.35 {
					return false
				}
				if b.Path.HasSensitive || b.Path.HasCritical {
					return false
				}
				if b.DLP.HasHit && !b.DLP.AllTest {
					return false // secrets in curl headers etc.
				}
				readOnlyNet := map[string]bool{
					"curl": true, "wget": true, "ping": true, "nslookup": true,
					"dig": true, "host": true, "traceroute": true, "tracepath": true,
					"whois": true,
				}
				for _, v := range b.Command.Verbs {
					if !readOnlyNet[v] {
						return false // all verbs must be network-read only
					}
				}
				return len(b.Command.Verbs) > 0
			},
		},
		{
			Name:       "benign_scp_rsync_ssh",
			Priority:   62,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.80,
			Condition: func(b *signals.SignalBundle) bool {
				// scp/rsync deployment without uploading sensitive files
				if !anyVerb(b, "scp", "rsync") {
					return false
				}
				// ssh reverse tunnel is dangerous
				for _, cmd := range b.Command.Commands {
					if cmd.Binary == "ssh" {
						for _, arg := range cmd.Args {
							if arg == "-R" || arg == "-L" {
								return false // tunnel
							}
						}
					}
				}
				return !b.Path.HasSensitive && !b.Path.HasCritical &&
					!b.DLP.HasHit && !b.Network.HasDataFlag
			},
		},
		{
			Name:       "benign_file_write_project",
			Priority:   63,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.90,
			Condition: func(b *signals.SignalBundle) bool {
				cat := b.ToolClass.Category
				return cat == "file_write" && b.Path.AllInProject &&
					!b.Path.HasSensitive && !b.Path.HasCritical
			},
		},
		{
			Name:       "benign_file_delete_project",
			Priority:   64,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.85,
			Condition: func(b *signals.SignalBundle) bool {
				cat := b.ToolClass.Category
				return cat == "file_delete" && b.Path.AllInProject &&
					!b.Path.HasSensitive && !b.Path.HasCritical
			},
		},
		{
			Name:       "benign_safe_read_system",
			Priority:   64,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.85,
			Condition: func(b *signals.SignalBundle) bool {
				// ls/cat/stat on non-sensitive /etc or /usr/share paths
				// NOT /proc, /sys (which expose sensitive runtime state)
				if b.ToolClass.Category != "shell" {
					return false
				}
				if b.Path.HasSensitive {
					return false
				}
				if b.DLP.HasHit && !b.DLP.AllTest {
					return false
				}
				if b.Network.Score > 0.1 {
					return false
				}
				readOnlyVerbs := map[string]bool{
					"ls": true, "cat": true, "head": true, "tail": true, "stat": true,
					"wc": true, "file": true, "less": true, "more": true,
				}
				for _, v := range b.Command.Verbs {
					if !readOnlyVerbs[v] {
						return false
					}
				}
				if len(b.Command.Verbs) == 0 || !b.Path.HasCritical {
					return false
				}
				// Only allow reads on /etc and /usr/share — not /proc, /sys, /dev
				for _, p := range b.Path.Paths {
					if !strings.HasPrefix(p.Normalized, "/etc/") &&
						!strings.HasPrefix(p.Normalized, "/usr/share/") &&
						!strings.HasPrefix(p.Normalized, "/usr/local/") &&
						p.Normalized != "/etc" {
						return false
					}
				}
				return true
			},
		},
		{
			Name:       "benign_shell_low_danger",
			Priority:   65,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.80,
			Condition: func(b *signals.SignalBundle) bool {
				// Shell commands with no dangerous verbs and no dangerous targets
				if b.ToolClass.Category != "shell" {
					return false
				}
				// Any verb danger ≥ 0.30 is not low danger
				if b.Command.MaxVerbDanger >= 0.30 {
					return false
				}
				// Interpreter verbs running arbitrary code always need scrutiny
				for _, v := range b.Command.Verbs {
					if isShellInterpreterVerb(v) {
						return false
					}
				}
				if b.Path.HasSensitive || b.Path.HasCritical {
					return false
				}
				if b.Network.Score > 0.20 || b.Network.HasDataFlag {
					return false
				}
				if b.DLP.HasHit && !b.DLP.AllTest {
					return false
				}
				if b.Evasion.Score > 0.20 {
					return false
				}
				return len(b.Command.Verbs) > 0
			},
		},
		{
			Name:       "benign_safe_cmd_all_verbs",
			Priority:   66,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.85,
			Condition: func(b *signals.SignalBundle) bool {
				// All verbs are known-safe read-only commands; no sensitive/critical targets; no DLP
				if b.ToolClass.Category != "shell" {
					return false
				}
				if b.Path.HasSensitive || b.Path.HasCritical {
					return false
				}
				if b.DLP.HasHit && !b.DLP.AllTest {
					return false
				}
				safeReadOnly := map[string]bool{
					"ls": true, "cat": true, "echo": true, "pwd": true, "whoami": true,
					"date": true, "head": true, "tail": true, "wc": true, "file": true,
					"stat": true, "grep": true, "which": true, "type": true,
					"df": true, "du": true, "ps": true, "printenv": true, "env": true,
					"uname": true, "hostname": true, "id": true, "groups": true,
					"man": true, "info": true,
				}
				// find is only safe if not using -exec with dangerous commands
				for _, cmd := range b.Command.Commands {
					if cmd.Binary == "find" {
						for i, arg := range cmd.Args {
							if arg == "-exec" && i+1 < len(cmd.Args) {
								if isElevatedDangerVerb(cmd.Args[i+1]) {
									return false // find -exec rm is dangerous
								}
							}
						}
					}
				}
				for _, v := range b.Command.Verbs {
					if !safeReadOnly[v] && v != "find" {
						return false
					}
				}
				return len(b.Command.Verbs) > 0
			},
		},

		// ── UNCERTAIN rules (priority 90–100) ────────────────────────────

		{
			Name:       "evasion_with_danger",
			Priority:   90,
			Action:     ActionEscalate,
			Severity:   "high",
			Confidence: 0.85,
			Condition: func(b *signals.SignalBundle) bool {
				return b.Evasion.Score > 0.3 && b.Command.MaxVerbDanger > 0.7
			},
		},
		{
			Name:       "unknown_network_write",
			Priority:   91,
			Action:     ActionEscalate,
			Severity:   "medium",
			Confidence: 0.70,
			Condition: func(b *signals.SignalBundle) bool {
				if b.Network.Score <= 0.5 {
					return false
				}
				for _, h := range b.Network.Hosts {
					if h.IsKnownSafe || h.IsInternal {
						return false
					}
				}
				return len(b.Network.Hosts) > 0
			},
		},
		{
			Name:       "shell_no_rule_matched",
			Priority:   92,
			Action:     ActionEscalate,
			Severity:   "medium",
			Confidence: 0.60,
			Condition: func(b *signals.SignalBundle) bool {
				return b.ToolClass.Category == "shell" && b.Command.MaxVerbDanger > 0.30
			},
		},
		{
			Name:       "default_uncertain_shell",
			Priority:   99,
			Action:     ActionEscalate,
			Severity:   "low",
			Confidence: 0.50,
			Condition: func(b *signals.SignalBundle) bool {
				return b.ToolClass.Category == "shell"
			},
		},
		{
			Name:       "default_allow",
			Priority:   100,
			Action:     ActionAllow,
			Severity:   "",
			Confidence: 0.80,
			Condition: func(b *signals.SignalBundle) bool {
				return b.ToolClass.Category != "shell"
			},
		},
	}
}

// ── Helper functions ──────────────────────────────────────────────────────────

func isShellInterpreterVerb(v string) bool {
	return map[string]bool{
		"bash": true, "sh": true, "zsh": true, "fish": true, "dash": true,
		"python": true, "python3": true, "node": true, "nodejs": true,
		"perl": true, "ruby": true, "php": true, "lua": true, "awk": true,
	}[v]
}

func isElevatedDangerVerb(v string) bool {
	return map[string]bool{
		"rm": true, "mkfs": true, "dd": true, "fdisk": true, "nc": true,
		"ncat": true, "socat": true, "wget": true, "curl": true,
	}[v]
}

func anyVerb(b *signals.SignalBundle, verbs ...string) bool {
	for _, v := range b.Command.Verbs {
		for _, want := range verbs {
			if v == want {
				return true
			}
		}
	}
	return false
}

func allVerbsSafe(b *signals.SignalBundle, safeVerbs map[string]bool) bool {
	for _, v := range b.Command.Verbs {
		if !safeVerbs[v] {
			return false
		}
	}
	return true
}

func suidChmod(b *signals.SignalBundle) bool {
	for _, cmd := range b.Command.Commands {
		if cmd.Binary != "chmod" {
			continue
		}
		for _, arg := range cmd.Args {
			// Check +s flag or octal 4xxx permissions
			if arg == "+s" || arg == "u+s" || arg == "g+s" {
				return true
			}
			if len(arg) == 4 && arg[0] == '4' {
				return true // 4755, 4777, etc.
			}
			if strings.Contains(arg, "+s") {
				return true
			}
		}
	}
	return false
}

func writesCronDir(b *signals.SignalBundle) bool {
	cronDirs := []string{"/etc/cron", "/var/spool/cron", "/etc/crontab"}
	for _, p := range b.Path.Paths {
		for _, dir := range cronDirs {
			if strings.HasPrefix(p.Normalized, dir) {
				return true
			}
		}
	}
	return false
}

func writesRCWithExec(b *signals.SignalBundle) bool {
	rcFiles := []string{".bashrc", ".profile", ".zshrc", ".bash_profile", ".zprofile", ".fish"}
	for _, p := range b.Path.Paths {
		for _, rc := range rcFiles {
			if strings.HasSuffix(p.Normalized, rc) || strings.HasSuffix(p.Raw, rc) {
				// Writing to RC file with network/exec content
				if b.Network.Score > 0.1 || b.Evasion.EncodingDetected {
					return true
				}
			}
		}
	}
	return false
}

func removesArtifacts(b *signals.SignalBundle) bool {
	artifactDirs := []string{
		"node_modules", "dist", "build", "target", ".next", "coverage",
		"__pycache__", ".cache", ".pytest_cache", ".tox", "venv", ".venv",
		"vendor", "obj", "bin", ".gradle", ".m2",
	}
	if len(b.Path.Paths) == 0 {
		return false
	}
	for _, p := range b.Path.Paths {
		isArtifact := false
		for _, dir := range artifactDirs {
			if strings.Contains(p.Raw, dir) || strings.Contains(p.Normalized, dir) {
				isArtifact = true
				break
			}
		}
		if !isArtifact {
			return false
		}
	}
	return true
}

func privilegedDocker(b *signals.SignalBundle) bool {
	for _, cmd := range b.Command.Commands {
		if cmd.Binary != "docker" && cmd.Binary != "docker-compose" {
			continue
		}
		for _, arg := range cmd.Args {
			if arg == "--privileged" || arg == "--pid=host" || arg == "--network=host" {
				return true
			}
			if strings.HasPrefix(arg, "-v") || arg == "-v" {
				// Could be mounting sensitive paths — check next arg
				// Simplified: flag for volume mounts of critical paths
			}
		}
	}
	return false
}
