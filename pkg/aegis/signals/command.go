package signals

import (
	"encoding/json"
	"strings"

	"github.com/mayjain/aegis/internal/extract"
)

// CommandSignal is Signal 2: resolved commands with verb danger scores.
type CommandSignal struct {
	Commands      []ResolvedCommand
	Verbs         []string
	VerbDanger    map[string]float64
	MaxVerbDanger float64
	// Paths extracted from shell command arguments (for shell tools)
	Paths []string
	// Hosts extracted from shell command arguments (for shell tools)
	Hosts []string
}

// ResolvedCommand is a single binary invocation after unwrapping.
type ResolvedCommand struct {
	Binary      string
	FullPath    string // absolute path if invoked with full path (e.g. /tmp/payload)
	Args        []string
	Wrappers    []string
	VarExpanded bool
}

// verbDangerTable maps binary names to their danger score.
// curl/wget base score is 0.20; rules boost to 0.70 when data flags present.
var verbDangerTable = map[string]float64{
	"rm": 0.80, "mkfs": 0.95, "fdisk": 0.95, "dd": 0.95, "shred": 0.90,
	"shutdown": 0.85, "reboot": 0.85, "halt": 0.85, "poweroff": 0.85,
	"init": 0.85, "telinit": 0.85,
	"nc": 0.85, "ncat": 0.85, "socat": 0.85, "telnet": 0.85,
	"curl": 0.20, "wget": 0.20,
	"scp": 0.50, "rsync": 0.50,
	"git": 0.05, "npm": 0.05, "pip": 0.05, "pip3": 0.05,
	"cargo": 0.05, "go": 0.05, "yarn": 0.05, "brew": 0.05, "apt": 0.05, "apt-get": 0.05,
	"make": 0.05, "cmake": 0.05, "gradle": 0.05, "mvn": 0.05,
	"tsc": 0.05, "gcc": 0.05, "rustc": 0.05,
	"ls": 0.02, "cat": 0.02, "echo": 0.02, "pwd": 0.02,
	"whoami": 0.02, "date": 0.02, "head": 0.02, "tail": 0.02,
	"wc": 0.02, "file": 0.02, "stat": 0.02, "find": 0.02, "grep": 0.02,
	"docker": 0.30, "kubectl": 0.30, "docker-compose": 0.30,
	"sudo": 0.70, "su": 0.70, "pkexec": 0.70, "doas": 0.70,
	"crontab": 0.75,
	"chmod": 0.40, "chown": 0.30,
	// Scripting interpreters — base danger reflects ability to execute arbitrary code
	"python": 0.35, "python3": 0.35, "node": 0.35, "ruby": 0.35,
	"perl": 0.35, "php": 0.35, "lua": 0.35, "awk": 0.35,
	"bash": 0.35, "sh": 0.35, "zsh": 0.35,
	// SSH/SCP can open tunnels or exfiltrate data
	"ssh": 0.40,
	// passwd changes credentials
	"passwd": 0.80, "chpasswd": 0.80,
	// openssl can exfiltrate data via TLS connections
	"openssl": 0.40,
	"pytest": 0.02, "jest": 0.02, "mocha": 0.02,
	"base64": 0.20, "xxd": 0.20,
	// System config
	"systemctl": 0.40, "service": 0.40,
	"useradd": 0.70, "usermod": 0.70, "userdel": 0.70,
	"visudo": 0.85,
	"iptables": 0.60, "ip6tables": 0.60,
	"mount": 0.60, "umount": 0.40,
}

// dataFlags are curl/wget flags that indicate data upload (exfiltration risk).
var dataFlags = map[string]bool{
	"-d": true, "--data": true, "--data-binary": true, "--data-raw": true,
	"-T": true, "-F": true, "--form": true,
	"--post-file": true, "--upload-file": true,
	"--data-urlencode": true,
}

// AnalyzeCommand computes CommandSignal from tool name and raw arguments JSON.
func AnalyzeCommand(tool string, argsJSON string, extractor *extract.Extractor) CommandSignal {
	var sig CommandSignal
	sig.VerbDanger = make(map[string]float64)

	// Only shell tools have commands to analyze
	if !IsShellTool(tool) {
		return sig
	}

	result := extractor.Extract(normalizeToolName(tool), argsJSON)
	if result.Err != nil && len(result.Commands) == 0 {
		// Parse error with no commands — try to extract the command string directly
		cmd := extractCommandField(argsJSON)
		if cmd != "" {
			// Minimal extraction: just split on spaces
			parts := strings.Fields(cmd)
			if len(parts) > 0 {
				result.Commands = []extract.Command{{Name: parts[0], Args: parts[1:]}}
			}
		}
	}

	sig.Hosts = result.Hosts

	verbsSeen := make(map[string]bool)
	for _, cmd := range result.Commands {
		resolved := ResolvedCommand{
			Binary:   cmd.Name,
			FullPath: cmd.FullPath,
			Args:     cmd.Args,
		}

		danger := verbDangerTable[cmd.Name]

		// Boost curl/wget danger when data flags are present
		if (cmd.Name == "curl" || cmd.Name == "wget") && hasDataFlag(cmd.Args) {
			danger = 0.70
		}

		sig.Commands = append(sig.Commands, resolved)

		if !verbsSeen[cmd.Name] {
			verbsSeen[cmd.Name] = true
			sig.Verbs = append(sig.Verbs, cmd.Name)
			sig.VerbDanger[cmd.Name] = danger
			if danger > sig.MaxVerbDanger {
				sig.MaxVerbDanger = danger
			}
		}
	}

	// extractKeyValuePaths must run AFTER sig.Commands is populated (e.g. dd if=/dev/sda).
	kvPaths := extractKeyValuePaths(sig.Commands)
	sig.Paths = append(append(result.Paths, kvPaths...), extractRedirectTargets(extractCommandField(argsJSON))...)

	return sig
}

func hasDataFlag(args []string) bool {
	for _, arg := range args {
		// Handle --data=value style
		key := strings.SplitN(arg, "=", 2)[0]
		if dataFlags[key] {
			return true
		}
	}
	return false
}

// normalizeToolName maps native tool names to the extract package's expected names.
func normalizeToolName(tool string) string {
	switch strings.ToLower(tool) {
	case "shell":
		return "shell_exec"
	case "bash":
		return "bash"
	default:
		return tool
	}
}

func extractCommandField(argsJSON string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &obj); err != nil {
		return ""
	}
	for _, key := range []string{"command", "cmd", "script", "shell"} {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// extractKeyValuePaths extracts paths from key=value style arguments (e.g. dd if=/dev/sda).
func extractKeyValuePaths(cmds []ResolvedCommand) []string {
	var paths []string
	for _, cmd := range cmds {
		for _, arg := range cmd.Args {
			if idx := strings.Index(arg, "=/"); idx > 0 {
				path := arg[idx+1:]
				if strings.HasPrefix(path, "/") {
					paths = append(paths, path)
				}
			}
			// Also handle home dir: key=~/path
			if idx := strings.Index(arg, "=~/"); idx > 0 {
				path := arg[idx+1:]
				paths = append(paths, path)
			}
		}
	}
	return paths
}

// extractRedirectTargets pulls out shell redirect targets (> /path, >> /path, 2> /path).
// These are often missed by the extractor since redirects aren't CallExpr arguments.
func extractRedirectTargets(cmd string) []string {
	if cmd == "" {
		return nil
	}
	var paths []string
	// Match: >> /path, > /path, 2>> /path, 2> /path
	// Simple regex-free scan
	for i := 0; i < len(cmd)-1; i++ {
		if cmd[i] == '>' {
			// Skip to next non-space after >
			j := i + 1
			if j < len(cmd) && cmd[j] == '>' {
				j++ // >>
			}
			for j < len(cmd) && (cmd[j] == ' ' || cmd[j] == '\t') {
				j++
			}
			// Read the path
			k := j
			for k < len(cmd) && cmd[k] != ' ' && cmd[k] != '\t' && cmd[k] != ';' && cmd[k] != '|' {
				k++
			}
			if k > j {
				path := cmd[j:k]
				if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "~/") {
					paths = append(paths, path)
				}
			}
		}
	}
	return paths
}

// HasDataFilePattern returns true if the args contain @file data upload patterns
// (e.g., curl -d @/etc/passwd or curl -F "file=@/etc/shadow").
func HasDataFilePattern(args []string) (bool, string) {
	for _, arg := range args {
		// -d @/path  (strip only the @ prefix, preserve the full path)
		if strings.HasPrefix(arg, "@/") || strings.HasPrefix(arg, "@~") {
			return true, arg[1:] // keep leading / or ~
		}
		// -F "field=@/path" or --form "field=@/path"
		if strings.Contains(arg, "=@/") || strings.Contains(arg, "=@~") {
			idx := strings.Index(arg, "=@")
			if idx >= 0 {
				return true, arg[idx+2:] // keep leading / or ~ — do NOT strip it
			}
		}
	}
	return false, ""
}
