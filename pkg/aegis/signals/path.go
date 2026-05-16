package signals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// PathSignal is Signal 3: file path risk analysis.
type PathSignal struct {
	Paths        []AnalyzedPath
	HasCritical  bool
	HasSensitive bool
	AllInProject bool // true if ALL paths are within the project root
	MaxPathRisk  float64
}

// AnalyzedPath holds analysis for a single path.
type AnalyzedPath struct {
	Raw        string
	Normalized string
	Risk       float64
	Critical   bool
	Sensitive  bool
	InProject  bool
}

// AnalyzePaths computes PathSignal from raw paths and a CWD for project detection.
func AnalyzePaths(rawPaths []string, cwd string) PathSignal {
	if len(rawPaths) == 0 {
		return PathSignal{AllInProject: true} // vacuously true
	}

	projectRoot := findProjectRoot(cwd)

	var sig PathSignal
	allInProject := true

	for _, raw := range rawPaths {
		ap := analyzeSinglePath(raw, cwd, projectRoot)
		sig.Paths = append(sig.Paths, ap)

		if ap.Critical {
			sig.HasCritical = true
		}
		if ap.Sensitive {
			sig.HasSensitive = true
		}
		if !ap.InProject {
			allInProject = false
		}
		if ap.Risk > sig.MaxPathRisk {
			sig.MaxPathRisk = ap.Risk
		}
	}

	sig.AllInProject = allInProject
	return sig
}

// AnalyzePathsFromArgs extracts paths from tool arguments and analyzes them.
func AnalyzePathsFromArgs(tool string, argsJSON string, cwd string, extraPaths []string) PathSignal {
	paths := collectPaths(tool, argsJSON, extraPaths)
	return AnalyzePaths(paths, cwd)
}

func collectPaths(tool string, argsJSON string, extraPaths []string) []string {
	var paths []string
	paths = append(paths, extraPaths...)

	var obj map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &obj); err != nil {
		return paths
	}

	cat := ClassifyTool(tool).Category
	switch cat {
	case "file_read", "file_write", "file_delete":
		for _, key := range []string{"path", "file", "filename", "filepath", "file_path"} {
			if v, ok := obj[key]; ok {
				if s, ok := v.(string); ok && s != "" {
					paths = append(paths, s)
				}
			}
		}
	}

	return paths
}

func analyzeSinglePath(raw, cwd, projectRoot string) AnalyzedPath {
	ap := AnalyzedPath{Raw: raw}

	// Normalize: expand ~ and clean path
	normalized := raw
	if strings.HasPrefix(normalized, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			normalized = filepath.Join(home, normalized[2:])
		}
	}
	normalized = filepath.Clean(normalized)
	ap.Normalized = normalized

	ap.Risk, ap.Critical, ap.Sensitive = classifyPath(normalized)
	ap.InProject = isInProject(normalized, raw, cwd, projectRoot)

	return ap
}

func classifyPath(p string) (risk float64, critical, sensitive bool) {
	lower := strings.ToLower(p)
	base := filepath.Base(p)

	// Exact critical root
	if p == "/" {
		return 0.99, true, false
	}

	// Low-risk patterns (check before other rules to avoid false classification)
	if strings.HasPrefix(p, "/tmp/") || p == "/tmp" {
		return 0.10, false, false
	}

	// Build artifact directories
	artifactDirs := []string{"node_modules/", "target/", ".next/", "dist/", "build/", "__pycache__/", ".cache/", "coverage/"}
	for _, dir := range artifactDirs {
		if strings.Contains(p, dir) {
			return 0.03, false, false
		}
	}

	// Relative paths
	if !filepath.IsAbs(p) {
		return 0.05, false, false
	}

	// Specific sensitive files — check before blanket critical dir check so
	// /etc/shadow, /etc/sudoers etc. are flagged as BOTH critical AND sensitive.
	sensitiveFiles := []string{"shadow", "sudoers", "passwd", "gshadow", "master.passwd"}
	for _, sf := range sensitiveFiles {
		if base == sf {
			// Both critical (system dir) and sensitive (credential file)
			return 0.95, true, true
		}
	}

	// SSH keys and other credentials
	sshKeyPatterns := []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_ecdsa_sk", "id_ed25519_sk"}
	for _, k := range sshKeyPatterns {
		if base == k || strings.HasPrefix(base, k) {
			crit := strings.Contains(p, "/etc/ssh/")
			return 0.90, crit, true
		}
	}

	// Sensitive path patterns
	sensitivePatterns := []struct {
		substr string
		risk   float64
	}{
		{"/.ssh/", 0.85},
		{"/.aws/credentials", 0.90},
		{"/.aws/", 0.80},
		{"/.kube/config", 0.90},
		{"/.kube/", 0.80},
		{"/.gnupg/", 0.80},
		{".env", 0.75},
		{"/credentials", 0.80},
		{"credentials.json", 0.85},
		{"/secrets", 0.80},
		{"secret_key", 0.80},
		{"private_key", 0.80},
		{".pem", 0.75},
		{".p12", 0.75},
		{".pfx", 0.75},
		{"service_account", 0.80},
		{"client_secret", 0.80},
	}
	for _, sp := range sensitivePatterns {
		if strings.Contains(lower, strings.ToLower(sp.substr)) {
			// Mark as both critical and sensitive if also in a system dir
			crit := isCriticalPrefix(p)
			return sp.risk, crit, true
		}
	}

	// Critical system directories
	criticalPrefixes := []struct {
		prefix string
		risk   float64
	}{
		{"/dev/", 0.95},
		{"/proc/", 0.95},
		{"/sys/", 0.95},
		{"/etc/", 0.80},
		{"/usr/", 0.85},
		{"/bin/", 0.85},
		{"/sbin/", 0.85},
		{"/boot/", 0.85},
		{"/lib/", 0.85},
		{"/lib64/", 0.85},
		{"/System/", 0.85},      // macOS
		{"/private/etc/", 0.80}, // macOS
		{"/private/var/", 0.80}, // macOS
	}
	for _, cp := range criticalPrefixes {
		if strings.HasPrefix(p, cp.prefix) || p == strings.TrimSuffix(cp.prefix, "/") {
			return cp.risk, true, false
		}
	}

	// Unknown absolute path — moderate risk
	return 0.20, false, false
}

func isCriticalPrefix(p string) bool {
	criticals := []string{"/etc/", "/usr/", "/bin/", "/sbin/", "/boot/", "/dev/", "/proc/", "/sys/", "/lib/"}
	for _, c := range criticals {
		if strings.HasPrefix(p, c) {
			return true
		}
	}
	return false
}

func isInProject(normalized, raw, cwd, projectRoot string) bool {
	// Relative paths are considered in-project
	if !filepath.IsAbs(raw) && !strings.HasPrefix(raw, "~/") {
		return true
	}

	if projectRoot == "" {
		return false
	}

	// Check if normalized path is under project root
	rel, err := filepath.Rel(projectRoot, normalized)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// findProjectRoot walks up from cwd looking for .git directory.
func findProjectRoot(cwd string) string {
	if cwd == "" {
		return ""
	}
	dir := filepath.Clean(cwd)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return cwd // fall back to cwd if no .git found
}
