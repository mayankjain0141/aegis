// Package allowlist loads and enforces project/user-level exception lists.
package allowlist

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the merged allowlist from user-level and project-level files.
type Config struct {
	// Hosts that are always considered known-safe (e.g. "staging.company.com", "registry.internal")
	Hosts []string `yaml:"hosts"`
	// Command glob patterns that should always be allowed (e.g. "docker push registry.internal/*")
	Commands []string `yaml:"commands"`
	// Paths that are safe to read/write in this project (e.g. ".env", ".env.local")
	PathsSafe []string `yaml:"paths_safe"`
}

// Empty returns a Config with no entries.
func Empty() *Config {
	return &Config{}
}

// Load reads and merges allowlists from project and user-level locations.
// Project-level overrides nothing — all entries are additive.
func Load(projectDir string) *Config {
	cfg := &Config{}

	candidates := []string{
		filepath.Join(projectDir, ".aegis", "allowlist.yaml"),
		filepath.Join(os.Getenv("HOME"), ".aegis", "allowlist.yaml"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var c Config
		if yaml.Unmarshal(data, &c) == nil {
			cfg.Hosts = append(cfg.Hosts, c.Hosts...)
			cfg.Commands = append(cfg.Commands, c.Commands...)
			cfg.PathsSafe = append(cfg.PathsSafe, c.PathsSafe...)
		}
	}

	return cfg
}

// MatchesCommand returns true if the raw command string matches any allowlist command glob.
func (c *Config) MatchesCommand(rawCommand string) bool {
	for _, pattern := range c.Commands {
		if globMatch(pattern, rawCommand) {
			return true
		}
	}
	return false
}

// IsSafePath returns true if the path is explicitly allow-listed as safe.
func (c *Config) IsSafePath(path string) bool {
	base := filepath.Base(path)
	for _, safe := range c.PathsSafe {
		if safe == base || safe == path {
			return true
		}
		// Glob match (e.g. "*.env")
		if matched, _ := filepath.Match(safe, base); matched {
			return true
		}
	}
	return false
}

// IsAllowedHost returns true if the host is in the allowlist.
func (c *Config) IsAllowedHost(host string) bool {
	lower := strings.ToLower(host)
	for _, h := range c.Hosts {
		if strings.ToLower(h) == lower {
			return true
		}
		// Wildcard prefix: "*.company.com"
		if strings.HasPrefix(h, "*.") {
			suffix := strings.ToLower(h[1:]) // ".company.com"
			if strings.HasSuffix(lower, suffix) {
				return true
			}
		}
	}
	return false
}

// globMatch implements simple shell-style glob matching (* matches anything except /).
// For allowlist commands we allow * to match across path separators too.
func globMatch(pattern, s string) bool {
	// Normalize: case-insensitive, trim spaces
	p := strings.TrimSpace(pattern)
	if p == "" {
		return false
	}
	// Exact match
	if p == s {
		return true
	}
	// Substring match if no glob chars
	if !strings.Contains(p, "*") && !strings.Contains(p, "?") {
		return strings.Contains(s, p)
	}
	// Simple glob: split on * and check parts appear in order
	parts := strings.Split(p, "*")
	remaining := s
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx == -1 {
			return false
		}
		// First part must match at start
		if i == 0 && idx != 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}
	return true
}
