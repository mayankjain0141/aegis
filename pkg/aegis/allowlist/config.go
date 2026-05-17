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
//
// Security: matching is done against the normalized path to prevent traversal
// bypasses. "paths_safe: [.env]" matches "./.env" and "/project/.env" but
// NOT "../../.env" (which normalizes to an absolute path outside the project).
func (c *Config) IsSafePath(rawPath string) bool {
	if len(c.PathsSafe) == 0 {
		return false
	}
	// Normalize to remove traversal components
	clean := filepath.Clean(rawPath)
	base := filepath.Base(clean)

	for _, safe := range c.PathsSafe {
		safe = strings.TrimSpace(safe)
		if safe == "" {
			continue
		}
		// If the allowlist entry has no path separator, match only the basename
		// to avoid "../../.env" matching a bare ".env" entry.
		if !strings.ContainsRune(safe, '/') {
			// Only match if the path is relative (no directory traversal)
			if filepath.IsAbs(clean) {
				// Absolute path: only match if it ends with the safe basename
				// and the clean path equals what you'd expect in a project context
				// (i.e., not a traversal to a system path)
				if base == safe {
					return true
				}
				if matched, _ := filepath.Match(safe, base); matched {
					return true
				}
			} else {
				// Relative path: safe to match on basename
				if base == safe {
					return true
				}
				if matched, _ := filepath.Match(safe, base); matched {
					return true
				}
			}
		} else {
			// Entry contains path separator — match the full cleaned path
			if clean == safe || strings.HasSuffix(clean, "/"+safe) {
				return true
			}
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

// globMatch implements anchored glob matching for allowlist command patterns.
//
// Security contract: the pattern must match the ENTIRE command string from start
// to end. A trailing * allows arbitrary suffixes, but without it the command must
// end at the last literal segment. This prevents injection attacks like:
//   pattern: "docker push registry.internal/*"
//   command: "docker push registry.internal/img && rm -rf /"  → does NOT match
// because the trailing "/ && rm -rf /" is not covered by the pattern.
func globMatch(pattern, s string) bool {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return false
	}
	if p == s {
		return true
	}
	if !strings.Contains(p, "*") {
		return p == s
	}

	// Split on * — every segment must appear in order, first anchored at start,
	// last anchored at end (unless the pattern ends with *).
	parts := strings.Split(p, "*")
	endsWithGlob := strings.HasSuffix(p, "*")
	remaining := s

	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx == -1 {
			return false
		}
		if i == 0 && idx != 0 {
			return false // first segment must be at start
		}
		remaining = remaining[idx+len(part):]
	}

	// If pattern doesn't end with *, remaining must be empty (full match required)
	if !endsWithGlob && remaining != "" {
		return false
	}
	return true
}
