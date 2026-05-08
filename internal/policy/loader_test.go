package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFromFile_ValidYAML(t *testing.T) {
	yaml := `
version: "load-test-v1"
policies:
  - name: allow-all
    match:
      tool: "*"
    action: allow
    severity: low
`
	path := writeTempYAML(t, yaml)
	eval, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.Version() != "load-test-v1" {
		t.Errorf("version: got %q, want %q", eval.Version(), "load-test-v1")
	}
	if eval.RuleCount() != 1 {
		t.Errorf("rules: got %d, want 1", eval.RuleCount())
	}
}

func TestLoadFromFile_InvalidYAML_ReturnsError(t *testing.T) {
	path := writeTempYAML(t, `{{{not valid yaml`)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFromFile_InvalidRegex_ReturnsError(t *testing.T) {
	yaml := `
version: "bad-regex"
policies:
  - name: bad
    match:
      tool: shell_exec
      args_pattern: "[invalid(regex"
    action: deny
`
	path := writeTempYAML(t, yaml)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestLoadFromFile_InvalidAction_ReturnsError(t *testing.T) {
	yaml := `
version: "bad-action"
policies:
  - name: bad
    match:
      tool: "*"
    action: explode
`
	path := writeTempYAML(t, yaml)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestLoadFromFile_EmptyFile_DefaultDeny(t *testing.T) {
	yaml := `
version: "empty"
policies: []
`
	path := writeTempYAML(t, yaml)
	eval, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", eval.RuleCount())
	}
}

func TestLoadFromFile_FileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFromFile_RealDefaultYAML(t *testing.T) {
	path := filepath.Join("..", "..", "policies", "default.yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("policies/default.yaml not found, skipping")
	}
	eval, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("failed to load default.yaml: %v", err)
	}
	if eval.Version() == "" {
		t.Error("expected non-empty version")
	}
	if eval.RuleCount() == 0 {
		t.Error("expected at least one rule")
	}
}

func TestHotReloader_Current(t *testing.T) {
	eval, _ := parseYAML([]byte(`
version: "v1"
policies:
  - name: allow-all
    match:
      tool: "*"
    action: allow
`))
	reloader := NewHotReloader(eval)
	if reloader.Current().Version() != "v1" {
		t.Errorf("expected v1, got %q", reloader.Current().Version())
	}

	eval2, _ := parseYAML([]byte(`
version: "v2"
policies:
  - name: deny-all
    match:
      tool: "*"
    action: deny
`))
	reloader.evaluator.Store(eval2)
	if reloader.Current().Version() != "v2" {
		t.Errorf("expected v2, got %q", reloader.Current().Version())
	}
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	return path
}
