package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	// cmd/aegis/ is two levels below the repo root
	abs, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("repo root: %v", err)
	}
	return abs
}

func TestValidate_WellFormedDirectory(t *testing.T) {
	binary := buildAegis(t)
	root := repoRoot(t)

	cmd := exec.Command(binary, "validate", filepath.Join(root, "policies"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("validate should exit 0 for valid policies: %v\noutput: %s", err, out)
	}
}

func TestValidate_SingleValidFile(t *testing.T) {
	binary := buildAegis(t)
	root := repoRoot(t)

	cmd := exec.Command(binary, "validate", filepath.Join(root, "policies", "phase1-deny.yaml"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("validate should exit 0 for valid file: %v\noutput: %s", err, out)
	}
}

func TestValidate_InvalidFile_ExitsNonZero(t *testing.T) {
	binary := buildAegis(t)

	tmp, err := os.CreateTemp("", "bad-policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())

	// invalid_action is not a valid action
	tmp.WriteString(`rules:
  - name: bad
    action: invalid_action
    confidence: 0.9
    description: "bad rule"
    condition:
      any_verb: [rm]
`)
	tmp.Close()

	cmd := exec.Command(binary, "validate", tmp.Name())
	if cmd.Run() == nil {
		t.Error("validate should exit non-zero for invalid file")
	}
}

func TestValidate_MissingPath_ExitsNonZero(t *testing.T) {
	binary := buildAegis(t)

	cmd := exec.Command(binary, "validate", "/nonexistent/path/policies")
	if cmd.Run() == nil {
		t.Error("validate should exit non-zero for missing path")
	}
}

func buildAegis(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "aegis")
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build aegis: %v\n%s", err, out)
	}
	return binary
}
