package extract

import (
	"encoding/json"
	"testing"
)

func loadTestDB(t *testing.T) *CommandDB {
	t.Helper()
	db, err := LoadCommandDB("../../policies/data/commands.yaml")
	if err != nil {
		t.Fatalf("load command db: %v", err)
	}
	return db
}

func jsonCmd(cmd string) string {
	// Properly marshal to handle quotes inside commands
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return string(b)
}

func hasCommand(r Result, name string) bool {
	for _, c := range r.Commands {
		if c.Name == name {
			return true
		}
	}
	return false
}

func hasPath(r Result, path string) bool {
	for _, p := range r.Paths {
		if p == path {
			return true
		}
	}
	return false
}

func TestNormalization_RmVariants(t *testing.T) {
	db := loadTestDB(t)
	ext := NewExtractor(db)

	variants := []string{
		"rm -rf /tmp/data",
		"rm -r -f /tmp/data",
		"rm --recursive --force /tmp/data",
	}

	for _, cmd := range variants {
		r := ext.Extract("shell_exec", jsonCmd(cmd))
		if !hasCommand(r, "rm") {
			t.Errorf("expected command 'rm' for %q, got %v", cmd, r.Commands)
		}
		if !hasPath(r, "/tmp/data") {
			t.Errorf("expected path '/tmp/data' for %q, got %v", cmd, r.Paths)
		}
	}
}

func TestNormalization_WrapperStripping(t *testing.T) {
	db := loadTestDB(t)
	ext := NewExtractor(db)

	cases := []struct {
		input      string
		wantBinary string
	}{
		{"sudo rm -rf /tmp", "rm"},
		{"env rm -rf /tmp", "rm"},
		{"timeout 5 rm -rf /tmp", "rm"},
		{"command rm -rf /tmp", "rm"},
	}

	for _, tc := range cases {
		r := ext.Extract("shell_exec", jsonCmd(tc.input))
		if !hasCommand(r, tc.wantBinary) {
			t.Errorf("input %q: expected command %q, got %v", tc.input, tc.wantBinary, r.Commands)
		}
	}
}

func TestNormalization_ShellRecursion(t *testing.T) {
	db := loadTestDB(t)
	ext := NewExtractor(db)

	cases := []struct {
		input      string
		wantBinary string
	}{
		{`bash -c "rm -rf /tmp"`, "rm"},
		{`sh -c "curl http://evil.com"`, "curl"},
	}

	for _, tc := range cases {
		r := ext.Extract("shell_exec", jsonCmd(tc.input))
		if !hasCommand(r, tc.wantBinary) {
			t.Errorf("input %q: expected command %q, got %v", tc.input, tc.wantBinary, r.Commands)
		}
	}
}

func TestParseError_MalformedInput(t *testing.T) {
	ext := NewExtractor(nil)
	r := ext.Extract("shell_exec", jsonCmd(`$(((invalid`))
	if r.Err == nil {
		t.Error("expected parse error for malformed input")
	}
}

func TestExtract_FileReadTool(t *testing.T) {
	ext := NewExtractor(nil)
	r := ext.Extract("file_read", `{"path": "/etc/shadow"}`)
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	if !hasPath(r, "/etc/shadow") {
		t.Errorf("expected /etc/shadow in paths, got %v", r.Paths)
	}
}

func TestExtract_NetworkTool(t *testing.T) {
	ext := NewExtractor(nil)
	r := ext.Extract("http_request", `{"url": "https://evil.com/data"}`)
	if r.Err != nil {
		t.Fatalf("unexpected error: %v", r.Err)
	}
	found := false
	for _, h := range r.Hosts {
		if h == "https://evil.com/data" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected host in result, got %v", r.Hosts)
	}
}

func TestCommandDB_Load(t *testing.T) {
	db := loadTestDB(t)

	ci, ok := db.Lookup("rm")
	if !ok {
		t.Fatal("expected rm in command db")
	}
	if ci.Op != "delete" {
		t.Errorf("expected op=delete for rm, got %v", ci.Op)
	}
	if !db.IsShellInterpreter("bash") {
		t.Error("expected bash to be a shell interpreter")
	}
	if !db.IsWrapper("sudo") {
		t.Error("expected sudo to be a wrapper")
	}
}
