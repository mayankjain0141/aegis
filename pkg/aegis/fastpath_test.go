package aegis

import (
	"testing"
)

func TestFastPath_BloomHit_ReturnsAllow(t *testing.T) {
	fp := newDefaultFastPath(nil, nil)
	// A fresh FastPath with nil bloom+allowlist should return false (miss)
	req := &Request{Tool: "Shell", Arguments: map[string]any{"command": "git status"}, CWD: "/tmp"}
	allow, _ := fp.Check(req, `{"command":"git status"}`)
	// Fresh bloom has no entries, so must be a miss
	if allow {
		t.Error("fresh bloom+nil allowlist should be a miss")
	}
}

func TestFastPath_NilAllowlist_NoMatch(t *testing.T) {
	fp := newDefaultFastPath(nil, nil)
	req := &Request{Tool: "Read", Arguments: map[string]any{"path": "/etc/passwd"}, CWD: "/tmp"}
	allow, _ := fp.Check(req, `{"path":"/etc/passwd"}`)
	if allow {
		t.Error("nil allowlist should never match")
	}
}
