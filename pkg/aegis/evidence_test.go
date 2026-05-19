package aegis

import (
	"strings"
	"testing"
	"time"
)

func TestEvidence_FormatsTree(t *testing.T) {
	now := time.Now()
	ev := []Evidence{
		{What: "read ~/.ssh/id_rsa", When: now.Add(-12 * time.Second)},
		{What: "curl to unknown host", When: now.Add(-2 * time.Second)},
	}
	out := FormatEvidence(ev)

	if !strings.Contains(out, "~/.ssh/id_rsa") {
		t.Errorf("missing ssh key in output:\n%s", out)
	}
	if !strings.Contains(out, "curl") {
		t.Errorf("missing curl in output:\n%s", out)
	}
	if !strings.Contains(out, "Decision evidence:") {
		t.Errorf("missing header in output:\n%s", out)
	}
}

func TestEvidence_Empty(t *testing.T) {
	out := FormatEvidence(nil)
	if !strings.Contains(out, "(none)") {
		t.Errorf("empty evidence should contain '(none)', got: %s", out)
	}
}
