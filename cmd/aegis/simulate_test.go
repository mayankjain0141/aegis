package main_test

import (
	"os/exec"
	"strings"
	"testing"
)

func TestSimulate_DenyCommand(t *testing.T) {
	binary := buildAegis(t)
	cmd := exec.Command(binary, "simulate", "--tool", "Shell", "--command", "rm -rf /etc")
	cmd.Dir = "."
	out, _ := cmd.CombinedOutput()
	outStr := string(out)
	if !strings.Contains(strings.ToLower(outStr), "deny") {
		t.Errorf("simulate rm -rf /etc should show deny, got: %s", outStr)
	}
}

func TestSimulate_AllowCommand(t *testing.T) {
	binary := buildAegis(t)
	cmd := exec.Command(binary, "simulate", "--tool", "Shell", "--command", "git status")
	cmd.Dir = "."
	out, _ := cmd.CombinedOutput()
	outStr := string(out)
	if !strings.Contains(strings.ToLower(outStr), "allow") {
		t.Errorf("simulate git status should show allow, got: %s", outStr)
	}
}

func TestSimulate_ShowsSignals(t *testing.T) {
	binary := buildAegis(t)
	cmd := exec.Command(binary, "simulate", "--tool", "Shell", "--command", "rm -rf /")
	cmd.Dir = "."
	out, _ := cmd.CombinedOutput()
	outStr := string(out)
	if !strings.Contains(outStr, "Signals:") {
		t.Errorf("simulate should print Signals section, got: %s", outStr)
	}
}

func TestSimulate_MissingCommand_ExitsNonZero(t *testing.T) {
	binary := buildAegis(t)
	cmd := exec.Command(binary, "simulate", "--tool", "Shell")
	if cmd.Run() == nil {
		t.Error("simulate without --command should exit non-zero")
	}
}
