package aegis

// Race condition tests — run with: go test -race ./pkg/aegis/
//
// These tests are designed to expose concurrent access bugs in the engine.
// They are expected to trigger the Go race detector if synchronisation is
// missing or incorrect. The tests themselves are valid Go and compile cleanly.

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

// TestEngine_ConcurrentEvaluate_Race launches 100 goroutines that all call
// engine.Evaluate simultaneously using 5 distinct AgentIDs so that the
// session map is read and written from many goroutines at once.
func TestEngine_ConcurrentEvaluate_Race(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	const goroutines = 100
	const agentCount = 5

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			agentID := fmt.Sprintf("agent-%d", i%agentCount)
			req := &Request{
				Tool:      "Shell",
				Arguments: map[string]any{"command": fmt.Sprintf("git status %d", i)},
				CWD:       "/tmp/project",
				AgentID:   agentID,
			}
			d := e.Evaluate(context.Background(), req)
			if d == nil {
				t.Errorf("goroutine %d: got nil decision", i)
			}
		}()
	}

	wg.Wait()
}

// TestEngine_ConcurrentAllowlistLoad_Race launches 50 goroutines each using a
// distinct CWD value (/tmp/project-N) so that allowlistForCWD suffers
// concurrent cache misses and multiple goroutines race to write the same key.
func TestEngine_ConcurrentAllowlistLoad_Race(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			cwd := fmt.Sprintf("/tmp/project-%d", i)
			req := &Request{
				Tool:      "Shell",
				Arguments: map[string]any{"command": "ls -la"},
				CWD:       cwd,
				AgentID:   fmt.Sprintf("agent-cwd-%d", i),
			}
			d := e.Evaluate(context.Background(), req)
			if d == nil {
				t.Errorf("goroutine %d: got nil decision for CWD %s", i, cwd)
			}
		}()
	}

	wg.Wait()
}

// TestEngine_ConcurrentBloomAndSession_Race launches 60 goroutines in two
// groups: 30 reuse the same command (bloom filter hit path) and 30 use novel
// commands (full evaluation path). All run concurrently to stress both the
// bloom filter read path and the session/behavioral analysis write path.
func TestEngine_ConcurrentBloomAndSession_Race(t *testing.T) {
	e, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Warm the bloom filter with a single well-known command so the first group
	// can hit the fast path. The canonical key is tool+args, so we call Evaluate
	// once with this command before the race starts.
	warmReq := &Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "git status"},
		CWD:       "/tmp/project",
		AgentID:   "warm-agent",
	}
	// Run sequentially first so the session recorder populates state.
	for i := 0; i < 3; i++ {
		e.Evaluate(context.Background(), warmReq)
	}

	const bloomGroup = 30
	const novelGroup = 30

	var wg sync.WaitGroup
	wg.Add(bloomGroup + novelGroup)

	// Group 1: same command every time — exercises bloom filter / allowlist fast
	// path concurrently. Shared AgentID stresses session read from many goroutines.
	for i := 0; i < bloomGroup; i++ {
		i := i
		go func() {
			defer wg.Done()
			req := &Request{
				Tool:      "Shell",
				Arguments: map[string]any{"command": "git status"},
				CWD:       "/tmp/project",
				AgentID:   "shared-bloom-agent",
			}
			d := e.Evaluate(context.Background(), req)
			if d == nil {
				t.Errorf("bloom goroutine %d: got nil decision", i)
			}
		}()
	}

	// Group 2: distinct novel commands — bypasses bloom and drives the full
	// static + behavioral evaluation, writing to the session store concurrently.
	for i := 0; i < novelGroup; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Use an unusual command string unlikely to be in the bloom filter.
			cmd := fmt.Sprintf("curl -s https://novel-host-%d.example.com/data", i)
			req := &Request{
				Tool:      "Shell",
				Arguments: map[string]any{"command": cmd},
				CWD:       "/tmp/project",
				AgentID:   fmt.Sprintf("novel-agent-%d", i%5),
			}
			d := e.Evaluate(context.Background(), req)
			if d == nil {
				t.Errorf("novel goroutine %d: got nil decision", i)
			}
		}()
	}

	wg.Wait()
}
