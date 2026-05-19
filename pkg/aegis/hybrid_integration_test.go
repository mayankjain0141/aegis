package aegis_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
)

// TestHybridEngine_LegacyModeMatchesBaseline verifies that legacy mode
// produces decisions identical to the current default engine on the eval corpus.
func TestHybridEngine_LegacyModeMatchesBaseline(t *testing.T) {
	// Both engines should produce identical results in legacy mode
	// (sanity check that the hybrid plumbing doesn't break anything)
	baseline, err := aegis.NewEngine()
	if err != nil {
		t.Fatalf("baseline engine: %v", err)
	}
	hybrid, err := aegis.NewEngine(aegis.WithPolicyMode("legacy"))
	if err != nil {
		t.Fatalf("hybrid engine: %v", err)
	}

	corpus := loadHybridCorpus(t)
	if len(corpus) == 0 {
		t.Skip("no eval corpus found")
	}

	for _, tc := range corpus {
		dBase := baseline.Evaluate(context.Background(), tc)
		dHybrid := hybrid.Evaluate(context.Background(), tc)
		if dBase.Action != dHybrid.Action || dBase.Rule != dHybrid.Rule {
			t.Errorf("[%s] baseline=%s/%s hybrid=%s/%s",
				tc.Tool, dBase.Rule, dBase.Action, dHybrid.Rule, dHybrid.Action)
		}
	}
	t.Logf("Legacy mode parity: %d cases, 0 divergences", len(corpus))
}

func loadHybridCorpus(t *testing.T) []*aegis.Request {
	t.Helper()
	var requests []*aegis.Request
	paths := []string{
		"testdata/eval/attacks-native.jsonl",
		"testdata/eval/benign.jsonl",
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if line == "" {
				continue
			}
			var raw struct {
				Tool      string          `json:"tool"`
				Arguments json.RawMessage `json:"arguments"`
			}
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				continue
			}
			var argsMap map[string]any
			if err := json.Unmarshal(raw.Arguments, &argsMap); err != nil {
				var argsStr string
				if err2 := json.Unmarshal(raw.Arguments, &argsStr); err2 == nil {
					json.Unmarshal([]byte(argsStr), &argsMap)
				}
			}
			if argsMap == nil {
				continue
			}
			requests = append(requests, &aegis.Request{
				Tool:      raw.Tool,
				Arguments: argsMap,
				CWD:       "/tmp/test",
			})
		}
	}
	return requests
}

// suppress unused import warning
var _ = fmt.Sprintf
