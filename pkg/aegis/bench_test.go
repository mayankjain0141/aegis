package aegis_test

import (
	"context"
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
)

func BenchmarkEngine_YAMLMode_StaticRule(b *testing.B) {
	engine, _ := aegis.NewEngine()
	req := &aegis.Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "rm -rf /etc"},
		CWD:       "/tmp",
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(ctx, req)
	}
}

func BenchmarkEngine_YAMLMode_AllowRule(b *testing.B) {
	engine, _ := aegis.NewEngine()
	req := &aegis.Request{
		Tool:      "Shell",
		Arguments: map[string]any{"command": "git status"},
		CWD:       "/tmp",
	}
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.Evaluate(ctx, req)
	}
}
