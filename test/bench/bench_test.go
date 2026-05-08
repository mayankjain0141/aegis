package bench_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/mayjain/aegis/internal/ipc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/internal/risk"
	"github.com/mayjain/aegis/internal/trace"
)

func BenchmarkPolicyEval(b *testing.B) {
	evaluator, err := policy.LoadFromFile("../../policies/default.yaml")
	if err != nil {
		b.Fatal(err)
	}

	req := &policy.ToolCallRequest{
		AgentID:   "bench-agent",
		Tool:      "shell_exec",
		Arguments: `{"command":"ls -la /tmp"}`,
		RequestID: "bench-req",
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.Evaluate(ctx, req)
	}
}

func BenchmarkPolicyEval_Dangerous(b *testing.B) {
	evaluator, err := policy.LoadFromFile("../../policies/default.yaml")
	if err != nil {
		b.Fatal(err)
	}

	req := &policy.ToolCallRequest{
		AgentID:   "bench-agent",
		Tool:      "shell_exec",
		Arguments: `{"command":"rm -rf /"}`,
		RequestID: "bench-req",
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		evaluator.Evaluate(ctx, req)
	}
}

func BenchmarkRiskScore(b *testing.B) {
	scorer := risk.NewCompositeScorer(
		[]risk.RiskSignal{
			risk.ToolClassificationSignal{},
			risk.ArgPatternSignal{},
			risk.RateSignal{},
		},
		nil,
	)

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.Score(ctx, "shell_exec", `{"command":"ls -la"}`, 5)
	}
}

func BenchmarkTraceEmit(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	collector := trace.NewBatchCollector(nil, logger)
	defer collector.Close()

	event := &trace.TraceEvent{
		RequestID: "bench",
		AgentID:   "bench",
		Tool:      "shell_exec",
		RiskScore: 0.2,
		Decision:  "allow",
		Mode:      "enforce",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.Emit(event)
	}
}

func BenchmarkIPC_EnvelopeRoundTrip(b *testing.B) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	env := &ipc.AegisEnvelope{
		Type:       "mcp_request",
		ShimID:     "bench-shim",
		AgentID:    "bench-agent",
		RequestID:  "bench-req",
		MCPMessage: []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell_exec","arguments":{"command":"ls"}},"id":1}`),
	}

	go func() {
		for i := 0; i < b.N; i++ {
			_, err := ipc.ReadEnvelope(server)
			if err != nil {
				return
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ipc.WriteEnvelope(client, env); err != nil {
			b.Fatal(err)
		}
	}
}
