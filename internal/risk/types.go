package risk

import "context"

// RiskSignal computes an independent risk contribution for a tool call.
type RiskSignal interface {
	Name() string
	Score(ctx context.Context, tool string, args string, callsLastMinute int) float64
}

// CompositeScorer combines multiple risk signals with weights.
type CompositeScorer struct {
	Signals []RiskSignal
	Weights map[string]float64 // signal name → weight (default 1.0)
}
