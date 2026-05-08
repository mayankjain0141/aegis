package risk

import "context"

// RiskSignal computes an independent risk contribution for a tool call.
type RiskSignal interface {
	Name() string
	Score(ctx context.Context, tool string, args string, callsLastMinute int) float64
}
