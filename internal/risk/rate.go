package risk

import "context"

// RateSignal scores based on the sliding-window call rate.
type RateSignal struct{}

func (r RateSignal) Name() string { return "rate" }

func (r RateSignal) Score(_ context.Context, _ string, _ string, callsLastMinute int) float64 {
	switch {
	case callsLastMinute > 60:
		return 0.8
	case callsLastMinute > 30:
		return 0.5
	case callsLastMinute >= 10:
		return 0.2
	default:
		return 0.0
	}
}
