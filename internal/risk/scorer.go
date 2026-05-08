package risk

import "context"

// CompositeScorer combines multiple RiskSignals into a single weighted score.
type CompositeScorer struct {
	signals []RiskSignal
	weights map[string]float64
}

// NewCompositeScorer creates a CompositeScorer. Weights map signal names to
// multipliers; signals absent from the map default to weight 1.0.
func NewCompositeScorer(signals []RiskSignal, weights map[string]float64) *CompositeScorer {
	return &CompositeScorer{
		signals: signals,
		weights: weights,
	}
}

// Score computes the weighted average of all signals, clamped to [0, 1].
func (cs *CompositeScorer) Score(ctx context.Context, tool string, args string, callsLastMinute int) float64 {
	if len(cs.signals) == 0 {
		return 0
	}

	var weightedSum, totalWeight float64
	for _, sig := range cs.signals {
		w := 1.0
		if cs.weights != nil {
			if ww, ok := cs.weights[sig.Name()]; ok {
				w = ww
			}
		}
		weightedSum += sig.Score(ctx, tool, args, callsLastMinute) * w
		totalWeight += w
	}

	if totalWeight == 0 {
		return 0
	}

	score := weightedSum / totalWeight
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}
