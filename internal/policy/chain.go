package policy

import "context"

// Evaluate runs the chain in order; first non-nil decision wins.
// If all evaluators return nil, default deny is returned.
func (chain EvaluatorChain) Evaluate(ctx context.Context, req *ToolCallRequest) (*PolicyDecision, error) {
	for _, evaluator := range chain {
		decision, err := evaluator.Evaluate(ctx, req)
		if err != nil {
			return nil, err
		}
		if decision != nil {
			return decision, nil
		}
	}
	return &PolicyDecision{
		Action: ActionDeny,
		Reason: "no policy matched (default deny)",
	}, nil
}
