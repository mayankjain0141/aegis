package policy

import (
	"context"
	"time"

	"github.com/mayjain/aegis/internal/extract"
)

const pipelineTimeout = 50 * time.Millisecond

// EnrichedRequest is assembled by the Pipeline before passing to Steps.
type EnrichedRequest struct {
	AgentID    string
	Tool       string
	Arguments  string
	RequestID  string
	SessionCtx *SessionContext

	// Populated from extraction
	Commands []extract.Command
	Paths    []string
	Hosts    []string
	ParseErr error

	// Populated by caller (Router computes risk score)
	RiskScore float64
}

// Step is a single evaluation stage in the policy pipeline.
type Step interface {
	Name() string
	Evaluate(ctx context.Context, req *EnrichedRequest) (*PolicyDecision, error)
}

// Pipeline owns the Extractor and orchestrates Steps.
// It implements PolicyEvaluator for compatibility with the existing chain.
type Pipeline struct {
	extractor *extract.Extractor
	steps     []Step
	fallback  Action

	// ShadowCompare, if set, is called after Pipeline produces a decision.
	// Used to compare Pipeline decisions vs StaticEvaluator during migration.
	ShadowCompare func(req *ToolCallRequest, pipelineDecision *PolicyDecision)
}

// NewPipeline creates a pipeline with the given extractor and fallback action.
func NewPipeline(ext *extract.Extractor, fallback Action) *Pipeline {
	return &Pipeline{
		extractor: ext,
		fallback:  fallback,
	}
}

// AddStep appends a step. Steps execute in insertion order.
func (p *Pipeline) AddStep(s Step) {
	p.steps = append(p.steps, s)
}

// Evaluate implements PolicyEvaluator so Pipeline can be used in the existing chain.
func (p *Pipeline) Evaluate(ctx context.Context, req *ToolCallRequest) (*PolicyDecision, error) {
	ctx, cancel := context.WithTimeout(ctx, pipelineTimeout)
	defer cancel()

	// Run extraction
	result := p.extractor.Extract(req.Tool, req.Arguments)

	// Build enriched request
	enriched := &EnrichedRequest{
		AgentID:    req.AgentID,
		Tool:       req.Tool,
		Arguments:  req.Arguments,
		RequestID:  req.RequestID,
		SessionCtx: req.SessionCtx,
		Commands:   result.Commands,
		Paths:      result.Paths,
		Hosts:      result.Hosts,
		ParseErr:   result.Err,
	}

	// Run steps in order
	for _, step := range p.steps {
		select {
		case <-ctx.Done():
			return &PolicyDecision{
				Action:     ActionDeny,
				PolicyName: "pipeline:timeout",
				Severity:   "high",
				Reason:     "policy evaluation timed out",
			}, nil
		default:
		}

		decision, err := step.Evaluate(ctx, enriched)
		if err != nil {
			continue // step errors are non-fatal; skip and continue
		}
		if decision != nil {
			if decision.PolicyName == "" {
				decision.PolicyName = step.Name()
			} else {
				decision.PolicyName = step.Name() + ":" + decision.PolicyName
			}
			return decision, nil
		}
	}

	// No step had an opinion — return nil so the chain continues to StaticEvaluator
	return nil, nil
}
