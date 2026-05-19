package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// OPAInput is the document passed to Rego policies as `input`.
// Flattened from SignalBundle for ergonomic policy authoring.
type OPAInput struct {
	ToolCategory     string   `json:"tool_category"`
	Verbs            []string `json:"verbs"`
	MaxVerbDanger    float64  `json:"max_verb_danger"`
	HasCritical      bool     `json:"has_critical"`
	HasSensitive     bool     `json:"has_sensitive"`
	AllInProject     bool     `json:"all_in_project"`
	NetworkScore     float64  `json:"network_score"`
	HasDataFlag      bool     `json:"has_data_flag"`
	DLPHasHit        bool     `json:"dlp_has_hit"`
	DLPAllTest       bool     `json:"dlp_all_test"`
	EvasionScore     float64  `json:"evasion_score"`
	EncodingDetected bool     `json:"encoding_detected"`
	MLScore          float64  `json:"ml_score"`
}

func bundleToOPAInput(b *signals.SignalBundle) OPAInput {
	return OPAInput{
		ToolCategory:     b.ToolClass.Category,
		Verbs:            b.Command.Verbs,
		MaxVerbDanger:    b.Command.MaxVerbDanger,
		HasCritical:      b.Path.HasCritical,
		HasSensitive:     b.Path.HasSensitive,
		AllInProject:     b.Path.AllInProject,
		NetworkScore:     b.Network.Score,
		HasDataFlag:      b.Network.HasDataFlag,
		DLPHasHit:        b.DLP.HasHit,
		DLPAllTest:       b.DLP.AllTest,
		EvasionScore:     b.Evasion.Score,
		EncodingDetected: b.Evasion.EncodingDetected,
		MLScore:          b.MLScore,
	}
}

// CompileRego compiles a Rego policy source and rule query into a Predicate.
// ruleQuery must be the full data path, e.g. "data.aegis.policy.deny".
// Returns true when the rule is defined and truthy. Fails open on eval errors.
// Performance note: OPA evaluation is ~1-5ms; suitable for Tier 3 custom policies only.
func CompileRego(regoSource, ruleQuery string) (Predicate, error) {
	// Pre-compile to catch syntax/parse errors at load time.
	_, err := rego.New(
		rego.Query(ruleQuery),
		rego.Module("policy.rego", regoSource),
		rego.Input(map[string]interface{}{}),
	).PrepareForEval(context.Background())
	if err != nil {
		return nil, fmt.Errorf("compile rego: %w", err)
	}

	return func(b *signals.SignalBundle) bool {
		input := bundleToOPAInput(b)

		inputData, err := json.Marshal(input)
		if err != nil {
			return false
		}
		var inputMap map[string]interface{}
		if err := json.Unmarshal(inputData, &inputMap); err != nil {
			return false
		}

		r := rego.New(
			rego.Query(ruleQuery),
			rego.Module("policy.rego", regoSource),
			rego.Input(inputMap),
		)
		rs, err := r.Eval(context.Background())
		if err != nil {
			return false // fail-open: don't block on OPA eval error
		}
		if len(rs) == 0 || len(rs[0].Expressions) == 0 {
			return false
		}
		switch v := rs[0].Expressions[0].Value.(type) {
		case bool:
			return v
		case map[string]interface{}:
			return len(v) > 0
		default:
			return false
		}
	}, nil
}
