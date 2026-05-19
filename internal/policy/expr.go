package policy

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// ExprEnv is the variable environment exposed to expr expressions.
// All fields are exported (required by expr-lang).
type ExprEnv struct {
	ToolCategory     string   `expr:"tool_category"`
	Verbs            []string `expr:"verbs"`
	MaxVerbDanger    float64  `expr:"max_verb_danger"`
	HasCritical      bool     `expr:"has_critical"`
	HasSensitive     bool     `expr:"has_sensitive"`
	AllInProject     bool     `expr:"all_in_project"`
	NetworkScore     float64  `expr:"network_score"`
	HasDataFlag      bool     `expr:"has_data_flag"`
	DLPHasHit        bool     `expr:"dlp_has_hit"`
	DLPAllTest       bool     `expr:"dlp_all_test"`
	EvasionScore     float64  `expr:"evasion_score"`
	EncodingDetected bool     `expr:"encoding_detected"`
	MLScore          float64  `expr:"ml_score"`
}

func bundleToEnv(b *signals.SignalBundle) ExprEnv {
	return ExprEnv{
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

// CompileExpr compiles an expr-lang expression string into a Predicate.
// The returned Predicate is safe for concurrent use.
func CompileExpr(expression string) (Predicate, error) {
	program, err := expr.Compile(expression, expr.Env(ExprEnv{}), expr.AsBool())
	if err != nil {
		return nil, fmt.Errorf("compile expr %q: %w", expression, err)
	}
	return func(b *signals.SignalBundle) bool {
		env := bundleToEnv(b)
		result, err := expr.Run(program, env)
		if err != nil {
			return false
		}
		v, ok := result.(bool)
		return ok && v
	}, nil
}
