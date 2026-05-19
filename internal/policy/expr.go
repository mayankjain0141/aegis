package policy

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// ExprCommand is a resolved command exposed to expr expressions.
type ExprCommand struct {
	Binary   string   `expr:"binary"`
	Args     []string `expr:"args"`
	FullPath string   `expr:"full_path"`
}

// ExprEnv is the variable environment exposed to expr expressions.
// All fields are exported (required by expr-lang).
type ExprEnv struct {
	ToolCategory     string        `expr:"tool_category"`
	Verbs            []string      `expr:"verbs"`
	Commands         []ExprCommand `expr:"commands"` // resolved command list for complex rule expressions
	Paths            []string      `expr:"paths"`    // normalized path strings
	MaxVerbDanger    float64       `expr:"max_verb_danger"`
	HasCritical      bool          `expr:"has_critical"`
	HasSensitive     bool          `expr:"has_sensitive"`
	AllInProject     bool          `expr:"all_in_project"`
	NetworkScore     float64       `expr:"network_score"`
	HasDataFlag      bool          `expr:"has_data_flag"`
	HasStdinPipe     bool          `expr:"has_stdin_pipe"`
	DLPHasHit        bool          `expr:"dlp_has_hit"`
	DLPAllTest       bool          `expr:"dlp_all_test"`
	EvasionScore     float64       `expr:"evasion_score"`
	EncodingDetected bool          `expr:"encoding_detected"`
	WrappersStripped int           `expr:"wrappers_stripped"`
	MLScore          float64       `expr:"ml_score"`
}

func bundleToEnv(b *signals.SignalBundle) ExprEnv {
	cmds := make([]ExprCommand, 0, len(b.Command.Commands))
	for _, c := range b.Command.Commands {
		cmds = append(cmds, ExprCommand{
			Binary:   c.Binary,
			Args:     c.Args,
			FullPath: c.FullPath,
		})
	}
	paths := make([]string, 0, len(b.Path.Paths))
	for _, p := range b.Path.Paths {
		paths = append(paths, p.Normalized)
	}
	return ExprEnv{
		ToolCategory:     b.ToolClass.Category,
		Verbs:            b.Command.Verbs,
		Commands:         cmds,
		Paths:            paths,
		MaxVerbDanger:    b.Command.MaxVerbDanger,
		HasCritical:      b.Path.HasCritical,
		HasSensitive:     b.Path.HasSensitive,
		AllInProject:     b.Path.AllInProject,
		NetworkScore:     b.Network.Score,
		HasDataFlag:      b.Network.HasDataFlag,
		HasStdinPipe:     b.Network.HasStdinPipe,
		DLPHasHit:        b.DLP.HasHit,
		DLPAllTest:       b.DLP.AllTest,
		EvasionScore:     b.Evasion.Score,
		EncodingDetected: b.Evasion.EncodingDetected,
		WrappersStripped: b.Evasion.WrappersStripped,
		MLScore:          b.MLScore,
	}
}

// hasPrefix is a helper available in expr expressions via the env.
// Exposed as a method on ExprEnv so expr-lang can find it.
func (ExprEnv) HasPrefix(s, prefix string) bool { return strings.HasPrefix(s, prefix) }
func (ExprEnv) HasSuffix(s, suffix string) bool { return strings.HasSuffix(s, suffix) }
func (ExprEnv) Contains(s, sub string) bool      { return strings.Contains(s, sub) }

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
