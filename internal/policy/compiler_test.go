package policy_test

import (
	"testing"

	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// bundleBuilder builds SignalBundle test fixtures cleanly.
type bundleBuilder struct {
	b signals.SignalBundle
}

func newBundle() *bundleBuilder { return &bundleBuilder{} }

func (b *bundleBuilder) WithVerbs(verbs ...string) *bundleBuilder {
	b.b.Command.Verbs = verbs
	return b
}

func (b *bundleBuilder) WithCategory(cat string) *bundleBuilder {
	b.b.ToolClass.Category = cat
	return b
}

func (b *bundleBuilder) WithCriticalPath(v bool) *bundleBuilder {
	b.b.Path.HasCritical = v
	return b
}

func (b *bundleBuilder) WithSensitivePath(v bool) *bundleBuilder {
	b.b.Path.HasSensitive = v
	return b
}

func (b *bundleBuilder) WithAllInProject(v bool) *bundleBuilder {
	b.b.Path.AllInProject = v
	return b
}

func (b *bundleBuilder) WithDLP(hasHit, allTest bool) *bundleBuilder {
	b.b.DLP.HasHit = hasHit
	b.b.DLP.AllTest = allTest
	return b
}

func (b *bundleBuilder) WithNetworkScore(score float64) *bundleBuilder {
	b.b.Network.Score = score
	return b
}

func (b *bundleBuilder) WithDataFlag(v bool) *bundleBuilder {
	b.b.Network.HasDataFlag = v
	return b
}

func (b *bundleBuilder) WithEvasion(encoding bool, score float64) *bundleBuilder {
	b.b.Evasion.EncodingDetected = encoding
	b.b.Evasion.Score = score
	return b
}

func (b *bundleBuilder) WithVerbDanger(verb string, danger float64) *bundleBuilder {
	if b.b.Command.VerbDanger == nil {
		b.b.Command.VerbDanger = make(map[string]float64)
	}
	b.b.Command.VerbDanger[verb] = danger
	if danger > b.b.Command.MaxVerbDanger {
		b.b.Command.MaxVerbDanger = danger
	}
	return b
}

func (b *bundleBuilder) Build() *signals.SignalBundle { return &b.b }

func ptr[T any](v T) *T { return &v }

func TestCompile_AnyVerb(t *testing.T) {
	tests := []struct {
		name   string
		cond   policy.Condition
		bundle *signals.SignalBundle
		want   bool
	}{
		{
			"verb matches",
			policy.Condition{AnyVerb: []string{"rm", "mkfs"}},
			newBundle().WithVerbs("ls", "rm").Build(),
			true,
		},
		{
			"no match",
			policy.Condition{AnyVerb: []string{"rm", "mkfs"}},
			newBundle().WithVerbs("ls", "cat").Build(),
			false,
		},
		{
			"empty any_verb never matches",
			policy.Condition{AnyVerb: []string{}},
			newBundle().WithVerbs("rm").Build(),
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(tc.cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got := cr(tc.bundle)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompile_ToolCategory(t *testing.T) {
	tests := []struct {
		name   string
		cat    interface{}
		bundle *signals.SignalBundle
		want   bool
	}{
		{"exact match", "shell", newBundle().WithCategory("shell").Build(), true},
		{"no match", "shell", newBundle().WithCategory("file_read").Build(), false},
		{"multi-value match", []interface{}{"file_read", "file_write"}, newBundle().WithCategory("file_read").Build(), true},
		{"multi-value no match", []interface{}{"file_read", "file_write"}, newBundle().WithCategory("shell").Build(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(policy.Condition{ToolCategory: tc.cat})
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			got := cr(tc.bundle)
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCompile_PathConditions(t *testing.T) {
	tests := []struct {
		name   string
		cond   policy.Condition
		bundle *signals.SignalBundle
		want   bool
	}{
		{
			"has_critical true matches",
			policy.Condition{Path: &policy.PathCond{HasCritical: ptr(true)}},
			newBundle().WithCriticalPath(true).Build(),
			true,
		},
		{
			"has_critical true no match",
			policy.Condition{Path: &policy.PathCond{HasCritical: ptr(true)}},
			newBundle().WithCriticalPath(false).Build(),
			false,
		},
		{
			"has_sensitive true matches",
			policy.Condition{Path: &policy.PathCond{HasSensitive: ptr(true)}},
			newBundle().WithSensitivePath(true).Build(),
			true,
		},
		{
			"all_in_project false matches when false",
			policy.Condition{Path: &policy.PathCond{AllInProject: ptr(false)}},
			newBundle().WithAllInProject(false).Build(),
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(tc.cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.bundle) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.bundle), tc.want)
			}
		})
	}
}

func TestCompile_DLP(t *testing.T) {
	tests := []struct {
		name   string
		cond   policy.Condition
		bundle *signals.SignalBundle
		want   bool
	}{
		{
			"has_hit=true,all_test=false triggers",
			policy.Condition{DLP: &policy.DLPCond{HasHit: ptr(true), AllTest: ptr(false)}},
			newBundle().WithDLP(true, false).Build(),
			true,
		},
		{
			"has_hit=true,all_test=true does not trigger",
			policy.Condition{DLP: &policy.DLPCond{HasHit: ptr(true), AllTest: ptr(false)}},
			newBundle().WithDLP(true, true).Build(),
			false,
		},
		{
			"has_hit=false does not trigger",
			policy.Condition{DLP: &policy.DLPCond{HasHit: ptr(true)}},
			newBundle().WithDLP(false, false).Build(),
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(tc.cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.bundle) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.bundle), tc.want)
			}
		})
	}
}

func TestCompile_Network(t *testing.T) {
	tests := []struct {
		name   string
		cond   policy.Condition
		bundle *signals.SignalBundle
		want   bool
	}{
		{
			"score threshold matched",
			policy.Condition{Network: &policy.NetworkCond{ScoreGt: ptr(0.5)}},
			newBundle().WithNetworkScore(0.7).Build(),
			true,
		},
		{
			"score threshold not matched",
			policy.Condition{Network: &policy.NetworkCond{ScoreGt: ptr(0.5)}},
			newBundle().WithNetworkScore(0.3).Build(),
			false,
		},
		{
			"has_data_flag matched",
			policy.Condition{Network: &policy.NetworkCond{HasDataFlag: ptr(true)}},
			newBundle().WithDataFlag(true).Build(),
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(tc.cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.bundle) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.bundle), tc.want)
			}
		})
	}
}

func TestCompile_Evasion(t *testing.T) {
	tests := []struct {
		name   string
		cond   policy.Condition
		bundle *signals.SignalBundle
		want   bool
	}{
		{
			"encoding_detected matches",
			policy.Condition{Evasion: &policy.EvasionCond{EncodingDetected: ptr(true)}},
			newBundle().WithEvasion(true, 0.5).Build(),
			true,
		},
		{
			"encoding_detected not set",
			policy.Condition{Evasion: &policy.EvasionCond{EncodingDetected: ptr(true)}},
			newBundle().WithEvasion(false, 0.5).Build(),
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(tc.cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.bundle) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.bundle), tc.want)
			}
		})
	}
}

func TestCompile_VerbDanger(t *testing.T) {
	tests := []struct {
		name   string
		cond   policy.Condition
		bundle *signals.SignalBundle
		want   bool
	}{
		{
			"dd gt 0 matches",
			policy.Condition{VerbDanger: map[string]policy.ThresholdCond{"dd": {Gt: ptr(0.0)}}},
			newBundle().WithVerbDanger("dd", 0.95).Build(),
			true,
		},
		{
			"dd gt 0 no match when absent",
			policy.Condition{VerbDanger: map[string]policy.ThresholdCond{"dd": {Gt: ptr(0.0)}}},
			newBundle().Build(),
			false,
		},
		{
			"danger gte threshold",
			policy.Condition{VerbDanger: map[string]policy.ThresholdCond{"rm": {Gte: ptr(0.8)}}},
			newBundle().WithVerbDanger("rm", 0.8).Build(),
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(tc.cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.bundle) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.bundle), tc.want)
			}
		})
	}
}

func TestCompile_And(t *testing.T) {
	cond := policy.Condition{And: []policy.Condition{
		{AnyVerb: []string{"rm"}},
		{Path: &policy.PathCond{HasCritical: ptr(true)}},
	}}
	tests := []struct {
		name string
		b    *signals.SignalBundle
		want bool
	}{
		{"both true", newBundle().WithVerbs("rm").WithCriticalPath(true).Build(), true},
		{"first true only", newBundle().WithVerbs("rm").WithCriticalPath(false).Build(), false},
		{"second true only", newBundle().WithVerbs("ls").WithCriticalPath(true).Build(), false},
		{"both false", newBundle().WithVerbs("ls").WithCriticalPath(false).Build(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.b) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.b), tc.want)
			}
		})
	}
}

func TestCompile_Or(t *testing.T) {
	cond := policy.Condition{Or: []policy.Condition{
		{AnyVerb: []string{"rm"}},
		{AnyVerb: []string{"mkfs"}},
	}}
	tests := []struct {
		name string
		b    *signals.SignalBundle
		want bool
	}{
		{"first matches", newBundle().WithVerbs("rm").Build(), true},
		{"second matches", newBundle().WithVerbs("mkfs").Build(), true},
		{"neither matches", newBundle().WithVerbs("ls").Build(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.b) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.b), tc.want)
			}
		})
	}
}

func TestCompile_Not(t *testing.T) {
	cond := policy.Condition{Not: &policy.Condition{AnyVerb: []string{"rm"}}}
	tests := []struct {
		name string
		b    *signals.SignalBundle
		want bool
	}{
		{"inverts true to false", newBundle().WithVerbs("rm").Build(), false},
		{"inverts false to true", newBundle().WithVerbs("ls").Build(), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.b) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.b), tc.want)
			}
		})
	}
}

func TestCompile_NestedConditions(t *testing.T) {
	// (rm AND critical) OR (mkfs AND sensitive)
	cond := policy.Condition{Or: []policy.Condition{
		{And: []policy.Condition{
			{AnyVerb: []string{"rm"}},
			{Path: &policy.PathCond{HasCritical: ptr(true)}},
		}},
		{And: []policy.Condition{
			{AnyVerb: []string{"mkfs"}},
			{Path: &policy.PathCond{HasSensitive: ptr(true)}},
		}},
	}}
	tests := []struct {
		name string
		b    *signals.SignalBundle
		want bool
	}{
		{"rm+critical", newBundle().WithVerbs("rm").WithCriticalPath(true).Build(), true},
		{"mkfs+sensitive", newBundle().WithVerbs("mkfs").WithSensitivePath(true).Build(), true},
		{"rm+sensitive (wrong combo)", newBundle().WithVerbs("rm").WithSensitivePath(true).Build(), false},
		{"nothing", newBundle().WithVerbs("ls").Build(), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr, err := policy.Compile(cond)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if cr(tc.b) != tc.want {
				t.Errorf("got %v, want %v", cr(tc.b), tc.want)
			}
		})
	}
}
