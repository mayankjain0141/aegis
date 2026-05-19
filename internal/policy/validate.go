package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/agnivade/levenshtein"
	"gopkg.in/yaml.v3"
)

var validActions = []string{"deny", "allow", "escalate", "throttle"}
var validSeverities = []string{"critical", "high", "medium", "low", ""}

var knownConditionFields = []string{
	"any_verb", "all_verbs_safe", "tool_category",
	"path", "network", "dlp", "evasion", "verb_danger", "behavioral",
	"and", "or", "not",
	"expr", "rego", "rego_rule",
}

func validate(pf *PolicyFile) error {
	seen := make(map[string]bool)
	for _, r := range pf.Rules {
		if err := validateRule(r); err != nil {
			return err
		}
		if seen[r.Name] {
			return fmt.Errorf("duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true
	}
	return nil
}

func validateRule(r RuleDef) error {
	if r.Name == "" {
		return fmt.Errorf("rule missing required field \"name\"")
	}
	if r.Action == "" {
		return fmt.Errorf("rule %q: missing required field \"action\"", r.Name)
	}
	if r.Confidence == 0 {
		return fmt.Errorf("rule %q: missing required field \"confidence\"", r.Name)
	}
	if r.Description == "" {
		return fmt.Errorf("rule %q: missing required field \"description\"", r.Name)
	}
	if !contains(validActions, r.Action) {
		return fmt.Errorf("rule %q: invalid action %q (valid: %s)", r.Name, r.Action, strings.Join(validActions, ", "))
	}
	if !contains(validSeverities, r.Severity) {
		return fmt.Errorf("rule %q: invalid severity %q (valid: %s)", r.Name, r.Severity, strings.Join(validSeverities[0:len(validSeverities)-1], ", "))
	}
	return nil
}

func contains(list []string, val string) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

// conditionRaw is used to capture raw YAML keys for unknown-field detection.
type conditionRaw map[string]yaml.Node

// UnmarshalYAML on Condition validates keys and score fields before populating.
func (c *Condition) UnmarshalYAML(value *yaml.Node) error {
	// First pass: extract raw keys to check for unknowns
	raw := make(conditionRaw)
	if err := value.Decode(&raw); err != nil {
		return err
	}
	for key := range raw {
		if !isKnownConditionField(key) {
			suggestions := closestFields(key)
			if len(suggestions) > 0 {
				quoted := make([]string, len(suggestions))
				for i, s := range suggestions {
					quoted[i] = fmt.Sprintf("%q", s)
				}
				return fmt.Errorf("unknown field %q in condition (did you mean %s?)", key, strings.Join(quoted, " or "))
			}
			return fmt.Errorf("unknown field %q in condition", key)
		}
	}

	// Second pass: check bare numbers in score fields
	if netNode, ok := raw["network"]; ok {
		if err := checkScoreField("network", &netNode); err != nil {
			return err
		}
	}
	if evasionNode, ok := raw["evasion"]; ok {
		if err := checkScoreField("evasion", &evasionNode); err != nil {
			return err
		}
	}

	// Third pass: decode into a plain alias type to avoid infinite recursion
	type conditionAlias struct {
		AnyVerb      []string                 `yaml:"any_verb,omitempty"`
		AllVerbsSafe bool                     `yaml:"all_verbs_safe,omitempty"`
		ToolCategory interface{}              `yaml:"tool_category,omitempty"`
		Path         *PathCond                `yaml:"path,omitempty"`
		Network      *NetworkCond             `yaml:"network,omitempty"`
		DLP          *DLPCond                 `yaml:"dlp,omitempty"`
		Evasion      *EvasionCond             `yaml:"evasion,omitempty"`
		VerbDanger   map[string]ThresholdCond `yaml:"verb_danger,omitempty"`
		Behavioral   *BehavioralCond          `yaml:"behavioral,omitempty"`
		And          []Condition              `yaml:"and,omitempty"`
		Or           []Condition              `yaml:"or,omitempty"`
		Not          *Condition               `yaml:"not,omitempty"`
		Expr         string                   `yaml:"expr,omitempty"`
		Rego         string                   `yaml:"rego,omitempty"`
		RegoRule     string                   `yaml:"rego_rule,omitempty"`
	}
	var alias conditionAlias
	if err := value.Decode(&alias); err != nil {
		return err
	}
	c.AnyVerb = alias.AnyVerb
	c.AllVerbsSafe = alias.AllVerbsSafe
	c.ToolCategory = alias.ToolCategory
	c.Path = alias.Path
	c.Network = alias.Network
	c.DLP = alias.DLP
	c.Evasion = alias.Evasion
	c.VerbDanger = alias.VerbDanger
	c.Behavioral = alias.Behavioral
	c.And = alias.And
	c.Or = alias.Or
	c.Not = alias.Not
	c.Expr = alias.Expr
	c.Rego = alias.Rego
	c.RegoRule = alias.RegoRule
	return nil
}

// checkScoreField validates that score fields use operator form { gt: N }, not bare numbers.
func checkScoreField(parent string, node *yaml.Node) error {
	// Decode the sub-map to look for a "score" key
	subRaw := make(map[string]yaml.Node)
	if err := node.Decode(&subRaw); err != nil {
		return nil // not a map, skip
	}
	scoreNode, ok := subRaw["score"]
	if !ok {
		return nil
	}
	// If the score node is a scalar (number), it's a bare number — reject it
	if scoreNode.Kind == yaml.ScalarNode {
		return fmt.Errorf("%s.score requires operator form, e.g. { gt: 0.5 } — got bare number", parent)
	}
	return nil
}

func isKnownConditionField(key string) bool {
	for _, f := range knownConditionFields {
		if f == key {
			return true
		}
	}
	return false
}

// closestFields returns the top-N known condition fields closest to unknown.
// Uses token-level Levenshtein distance (threshold: distance ≤ 1 on any token,
// or overall distance ≤ 5). Returns up to 2 suggestions, deduplicated.
func closestFields(unknown string) []string {
	type scored struct {
		field     string
		tokenDist int
		fullDist  int
	}
	var candidates []scored
	for _, f := range knownConditionFields {
		tokens := strings.Split(f, "_")
		minTokD := 1<<31 - 1
		for _, tok := range tokens {
			if d := levenshtein.ComputeDistance(unknown, tok); d < minTokD {
				minTokD = d
			}
		}
		fullD := levenshtein.ComputeDistance(unknown, f)
		if minTokD <= 1 || fullD <= 5 {
			candidates = append(candidates, scored{f, minTokD, fullD})
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	// Sort: primary by tokenDist, secondary by fullDist, tertiary by field length
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].tokenDist != candidates[j].tokenDist {
			return candidates[i].tokenDist < candidates[j].tokenDist
		}
		if candidates[i].fullDist != candidates[j].fullDist {
			return candidates[i].fullDist < candidates[j].fullDist
		}
		return len(candidates[i].field) < len(candidates[j].field)
	})
	// Return up to 2
	out := []string{candidates[0].field}
	if len(candidates) > 1 && candidates[1].field != candidates[0].field {
		out = append(out, candidates[1].field)
	}
	return out
}
