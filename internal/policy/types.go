package policy

// PolicyFile is the top-level structure of a policy YAML file.
type PolicyFile struct {
	Version string    `yaml:"version,omitempty"`
	Rules   []RuleDef `yaml:"rules"`
}

// RuleDef is a single rule in a policy file.
type RuleDef struct {
	Name        string    `yaml:"name"`
	Priority    int       `yaml:"priority"`
	Action      string    `yaml:"action"`      // deny | allow | escalate | throttle
	Severity    string    `yaml:"severity"`    // critical | high | medium | low | ""
	Confidence  float64   `yaml:"confidence"`
	Description string    `yaml:"description"` // REQUIRED for all rules
	Remediation string    `yaml:"remediation,omitempty"`
	Tags        []string  `yaml:"tags,omitempty"`
	Condition   Condition `yaml:"condition"`
}

// Condition is the rule condition DSL — Tier 1: declarative fields.
type Condition struct {
	// Tier 1: Declarative
	AnyVerb      []string                 `yaml:"any_verb,omitempty"`
	AllVerbsSafe bool                     `yaml:"all_verbs_safe,omitempty"`
	ToolCategory interface{}              `yaml:"tool_category,omitempty"` // string or []string
	Path         *PathCond                `yaml:"path,omitempty"`
	Network      *NetworkCond             `yaml:"network,omitempty"`
	DLP          *DLPCond                 `yaml:"dlp,omitempty"`
	Evasion      *EvasionCond             `yaml:"evasion,omitempty"`
	VerbDanger   map[string]ThresholdCond `yaml:"verb_danger,omitempty"`

	// Combinators
	And []Condition `yaml:"and,omitempty"`
	Or  []Condition `yaml:"or,omitempty"`
	Not *Condition  `yaml:"not,omitempty"`

	// Tier 2: Expr
	Expr string `yaml:"expr,omitempty"`

	// Tier 3: Rego
	Rego     string `yaml:"rego,omitempty"`
	RegoRule string `yaml:"rego_rule,omitempty"`
}

// PathCond is the path sub-condition.
type PathCond struct {
	HasCritical  *bool `yaml:"has_critical,omitempty"`
	HasSensitive *bool `yaml:"has_sensitive,omitempty"`
	AllInProject *bool `yaml:"all_in_project,omitempty"`
}

// NetworkCond is the network sub-condition.
type NetworkCond struct {
	ScoreGt      *float64    `yaml:"-"` // parsed from { gt: N }
	HasDataFlag  *bool       `yaml:"has_data_flag,omitempty"`
	HasStdinPipe *bool       `yaml:"has_stdin_pipe,omitempty"`
	// Raw threshold — validated to require operator form { gt: N }
	Score interface{} `yaml:"score,omitempty"`
}

// DLPCond is the DLP sub-condition.
type DLPCond struct {
	HasHit  *bool `yaml:"has_hit,omitempty"`
	AllTest *bool `yaml:"all_test,omitempty"`
}

// EvasionCond is the evasion sub-condition.
type EvasionCond struct {
	EncodingDetected *bool       `yaml:"encoding_detected,omitempty"`
	ScoreGt          *float64    `yaml:"-"` // parsed from { gt: N }
	Score            interface{} `yaml:"score,omitempty"`
}

// ThresholdCond represents a threshold comparison like { gt: 0.5 }.
type ThresholdCond struct {
	Gt  *float64 `yaml:"gt,omitempty"`
	Gte *float64 `yaml:"gte,omitempty"`
	Lt  *float64 `yaml:"lt,omitempty"`
	Lte *float64 `yaml:"lte,omitempty"`
}
