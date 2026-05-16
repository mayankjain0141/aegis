// Package sequences defines known-bad multi-call attack patterns for Phase 2.
package sequences

import "time"

// SequencePattern describes a multi-step attack sequence.
type SequencePattern struct {
	Name    string
	Steps   []StepMatch
	Window  time.Duration // all steps must occur within this window
	Require int           // minimum steps that must match (0 = all)
}

// StepMatch describes what a single call in a sequence must look like.
type StepMatch struct {
	ToolCategory  string // "shell", "file_read", "file_write", etc.
	VerbHint      string // primary verb (optional, for logging)
	PathSensitive bool   // path must be sensitive
	PathCritical  bool   // path must be critical
	NetworkWrite  bool   // must have network write activity
	DLPHit        bool   // must have DLP hit
	DecisionDeny  bool   // must have been denied
	SameVerb      bool   // same verb as previous denied call
}

// KnownBadSequences are the multi-step attack patterns for Phase 2 detection.
var KnownBadSequences = []SequencePattern{
	{
		Name:   "exfil_after_sensitive_read",
		Window: 30 * time.Second,
		Steps: []StepMatch{
			{ToolCategory: "file_read", PathSensitive: true},
			{NetworkWrite: true},
		},
	},
	{
		Name:   "retry_after_deny",
		Window: 60 * time.Second,
		Steps: []StepMatch{
			{DecisionDeny: true},
			{SameVerb: true},
		},
	},
	{
		Name:   "encoded_exfil",
		Window: 60 * time.Second,
		Steps: []StepMatch{
			{ToolCategory: "file_read", PathSensitive: true},
			{ToolCategory: "shell", VerbHint: "base64"},
			{NetworkWrite: true},
		},
	},
	{
		Name:   "escalating_access",
		Window: 2 * time.Minute,
		Steps: []StepMatch{
			{PathCritical: true},
			{PathCritical: true},
			{PathCritical: true},
		},
		Require: 3,
	},
}
