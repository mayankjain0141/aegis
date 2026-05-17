// Package extract parses tool call arguments into normalized semantic
// representations. It uses shell AST parsing and interpreter dry-run
// to resolve command variants into a canonical form.
//
// The extractor produces FACTS, not decisions. It does not classify
// operations, detect evasion, or make policy judgments.
package extract

// Result is the output of the extractor. Pure data.
type Result struct {
	Commands []Command // resolved commands (wrappers stripped, vars expanded)
	Paths    []string  // all file paths mentioned in arguments
	Hosts    []string  // all hostnames/URLs mentioned in arguments
	Err      error     // non-nil if parsing failed
}

// Command is a single resolved binary invocation.
type Command struct {
	Name     string   // binary basename (e.g. "rm", "curl")
	Args     []string // expanded arguments (e.g. ["-rf", "/tmp"])
	FullPath string   // original full path if invoked with absolute path (e.g. "/tmp/payload")
}
