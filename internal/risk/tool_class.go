package risk

import "context"

// ToolClassificationSignal assigns a static danger score based on the tool name.
type ToolClassificationSignal struct{}

var toolDangerTable = map[string]float64{
	// read operations
	"file_read":   0.05,
	"list_files":  0.05,
	"web_search":  0.05,
	// write operations
	"file_write":  0.30,
	"file_create": 0.30,
	// execute operations
	"shell_exec":  0.60,
	"run_command": 0.60,
	// destructive ops
	"file_delete": 0.85,
	// network/exfil
	"http_request": 0.70,
	"send_email":   0.70,
	"api_call":     0.70,
}

const unknownToolScore = 0.50

func (t ToolClassificationSignal) Name() string { return "tool_class" }

func (t ToolClassificationSignal) Score(_ context.Context, tool string, _ string, _ int) float64 {
	if score, ok := toolDangerTable[tool]; ok {
		return score
	}
	return unknownToolScore
}
