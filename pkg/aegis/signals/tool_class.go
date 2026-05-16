package signals

import "strings"

// ToolClassSignal is Signal 1: deterministic tool category + base risk.
type ToolClassSignal struct {
	Category string  // "shell", "file_read", "file_write", "file_delete", "network_read", "search", "unknown"
	Score    float64 // 0.0–1.0 base risk for this tool type
}

var toolClassTable = []struct {
	names    []string
	category string
	score    float64
}{
	{
		names:    []string{"shell", "bash", "run_command", "execute_command", "terminal", "shell_exec"},
		category: "shell",
		score:    0.60,
	},
	{
		names:    []string{"read", "file_read", "cat", "tabread", "read_file"},
		category: "file_read",
		score:    0.05,
	},
	{
		names:    []string{"write", "file_write", "create_file", "edit", "strreplace", "write_file"},
		category: "file_write",
		score:    0.30,
	},
	{
		names:    []string{"delete", "file_delete", "delete_file"},
		category: "file_delete",
		score:    0.70,
	},
	{
		names:    []string{"glob", "grep", "find", "search"},
		category: "search",
		score:    0.02,
	},
	{
		names:    []string{"webfetch", "websearch"},
		category: "network_read",
		score:    0.15,
	},
}

// ClassifyTool returns the ToolClassSignal for the given tool name.
func ClassifyTool(tool string) ToolClassSignal {
	lower := strings.ToLower(tool)
	for _, entry := range toolClassTable {
		for _, name := range entry.names {
			if lower == name {
				return ToolClassSignal{Category: entry.category, Score: entry.score}
			}
		}
	}
	return ToolClassSignal{Category: "unknown", Score: 0.40}
}

// IsShellTool returns true if the tool is a shell execution tool.
func IsShellTool(tool string) bool {
	return ClassifyTool(tool).Category == "shell"
}
