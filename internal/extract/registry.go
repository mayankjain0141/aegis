package extract

import "strings"

// ExtractorFunc extracts structured facts from a tool call's arguments.
type ExtractorFunc func(tool, argsJSON string) Result

// Registry dispatches tool calls to registered ExtractorFuncs.
// Built-in handlers are registered at construction; custom handlers can be added via Register.
type Registry struct {
	handlers []registeredHandler
	fallback ExtractorFunc
}

type registeredHandler struct {
	pattern string
	fn      ExtractorFunc
}

// NewRegistry creates a Registry with built-in shell and file handlers.
// db may be nil (reduced accuracy but no panic).
func NewRegistry(db *CommandDB) *Registry {
	r := &Registry{}
	r.registerBuiltins(db)
	return r
}

// Register adds a custom handler for a specific tool name.
// Custom registrations take precedence over built-ins.
func (r *Registry) Register(pattern string, fn ExtractorFunc) {
	r.handlers = append([]registeredHandler{{pattern: pattern, fn: fn}}, r.handlers...)
}

// Extract dispatches to the appropriate handler for the given tool.
func (r *Registry) Extract(tool, argsJSON string) Result {
	// Exact match (case-insensitive)
	for _, h := range r.handlers {
		if strings.EqualFold(tool, h.pattern) {
			return h.fn(tool, argsJSON)
		}
	}
	// Prefix match for MCP:server:tool naming
	for _, h := range r.handlers {
		if h.pattern != "" && strings.HasPrefix(strings.ToLower(tool), strings.ToLower(h.pattern)+":") {
			return h.fn(tool, argsJSON)
		}
	}
	return r.fallback(tool, argsJSON)
}

func (r *Registry) registerBuiltins(db *CommandDB) {
	ext := NewFastExtractor(db)

	// Shell handler always routes through a known shell tool name so that
	// isShellTool() returns true regardless of the original tool name.
	shellHandler := func(tool, argsJSON string) Result {
		return ext.Extract("bash", argsJSON)
	}

	jsonHandler := func(tool, argsJSON string) Result {
		return ext.Extract("file_read", argsJSON)
	}

	shellTools := []string{
		"Shell", "shell_exec", "run_command", "bash", "Bash",
		"execute_command", "terminal",
	}
	for _, t := range shellTools {
		r.handlers = append(r.handlers, registeredHandler{pattern: t, fn: shellHandler})
	}
	if db != nil {
		for _, t := range db.ToolTypes.Shell {
			r.handlers = append(r.handlers, registeredHandler{pattern: t, fn: shellHandler})
		}
	}

	fileTools := []string{
		"Read", "Write", "Delete", "file_read", "file_write", "file_delete",
		"create_file", "edit_file", "view_file",
	}
	for _, t := range fileTools {
		r.handlers = append(r.handlers, registeredHandler{pattern: t, fn: jsonHandler})
	}

	// MCP prefix handler
	r.handlers = append(r.handlers, registeredHandler{pattern: "MCP", fn: jsonHandler})

	r.fallback = func(tool, argsJSON string) Result {
		return ext.Extract(tool, argsJSON)
	}
}
