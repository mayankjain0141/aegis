package extract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

const (
	maxRecursionDepth = 3
	dryRunTimeout     = 10 * time.Millisecond
)

// Extractor parses tool call arguments and produces a normalized Result.
type Extractor struct {
	cmdDB *CommandDB
}

// NewExtractor creates an extractor with the given command database.
// If db is nil, the extractor still parses but cannot strip wrappers
// or recurse into shell interpreters.
func NewExtractor(db *CommandDB) *Extractor {
	return &Extractor{cmdDB: db}
}

// Extract analyzes a tool call and returns normalized facts.
// The tool parameter is used to determine whether to invoke the shell parser.
func (e *Extractor) Extract(tool, argsJSON string) Result {
	if e.isShellTool(tool) {
		return e.extractShell(argsJSON)
	}
	return e.extractJSON(argsJSON)
}

func (e *Extractor) isShellTool(tool string) bool {
	if e.cmdDB != nil {
		for _, t := range e.cmdDB.ToolTypes.Shell {
			if strings.EqualFold(tool, t) {
				return true
			}
		}
	}
	// Fallback for when command DB has no tool_types section
	switch tool {
	case "shell_exec", "run_command", "bash", "Bash", "execute_command", "terminal":
		return true
	}
	return false
}

func (e *Extractor) extractShell(argsJSON string) Result {
	cmd := extractField(argsJSON, "command", "cmd", "script", "shell", "commandline")
	if cmd == "" {
		return Result{}
	}

	prog, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return Result{Err: fmt.Errorf("shell parse: %w", err)}
	}

	astCmds := e.walkAST(prog, 0)
	interpCmds, interpErr := e.dryRun(prog)
	commands := dedup(append(interpCmds, astCmds...))
	paths, hosts := extractPathsHosts(commands)

	return Result{
		Commands: commands,
		Paths:    paths,
		Hosts:    hosts,
		Err:      interpErr,
	}
}

func (e *Extractor) extractJSON(argsJSON string) Result {
	var r Result
	var obj map[string]any
	if err := json.Unmarshal([]byte(argsJSON), &obj); err != nil {
		return r
	}

	pathFields := []string{"path", "file", "filename", "filepath"}
	hostFields := []string{"url", "host", "endpoint", "uri"}

	if e.cmdDB != nil {
		if len(e.cmdDB.FieldMappings.PathFields) > 0 {
			pathFields = e.cmdDB.FieldMappings.PathFields
		}
		if len(e.cmdDB.FieldMappings.HostFields) > 0 {
			hostFields = e.cmdDB.FieldMappings.HostFields
		}
	}

	for _, key := range pathFields {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				r.Paths = append(r.Paths, s)
			}
		}
	}
	for _, key := range hostFields {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				r.Hosts = append(r.Hosts, s)
			}
		}
	}
	return r
}

// walkAST traverses the syntax tree collecting command invocations.
// This catches commands in ALL branches (including dead code like `false && rm`).
func (e *Extractor) walkAST(prog *syntax.File, depth int) []Command {
	if depth >= maxRecursionDepth {
		return nil
	}

	var commands []Command
	syntax.Walk(prog, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}

		parts := wordSlice(call.Args)
		if len(parts) == 0 {
			return true
		}

		binary := filepath.Base(parts[0])
		args := parts[1:]

		binary, args = e.unwrap(binary, args)

		if e.cmdDB != nil && e.cmdDB.IsShellInterpreter(binary) {
			if inner := shellDashC(args); inner != "" {
				innerProg, err := syntax.NewParser().Parse(strings.NewReader(inner), "")
				if err == nil {
					commands = append(commands, e.walkAST(innerProg, depth+1)...)
				}
				return true
			}
		}

		commands = append(commands, Command{Name: binary, Args: args})
		return true
	})
	return commands
}

// dryRun executes the AST in a sandboxed interpreter to expand variables.
func (e *Extractor) dryRun(prog *syntax.File) (commands []Command, retErr error) {
	// Protect against panics in the third-party interpreter library
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("interpreter panic: %v", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), dryRunTimeout)
	defer cancel()

	runner, err := interp.New(
		interp.StdIO(nil, nil, nil),
		interp.ExecHandlers(func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
			return func(ctx context.Context, args []string) error {
				if len(args) > 0 {
					binary := filepath.Base(args[0])
					cmdArgs := args[1:]
					binary, cmdArgs = e.unwrap(binary, cmdArgs)
					commands = append(commands, Command{
						Name: binary,
						Args: slices.Clone(cmdArgs),
					})
				}
				return nil
			}
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("interpreter init: %w", err)
	}

	runErr := runner.Run(ctx, prog)
	if runErr != nil && errors.Is(runErr, context.DeadlineExceeded) {
		return commands, fmt.Errorf("shell interpretation timed out")
	}
	return commands, nil
}

// unwrap strips command wrappers (sudo, env, timeout, etc.) to get the real binary.
func (e *Extractor) unwrap(binary string, args []string) (string, []string) {
	if e.cmdDB == nil {
		return binary, args
	}
	for e.cmdDB.IsWrapper(binary) && len(args) > 0 {
		i := 0
		// Skip flags and their values
		for i < len(args) {
			if strings.HasPrefix(args[i], "-") {
				i++ // skip the flag
				// Some flags take a value argument
				if i < len(args) && !strings.HasPrefix(args[i], "-") {
					i++ // skip the value
				}
			} else if binary == "timeout" || binary == "nice" || binary == "ionice" {
				// These wrappers take a positional numeric arg before the command
				if _, err := fmt.Sscanf(args[i], "%f", new(float64)); err == nil {
					i++
					continue
				}
				break
			} else {
				break
			}
		}
		if i >= len(args) {
			break
		}
		binary = filepath.Base(args[i])
		args = args[i+1:]
	}
	return binary, args
}

// --- Helpers ---

func wordSlice(words []*syntax.Word) []string {
	parts := make([]string, 0, len(words))
	for _, w := range words {
		parts = append(parts, wordText(w))
	}
	return parts
}

func wordText(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				if lit, ok := inner.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		}
	}
	return sb.String()
}

func shellDashC(args []string) string {
	for i, a := range args {
		if a == "-c" && i+1 < len(args) {
			return strings.Join(args[i+1:], " ")
		}
	}
	return ""
}

func extractPathsHosts(commands []Command) (paths, hosts []string) {
	seen := make(map[string]bool)
	for _, cmd := range commands {
		for _, arg := range cmd.Args {
			if looksLikePath(arg) && !seen[arg] {
				paths = append(paths, arg)
				seen[arg] = true
			} else if looksLikeHost(arg) && !seen[arg] {
				hosts = append(hosts, arg)
				seen[arg] = true
			}
		}
	}
	return
}

func looksLikePath(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~/") ||
		(strings.Contains(s, "/") && !strings.Contains(s, "://"))
}

func looksLikeHost(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") {
		return false
	}
	return strings.Contains(s, "://") ||
		(strings.Contains(s, ".") && !strings.Contains(s, "/"))
}

func dedup(commands []Command) []Command {
	seen := make(map[string]bool)
	var result []Command
	for _, c := range commands {
		key := c.Name + "\x00" + strings.Join(c.Args, "\x00")
		if !seen[key] {
			seen[key] = true
			result = append(result, c)
		}
	}
	return result
}

func extractField(jsonStr string, keys ...string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &obj); err != nil {
		return ""
	}
	for _, key := range keys {
		if v, ok := obj[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}
