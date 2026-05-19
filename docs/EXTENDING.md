# Extending Aegis

This guide covers the three main extension points: new tool types, new signal types,
and new argument extractors.

## Adding New Tool Types

Tool classification lives in `pkg/aegis/signals/tool_class.go`. The `toolClassTable`
slice maps tool name aliases to a category and base risk score.

To add a new tool category (e.g. for a custom MCP server tool):

**Step 1 — Add to the table:**
```go
// pkg/aegis/signals/tool_class.go
var toolClassTable = []struct { ... }{
    // ... existing entries ...
    {
        names:    []string{"my_custom_tool", "myCustomTool"},
        category: "file_write",  // reuse an existing category
        score:    0.30,
    },
}
```

**Step 2 — Register an extractor** (if the tool has non-standard arguments):
```go
// Somewhere during engine initialization:
registry := extract.NewRegistry(db)
registry.Register("my_custom_tool", func(tool, argsJSON string) extract.Result {
    // Parse argsJSON and return normalized Result
    var args struct {
        Target  string `json:"target_path"`
        Content string `json:"content"`
    }
    json.Unmarshal([]byte(argsJSON), &args)
    return extract.Result{
        Paths: []string{args.Target},
    }
})
```

**Step 3 — Write a policy rule** for the new tool:
```yaml
rules:
  - name: my_tool_sensitive_write
    priority: 18
    action: deny
    severity: high
    confidence: 0.90
    description: "Blocks my_custom_tool from writing to sensitive paths."
    condition:
      and:
        - tool_category: file_write
        - path:
            has_sensitive: true
```

Tool names are matched case-insensitively. For MCP-namespaced tools like
`mcp:my-server:write_file`, register the prefix `mcp:my-server` and the
registry handles prefix matching automatically.

---

## Adding New Signal Types

Signals are fields on `SignalBundle` in `pkg/aegis/signals/types.go`.
Adding a new signal requires four steps.

**Step 1 — Define the signal struct:**
```go
// pkg/aegis/signals/custom.go
type CustomSignal struct {
    IsDetected bool
    Score      float64
}
```

**Step 2 — Add the field to SignalBundle:**
```go
// pkg/aegis/signals/types.go
type SignalBundle struct {
    ToolClass ToolClassSignal
    Command   CommandSignal
    Path      PathSignal
    Network   NetworkSignal
    DLP       DLPSignal
    Evasion   EvasionSignal
    MLScore   float64
    Custom    CustomSignal   // add here
}
```

**Step 3 — Implement the analysis function:**
```go
// pkg/aegis/signals/custom.go
func AnalyzeCustom(tool, argsJSON string) CustomSignal {
    var sig CustomSignal
    // ... analysis logic ...
    return sig
}
```

**Step 4 — Wire it into the engine's SignalComputer:**

The `SignalComputer` interface is in `pkg/aegis/engine_interfaces.go`. The default
implementation is `defaultSignalComputer` in `pkg/aegis/engine_compute.go`.
Add a call to your analysis function in its `Compute` method:

```go
func (c *defaultSignalComputer) Compute(tool, argsJSON, cwd string) *signals.SignalBundle {
    bundle := &signals.SignalBundle{
        // ... existing fields ...
        Custom: signals.AnalyzeCustom(tool, argsJSON),
    }
    return bundle
}
```

**Step 5 — Expose in Expr environment** (optional, for Tier 2 rules):

Add the field to the `ExprEnv` struct in `internal/policy/expr.go` and populate it
in `newExprEnv`:
```go
type ExprEnv struct {
    // ... existing fields ...
    CustomDetected bool    `expr:"custom_detected"`
    CustomScore    float64 `expr:"custom_score"`
}

func newExprEnv(b *signals.SignalBundle) ExprEnv {
    return ExprEnv{
        // ...
        CustomDetected: b.Custom.IsDetected,
        CustomScore:    b.Custom.Score,
    }
}
```

Then write rules using it:
```yaml
condition:
  expr: "custom_detected && custom_score > 0.7"
```

---

## Adding New Argument Extractors

The `extract.Registry` dispatches tool calls to `ExtractorFunc` handlers. Each handler
receives the raw arguments JSON and returns a normalized `extract.Result`.

```go
// internal/extract/types.go
type Result struct {
    Commands []Command  // parsed command invocations
    Paths    []string   // file paths referenced
    Hosts    []string   // network hosts referenced
    Err      error      // parse error (non-fatal)
}
```

**To add an extractor for a new tool format:**
```go
// internal/extract/myformat.go
func extractMyFormat(tool, argsJSON string) Result {
    var args struct {
        ScriptPath string   `json:"script_path"`
        Args       []string `json:"args"`
    }
    if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
        return Result{Err: err}
    }
    return Result{
        Paths: []string{args.ScriptPath},
        Commands: []Command{{
            Name: filepath.Base(args.ScriptPath),
            Args: args.Args,
        }},
    }
}
```

**Register it during initialization:**
```go
registry := extract.NewRegistry(db)
registry.Register("run_script", extractMyFormat)
registry.Register("execute_script", extractMyFormat)
```

Registration order matters: `Register` prepends handlers, so the last `Register`
call takes highest precedence. Built-in handlers are registered at construction time
and can be overridden.

---

## Registering Custom Rules Without YAML

For programmatic rule injection (e.g. in tests or embedded deployments):

```go
import (
    "github.com/mayjain/aegis/pkg/aegis"
    "github.com/mayjain/aegis/pkg/aegis/rules"
)

myRule := rules.Rule{
    Name:       "my_custom_block",
    Priority:   15,
    Action:     rules.ActionDeny,
    Severity:   "high",
    Confidence: 0.90,
    Match: func(b *signals.SignalBundle) bool {
        return b.Custom.IsDetected && b.Custom.Score > 0.7
    },
}

engine, _ := aegis.NewEngine(aegis.WithRules(append(rules.Phase1Rules(), myRule)))
```

Using `WithRules` replaces the full rule set. To augment rather than replace,
load `rules.Phase1Rules()` first and append your custom rules.
