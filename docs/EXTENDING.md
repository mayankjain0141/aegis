# Extending Aegis

Aegis is designed for extension without modifying core code. Three primary extension points:

1. **Custom tool types** — register extractors for new MCP tools or IDE integrations
2. **New signals** — add computed signals to the evaluation pipeline
3. **New ML models** — swap or retrain the maliciousness scorer

---

## 1. Custom Tool Types (Registry Pattern)

The `extract.Registry` dispatches every tool call to the appropriate `ExtractorFunc`. Think of it like `http.HandleFunc`: you register a handler for a tool name, and the registry routes calls to it at evaluation time.

**ExtractorFunc signature:**
```go
type ExtractorFunc func(tool, argsJSON string) Result
```

`tool` is the full tool name as received (e.g., `browser_navigate` or `MCP:playwright:navigate`). `argsJSON` is the raw JSON arguments string from the MCP call. Return a `Result` with whatever fields you can extract:

```go
type Result struct {
    Commands []Command  // parsed command invocations
    Paths    []string   // file paths referenced
    Hosts    []string   // network hosts referenced
    Err      error      // parse error (non-fatal — logged, not fatal)
}
```

**Full working example — registering a browser automation tool:**

```go
// Example: registering a Playwright browser tool
reg := extract.NewRegistry(db)
reg.Register("browser_navigate", func(tool, argsJSON string) extract.Result {
    var args struct {
        URL string `json:"url"`
    }
    json.Unmarshal([]byte(argsJSON), &args)
    return extract.Result{
        Hosts: []string{args.URL},
    }
})
```

**Dispatch order:**

1. Exact name match — `browser_navigate` matches exactly
2. `MCP:server:` prefix match — `MCP:playwright:` catches all tools from that server
3. Fallback extractor — generic JSON key scanning for common fields (`path`, `command`, `url`)

MCP tools use `MCP:server:toolname` naming. Register with a prefix to catch all tools from a server:

```go
reg.Register("MCP:myserver:", func(tool, argsJSON string) extract.Result {
    // tool will be the full name, e.g. "MCP:myserver:write_file"
    // parse argsJSON based on your server's schema
    return extract.Result{ ... }
})
```

**Also register in commands.yaml** for path and host field mapping. If your tool has a field that contains file paths or hostnames, add it to `FieldMappings` so the Path and Network signals pick it up:

```yaml
# commands.yaml
FieldMappings:
  browser_navigate:
    hosts: [url, target_url]
  my_custom_tool:
    paths: [target_path, destination]
```

And list the tool in `ToolTypes.Shell` if it executes arbitrary commands (so `ToolClass` scores it correctly):

```yaml
ToolTypes:
  Shell:
    - bash
    - run_bash
    - my_custom_tool   # add here if it executes shell commands
```

**Step-by-step checklist for a new tool:**

1. Register an `ExtractorFunc` in `extract.Registry`
2. Add `FieldMappings` entry in `commands.yaml` if the tool has path/host fields
3. Add to `ToolTypes.Shell` in `commands.yaml` if it executes shell commands
4. Write a policy rule targeting the new tool's category
5. Test with `aegis simulate --tool my_custom_tool --args '{"target_path":"/etc/passwd"}'`

---

## 2. New Signals

Signals are fields on `SignalBundle` in `pkg/aegis/signals/types.go`. Every signal flows through the same pipeline: compute → bundle → expr env → OPA input → composite score.

**Step 1 — Add field to `SignalBundle`** in `pkg/aegis/signals/types.go`:

```go
type SignalBundle struct {
    ToolClass ToolClassSignal
    Command   CommandSignal
    Path      PathSignal
    Network   NetworkSignal
    DLP       DLPSignal
    Evasion   EvasionSignal
    MLScore   float64
    MySignal  MySignal   // add here
}
```

**Step 2 — Create `pkg/aegis/signals/mysignal.go`** with the analysis function:

```go
type MySignal struct {
    IsDetected bool
    Score      float64
}

func AnalyzeMySignal(ext *extract.Extractor, argsJSON string) MySignal {
    var sig MySignal
    // inspect ext.Commands, ext.Paths, ext.Hosts, or parse argsJSON directly
    return sig
}
```

The function receives a populated `*extract.Extractor` (already dispatched) and the raw args JSON. You can use either the pre-parsed extractor fields or re-parse argsJSON for tool-specific structure.

**Step 3 — Call it in `computeSignalsWithExtractor()`** in `pkg/aegis/engine.go`:

```go
func computeSignalsWithExtractor(ext *extract.Extractor, argsJSON string) *signals.SignalBundle {
    return &signals.SignalBundle{
        // ... existing fields ...
        MySignal: signals.AnalyzeMySignal(ext, argsJSON),
    }
}
```

**Step 4 — Add to `ExprEnv`** in `internal/policy/expr.go` and populate in `bundleToEnv()`:

```go
type ExprEnv struct {
    // ... existing fields ...
    MySignalDetected bool    `expr:"my_signal_detected"`
    MySignalScore    float64 `expr:"my_signal_score"`
}

func bundleToEnv(b *signals.SignalBundle) ExprEnv {
    return ExprEnv{
        // ...
        MySignalDetected: b.MySignal.IsDetected,
        MySignalScore:    b.MySignal.Score,
    }
}
```

**Step 5 — Add to `OPAInput`** in `internal/policy/opa.go` and populate in `bundleToOPAInput()`:

```go
type OPAInput struct {
    // ... existing fields ...
    MySignal struct {
        IsDetected bool    `json:"is_detected"`
        Score      float64 `json:"score"`
    } `json:"my_signal"`
}

func bundleToOPAInput(b *signals.SignalBundle) OPAInput {
    inp := OPAInput{ /* ... */ }
    inp.MySignal.IsDetected = b.MySignal.IsDetected
    inp.MySignal.Score = b.MySignal.Score
    return inp
}
```

**Step 6 — Add to `CompositeScore()`** in `pkg/aegis/signals/types.go`. Weights must sum to ≤ 1.0 across all signals:

```go
func (b *SignalBundle) CompositeScore() float64 {
    score := 0.0
    score += b.ToolClass.Score * 0.15
    score += b.Command.MaxVerbDanger * 0.20
    score += b.Path.MaxPathRisk * 0.20
    score += b.Network.Score * 0.15
    score += b.DLP.Score * 0.10
    score += b.Evasion.Score * 0.10
    score += b.MLScore * 0.10
    score += b.MySignal.Score * 0.00  // set weight when you're ready to use it
    if score > 1.0 {
        score = 1.0
    }
    return score
}
```

Start at weight 0.00 for a new signal and increase it only after validating score distribution. Increasing a weight must be balanced by reducing another, or the composite ceiling (1.0 clamp) absorbs it silently.

**Step 7 — Write tests** in `pkg/aegis/signals/mysignal_test.go`:

```go
func TestAnalyzeMySignal_Detection(t *testing.T) {
    ext := &extract.Extractor{ /* set up a representative extractor */ }
    sig := AnalyzeMySignal(ext, `{"field":"value"}`)
    if !sig.IsDetected {
        t.Fatal("expected detection")
    }
}
```

After all steps, write a policy rule using the new expr fields:

```yaml
condition:
  expr: "my_signal_detected && my_signal_score > 0.7"
```

Or for OPA-tier rules, reference `input.my_signal.is_detected` in Rego.

---

## 3. New ML Models

When to retrain: current recall < 90% on your threat corpus, or a new attack vector (e.g., novel shell encoding scheme) isn't covered by the QuasarNix model.

**Step 1 — Collect a labeled dataset** of (command, label) pairs. Minimum viable: ~5,000 attack commands + ~10,000 benign developer commands. Attack commands should cover reverse shells, privilege escalation, data exfiltration, and obfuscated variants. Benign commands should reflect real developer workflows (git, npm, make, curl to known registries).

**Step 2 — Train in Python:**

```bash
make ml-train  # uses the python/ directory
```

The training script (`python/train.py`) handles:
- Tokenizing commands into character n-grams of length 1–3
- Building the vocab `map[string]int`
- Training XGBoost with 100 trees

Or train manually:

```python
import xgboost as xgb

model = xgb.XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric="logloss",
)
model.fit(X_train, y_train)
```

**Step 3 — Export to JSON.** Use `.json` format, NOT `.ubj` / `.xgboost` UBJSON (the Go loader reads the JSON tree format):

```python
model.save_model("mymodel.json")
```

**Step 4 — Build the vocab file** as `mymodel_vocab.json` — a `map[string]int` mapping each n-gram to its feature index:

```python
import json
vocab = {ngram: idx for idx, ngram in enumerate(sorted(all_ngrams))}
with open("mymodel_vocab.json", "w") as f:
    json.dump(vocab, f)
```

Vocab and model must agree: the feature at index `i` in the model must correspond to vocab entry with value `i`.

**Step 5 — Place both files** in `pkg/aegis/signals/models/`:

```
pkg/aegis/signals/models/
  mymodel.json
  mymodel_vocab.json
```

**Step 6 — Initialize with the new files:**

```go
scorer, err := signals.NewMLScorer("mymodel.json", "mymodel_vocab.json")
if err != nil {
    log.Fatal(err)
}
```

Pass the scorer to the engine during initialization via `aegis.WithMLScorer(scorer)`.

**Step 7 — Verify:**

```bash
aegis doctor        # should report: ML model: mymodel.json (100 trees, 4096 features)
make ml-test        # runs the built-in eval suite against known attack/benign commands
```

`aegis doctor` will warn if `UseHeuristic = true`, which means the model files weren't found or failed to load.

**Model JSON format requirements.** The Go loader expects this structure:

```json
{
  "learner": {
    "learner_model_param": {
      "num_feature": "4096",
      "base_score": "[0.5]"
    },
    "gradient_booster": {
      "model": {
        "trees": [
          {
            "left_children": [...],
            "right_children": [...],
            "split_indices": [...],
            "split_conditions": [...],
            "default_left": [...]
          }
        ]
      }
    }
  }
}
```

`num_feature` must match the vocab size. `base_score` is the pre-sigmoid offset applied before summing tree leaf values. `default_left` controls which branch a NaN feature value takes — the model uses `true` (route left) for absent n-gram features, which prevents score inflation from missing tokens.

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
        return b.MySignal.IsDetected && b.MySignal.Score > 0.7
    },
}

engine, _ := aegis.NewEngine(aegis.WithRules(append(rules.Phase1Rules(), myRule)))
```

Using `WithRules` replaces the full rule set. To augment rather than replace, load `rules.Phase1Rules()` first and append your custom rules.

Priority controls evaluation order — higher numbers run first. Built-in Phase 1 rules use priorities 1–20. Use priority ≥ 21 for custom rules to avoid conflicts, or use a lower priority (< 1) to run after all built-ins as a catch-all.
