package aegis

import (
	"encoding/json"

	"github.com/mayjain/aegis/internal/extract"
	"github.com/mayjain/aegis/pkg/aegis/signals"
)

// SignalComputer extracts a SignalBundle from a tool call.
type SignalComputer interface {
	Compute(tool, argsJSON, cwd string) *signals.SignalBundle
	ComputeFull(tool, argsJSON, cwd string) *signals.SignalBundle
}

type defaultSignalComputer struct {
	fast     *extract.Extractor
	full     *extract.Extractor
	fastPath FastPath
}

func newDefaultSignalComputer(fast, full *extract.Extractor, fp FastPath) SignalComputer {
	return &defaultSignalComputer{fast: fast, full: full, fastPath: fp}
}

func (c *defaultSignalComputer) Compute(tool, argsJSON, cwd string) *signals.SignalBundle {
	return c.compute(tool, argsJSON, cwd, c.fast)
}

func (c *defaultSignalComputer) ComputeFull(tool, argsJSON, cwd string) *signals.SignalBundle {
	return c.compute(tool, argsJSON, cwd, c.full)
}

func (c *defaultSignalComputer) compute(tool, argsJSON, cwd string, ext *extract.Extractor) *signals.SignalBundle {
	toolClass := signals.ClassifyTool(tool)
	cmd := signals.AnalyzeCommand(tool, argsJSON, ext)

	extraPaths := append([]string(nil), cmd.Paths...)
	for _, sub := range cmd.Commands {
		if hasDataFile, filePath := signals.HasDataFilePattern(sub.Args); hasDataFile && filePath != "" {
			extraPaths = append(extraPaths, filePath)
		}
	}
	pathSig := signals.AnalyzePathsFromArgs(tool, argsJSON, cwd, extraPaths)
	netSig := signals.AnalyzeNetworkFromExtracted(cmd)
	dlpSig := signals.ScanDLP(argsJSON)
	evasionSig := signals.AnalyzeEvasion(cmd, argsJSON)

	bundle := &signals.SignalBundle{
		ToolClass: toolClass,
		Command:   cmd,
		Path:      pathSig,
		Network:   netSig,
		DLP:       dlpSig,
		Evasion:   evasionSig,
	}

	var args map[string]any
	if json.Unmarshal([]byte(argsJSON), &args) == nil {
		for _, key := range []string{"command", "cmd", "script", "shell"} {
			if cmdStr, ok := args[key].(string); ok && cmdStr != "" {
				bundle.MLScore = mlScorer.Score(cmdStr)
				break
			}
		}
	}

	if al := c.fastPath.allowlistForCWD(cwd); al != nil {
		applyAllowlistMutations(bundle, al)
	}
	return bundle
}
