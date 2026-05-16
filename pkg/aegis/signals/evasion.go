package signals

import (
	"regexp"
	"strings"
)

// EvasionSignal is Signal 6: evasion technique detection.
type EvasionSignal struct {
	WrappersStripped    int
	VarsExpanded        bool
	VarsRevealedDanger  bool
	ShellRecursionDepth int
	EncodingDetected    bool
	CommandSubstitution bool
	Score               float64
}

var (
	// base64ToShellPattern detects base64/hex decoded and piped to shell
	base64ToShellPattern = regexp.MustCompile(
		`(?i)(base64|xxd|od|hexdump|perl\s+-e|python.*decode|echo.*\\\|)\s*[\|>].*\b(bash|sh|zsh|dash|exec)\b`,
	)

	// curlPipeShell detects download and execute patterns
	curlPipeShell = regexp.MustCompile(
		`(?i)(curl|wget).*[\|]\s*(bash|sh|zsh|exec|python|perl|ruby|node)\b`,
	)

	// commandSubstitutionDanger detects $() or `` resolving to dangerous verbs
	commandSubstitutionPattern = regexp.MustCompile(
		`(?i)\$\(.*\b(rm|mkfs|dd|wget|curl|nc|socat)\b.*\)|` +
			"`.*\\b(rm|mkfs|dd|wget|curl|nc|socat)\\b.*`",
	)

	// shellRecursionPattern detects nested shell calls: sh -c 'sh -c ...'
	shellRecursionPattern = regexp.MustCompile(
		`(?i)(bash|sh|zsh|dash)\s+-c\s+['"].*\b(bash|sh|zsh|dash)\s+-c\b`,
	)

	// varExpansionDanger detects variable expansion hiding dangerous commands
	varExpansionPattern = regexp.MustCompile(
		`(?i)\$\{?[A-Z_][A-Z0-9_]*\}?\s*=\s*['"](rm|mkfs|dd|curl|wget|nc)\b`,
	)
)

var commandWrappers = map[string]bool{
	"sudo": true, "env": true, "strace": true, "ltrace": true,
	"nohup": true, "nice": true, "ionice": true, "taskset": true,
	"timeout": true, "time": true, "stime": true,
}

// AnalyzeEvasion computes EvasionSignal from command signal and raw args JSON.
func AnalyzeEvasion(cmd CommandSignal, argsJSON string) EvasionSignal {
	var sig EvasionSignal

	// Count wrappers stripped
	for _, c := range cmd.Commands {
		for _, w := range c.Wrappers {
			if commandWrappers[w] {
				sig.WrappersStripped++
			}
		}
	}

	// Extract command string for pattern matching
	cmdStr := extractCommandField(argsJSON)

	if cmdStr == "" {
		sig.Score = computeEvasionScore(&sig)
		return sig
	}

	// Detect encoding piped to shell
	if base64ToShellPattern.MatchString(cmdStr) || curlPipeShell.MatchString(cmdStr) {
		sig.EncodingDetected = true
	}

	// Detect command substitution with dangerous verbs
	if commandSubstitutionPattern.MatchString(cmdStr) {
		sig.CommandSubstitution = true
	}

	// Detect nested shell recursion
	if shellRecursionPattern.MatchString(cmdStr) {
		sig.ShellRecursionDepth = 2
	}

	// Detect variable expansion revealing danger
	if varExpansionPattern.MatchString(cmdStr) {
		sig.VarsExpanded = true
		sig.VarsRevealedDanger = true
	}

	// Also check if command contains obvious evasion with wrappers
	if sig.WrappersStripped > 0 && cmd.MaxVerbDanger > 0.7 {
		sig.VarsRevealedDanger = true
	}

	sig.Score = computeEvasionScore(&sig)
	return sig
}

func computeEvasionScore(sig *EvasionSignal) float64 {
	score := 0.0

	// +0.10 per wrapper stripped (max 0.30)
	wrapperBoost := float64(sig.WrappersStripped) * 0.10
	if wrapperBoost > 0.30 {
		wrapperBoost = 0.30
	}
	score += wrapperBoost

	// +0.40 if vars expanded AND revealed dangerous verb/path
	if sig.VarsExpanded && sig.VarsRevealedDanger {
		score += 0.40
	}

	// +0.20 if shell recursion depth > 1
	if sig.ShellRecursionDepth > 1 {
		score += 0.20
	}

	// +0.50 if encoding detected (download/decode piped to shell)
	if sig.EncodingDetected {
		score += 0.50
	}

	// +0.30 if command substitution with dangerous verb
	if sig.CommandSubstitution {
		score += 0.30
	}

	// Clamp to [0, 1]
	if score > 1.0 {
		score = 1.0
	}
	return score
}

// checkStdinPipe detects patterns like `cat file | curl` or `< file curl`
func checkStdinPipe(cmdStr string) bool {
	stdinPipePattern := regexp.MustCompile(
		`(?i)(cat\s+\S+\s*\|\s*(curl|wget|nc|socat)|<\s*\S+\s+(curl|wget|nc|socat))`,
	)
	return stdinPipePattern.MatchString(cmdStr)
}

// detectWrappers returns wrappers found at the start of args
func detectWrappers(args []string) []string {
	var wrappers []string
	for _, arg := range args {
		if commandWrappers[strings.TrimPrefix(arg, "/")] {
			wrappers = append(wrappers, arg)
		}
	}
	return wrappers
}
