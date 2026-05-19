package signals

// SignalBundle holds all computed signals for a single tool call.
type SignalBundle struct {
	ToolClass ToolClassSignal
	Command   CommandSignal
	Path      PathSignal
	Network   NetworkSignal
	DLP       DLPSignal
	Evasion   EvasionSignal
	MLScore   float64
}

// CompositeScore computes a weighted score for observability only.
// This number is NOT used for decisions — only for dashboards.
func CompositeScore(b *SignalBundle) float64 {
	score := b.ToolClass.Score*0.15 +
		b.Command.MaxVerbDanger*0.20 +
		b.Path.MaxPathRisk*0.20 +
		b.Network.Score*0.15 +
		b.DLP.Score*0.10 +
		b.Evasion.Score*0.10 +
		b.MLScore*0.10
	if score > 1.0 {
		return 1.0
	}
	if score < 0.0 {
		return 0.0
	}
	return score
}
