// Package session manages per-agent session state for Phase 2 behavioral analysis.
package session

import (
	"math"
	"sync"
	"time"
)

// ToolCall records a single evaluated tool call.
type ToolCall struct {
	Time           time.Time
	Tool           string
	ArgSummary     string  // first 80 chars of the command/path
	PrimaryVerb    string  // primary dangerous verb (for RetryAfterDeny detection)
	Decision       string  // "allow", "deny", "escalate"
	Rule           string  // which rule fired
	CompositeScore float64
	// Path context — enables exfil_after_sensitive_read sequence detection.
	// These must be populated from the signal bundle in engine.recordCall.
	PathSensitive bool
	PathCritical  bool
	NetworkWrite  bool
}

// DenyEvent records a deny decision for retry detection.
type DenyEvent struct {
	Time time.Time
	Tool string
	Verb string // primary dangerous verb
	Rule string
}

// State holds all session data for one agent session.
type State struct {
	AgentID   string
	StartTime time.Time

	calls       [100]ToolCall
	callHead    int
	callCount   int
	denies      [50]DenyEvent
	denyHead    int
	denyCount   int
	toolCounts  map[string]int
	baseline    map[string]float64 // tool distribution from first 5 min
	baselineSet bool
	ewma        *EWMABaseline
	mu          sync.RWMutex
}

// New creates a new session state for an agent.
func New(agentID string) *State {
	return &State{
		AgentID:    agentID,
		StartTime:  time.Now(),
		toolCounts: make(map[string]int),
		baseline:   make(map[string]float64),
		ewma:       NewEWMABaseline(0.02, 10),
	}
}

// Record stores a tool call result in session history.
func (s *State) Record(call ToolCall) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.calls[s.callHead] = call
	s.callHead = (s.callHead + 1) % len(s.calls)
	if s.callCount < len(s.calls) {
		s.callCount++
	}
	s.ewma.Update(call.Tool)

	if call.Decision == "deny" || call.Decision == "escalate" {
		ev := DenyEvent{Time: call.Time, Tool: call.Tool, Verb: call.PrimaryVerb, Rule: call.Rule}
		s.denies[s.denyHead] = ev
		s.denyHead = (s.denyHead + 1) % len(s.denies)
		if s.denyCount < len(s.denies) {
			s.denyCount++
		}
	}

	s.toolCounts[call.Tool]++

	// Set baseline from first 5 minutes of traffic
	if !s.baselineSet && time.Since(s.StartTime) > 5*time.Minute {
		total := 0
		for _, v := range s.toolCounts {
			total += v
		}
		if total > 0 {
			for tool, count := range s.toolCounts {
				s.baseline[tool] = float64(count) / float64(total)
			}
			s.baselineSet = true
		}
	}
}

// Signal computes the SessionSignal for Phase 2 analysis.
func (s *State) Signal(current ToolCall) SessionSignal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sig := SessionSignal{}
	now := time.Now()

	// Count calls in windows
	sig.CallsLastMinute = s.countCallsInWindow(now, time.Minute)
	sig.CallsLast5Minutes = s.countCallsInWindow(now, 5*time.Minute)

	// Count unique tools
	sig.UniqueToolsUsed = len(s.toolCounts)

	// Recent deny count and last deny info (including verb for RetryAfterDeny detection)
	sig.RecentDenyCount = s.countDeniesInWindow(now, 5*time.Minute)
	if s.denyCount > 0 {
		lastDeny := s.denies[(s.denyHead-1+len(s.denies))%len(s.denies)]
		sig.LastDenyTool = lastDeny.Tool
		sig.LastDenyVerb = lastDeny.Verb
		sig.LastDenyTimeAgo = now.Sub(lastDeny.Time)
		sig.LastDenyRule = lastDeny.Rule
	}

	// Tool sequence (last 20)
	seq := s.recentSequence(20)
	sig.ToolSequence = seq

	// Risk trend (slope over last 20 calls)
	sig.RiskTrend = s.computeRiskTrend()

	sig.BaselineEstablished = s.baselineSet
	if s.baselineSet {
		sig.BaselineDeviation = s.computeBaselineDeviation()
	}

	return sig
}

// RecentDenies returns deny events within the window.
func (s *State) RecentDenies(window time.Duration) []DenyEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	var result []DenyEvent
	for i := 0; i < s.denyCount; i++ {
		idx := (s.denyHead - 1 - i + len(s.denies)) % len(s.denies)
		ev := s.denies[idx]
		if ev.Time.Before(cutoff) {
			break
		}
		result = append(result, ev)
	}
	return result
}

// RecentCalls returns the last n calls in chronological order.
func (s *State) RecentCalls(n int) []ToolCall {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if n > s.callCount {
		n = s.callCount
	}
	result := make([]ToolCall, n)
	for i := 0; i < n; i++ {
		idx := (s.callHead - 1 - i + len(s.calls)) % len(s.calls)
		result[n-1-i] = s.calls[idx]
	}
	return result
}

func (s *State) countCallsInWindow(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	count := 0
	for i := 0; i < s.callCount; i++ {
		idx := (s.callHead - 1 - i + len(s.calls)) % len(s.calls)
		if s.calls[idx].Time.Before(cutoff) {
			break
		}
		count++
	}
	return count
}

func (s *State) countDeniesInWindow(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	count := 0
	for i := 0; i < s.denyCount; i++ {
		idx := (s.denyHead - 1 - i + len(s.denies)) % len(s.denies)
		if s.denies[idx].Time.Before(cutoff) {
			break
		}
		count++
	}
	return count
}

func (s *State) recentSequence(n int) []string {
	if n > s.callCount {
		n = s.callCount
	}
	tools := make([]string, n)
	for i := 0; i < n; i++ {
		idx := (s.callHead - 1 - i + len(s.calls)) % len(s.calls)
		tools[n-1-i] = s.calls[idx].Tool
	}
	return tools
}

func (s *State) computeRiskTrend() float64 {
	n := s.callCount
	if n < 3 {
		return 0.0
	}
	if n > 20 {
		n = 20
	}
	// Simple linear regression slope on risk scores
	scores := make([]float64, n)
	for i := 0; i < n; i++ {
		idx := (s.callHead - n + i + len(s.calls)) % len(s.calls)
		scores[i] = s.calls[idx].CompositeScore
	}
	// Compute slope
	meanX := float64(n-1) / 2
	meanY := 0.0
	for _, v := range scores {
		meanY += v
	}
	meanY /= float64(n)
	numr, denr := 0.0, 0.0
	for i, y := range scores {
		x := float64(i)
		numr += (x - meanX) * (y - meanY)
		denr += (x - meanX) * (x - meanX)
	}
	if denr == 0 {
		return 0.0
	}
	return numr / denr
}

func (s *State) computeBaselineDeviation() float64 {
	if !s.baselineSet || len(s.toolCounts) == 0 {
		return 0.0
	}
	// Recent distribution (last 20 calls)
	recent := make(map[string]float64)
	n := s.callCount
	if n > 20 {
		n = 20
	}
	for i := 0; i < n; i++ {
		idx := (s.callHead - 1 - i + len(s.calls)) % len(s.calls)
		recent[s.calls[idx].Tool]++
	}
	if n > 0 {
		for k := range recent {
			recent[k] /= float64(n)
		}
	}

	// Cosine distance between baseline and recent
	var dot, normA, normB float64
	tools := make(map[string]bool)
	for k := range s.baseline {
		tools[k] = true
	}
	for k := range recent {
		tools[k] = true
	}
	for t := range tools {
		a := s.baseline[t]
		b := recent[t]
		dot += a * b
		normA += a * a
		normB += b * b
	}
	if normA == 0 || normB == 0 {
		return 0.0
	}
	cosine := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	return 1.0 - cosine // distance: 0=identical, 1=orthogonal
}

// SessionSignal is the output of session state analysis for Phase 2 rules.
type SessionSignal struct {
	CallsLastMinute     int
	CallsLast5Minutes   int
	UniqueToolsUsed     int
	RecentDenyCount     int
	LastDenyTool        string
	LastDenyVerb        string // primary verb from the denied call, for RetryAfterDeny
	LastDenyTimeAgo     time.Duration
	LastDenyRule        string
	ToolSequence        []string
	RiskTrend           float64
	BaselineDeviation   float64
	BaselineEstablished bool // true only after 5+ minutes of traffic
}

// EWMABaseline tracks tool-usage distribution using exponential weighted moving average.
type EWMABaseline struct {
	weights     map[string]float64
	frozen      bool
	sampleCount int
	minSamples  int
	slowAlpha   float64
}

// NewEWMABaseline creates a new EWMA baseline tracker.
func NewEWMABaseline(slowAlpha float64, minSamples int) *EWMABaseline {
	return &EWMABaseline{
		weights:    make(map[string]float64),
		slowAlpha:  slowAlpha,
		minSamples: minSamples,
	}
}

func (b *EWMABaseline) Update(tool string) {
	if b.frozen {
		return
	}
	b.sampleCount++
	alpha := b.slowAlpha
	b.weights[tool] = b.weights[tool]*(1-alpha) + alpha
	for k := range b.weights {
		if k != tool {
			b.weights[k] = b.weights[k] * (1 - alpha)
		}
	}
}

func (b *EWMABaseline) Freeze() { b.frozen = true }

func (b *EWMABaseline) Established() bool { return b.sampleCount >= b.minSamples }

func (b *EWMABaseline) Deviation(tool string) float64 {
	if !b.Established() {
		return 0.0
	}
	w := b.weights[tool]
	maxW := 0.0
	for _, v := range b.weights {
		if v > maxW {
			maxW = v
		}
	}
	if maxW == 0 {
		return 0.0
	}
	return 1.0 - (w / maxW)
}

// Freeze freezes the session's EWMA baseline.
func (s *State) Freeze() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ewma.Freeze()
}
