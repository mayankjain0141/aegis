package telemetry

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Event is a single decision record in the audit WAL.
type Event struct {
	Time           time.Time `json:"time"`
	AgentID        string    `json:"agent_id,omitempty"`
	Tool           string    `json:"tool"`
	ArgSummary     string    `json:"arg_summary,omitempty"`
	Action         string    `json:"action"`
	Rule           string    `json:"rule"`
	Severity       string    `json:"severity,omitempty"`
	Confidence     float64   `json:"confidence"`
	CompositeScore float64   `json:"composite_score"`
	Phase          int       `json:"phase"`
	LatencyUs      int64     `json:"latency_us"`
}

// WAL is a thread-safe append-only JSONL writer.
type WAL struct {
	path string
	f    *os.File
	enc  *json.Encoder
	mu   sync.Mutex
}

// Open opens or creates the WAL file at path.
func Open(path string) (*WAL, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open WAL %s: %w", path, err)
	}
	return &WAL{path: path, f: f, enc: json.NewEncoder(f)}, nil
}

// Write appends an event. Thread-safe.
func (w *WAL) Write(ev Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(ev)
}

// Close flushes and closes.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.f.Close()
}

// ReadAll reads all events from a WAL file.
func ReadAll(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var events []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events, sc.Err()
}

// Stats summarizes events.
type Stats struct {
	Total     int
	ByAction  map[string]int
	ByRule    map[string]int
	FirstTime time.Time
	LastTime  time.Time
}

// Summarize computes stats from events.
func Summarize(events []Event) Stats {
	s := Stats{
		Total:    len(events),
		ByAction: make(map[string]int),
		ByRule:   make(map[string]int),
	}
	for i, ev := range events {
		s.ByAction[ev.Action]++
		s.ByRule[ev.Rule]++
		if i == 0 {
			s.FirstTime = ev.Time
		}
		s.LastTime = ev.Time
	}
	return s
}

// TopRules returns the top n rules by count.
func TopRules(byRule map[string]int, n int) []struct {
	Rule  string
	Count int
} {
	type kv struct {
		Rule  string
		Count int
	}
	var kvs []kv
	for k, v := range byRule {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].Count > kvs[j].Count })
	if len(kvs) > n {
		kvs = kvs[:n]
	}
	result := make([]struct {
		Rule  string
		Count int
	}, len(kvs))
	for i, k := range kvs {
		result[i] = struct {
			Rule  string
			Count int
		}{k.Rule, k.Count}
	}
	return result
}
