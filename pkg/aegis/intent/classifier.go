// Package intent implements the Phase 3 LLM intent classifier.
// It is invoked only when Phase 1 and Phase 2 produce low-confidence decisions.
// The default fail-secure behavior: on any error → DENY.
package intent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// IntentSignal is the output of the LLM classifier.
type IntentSignal struct {
	Intent     string  // "legitimate", "suspicious", "malicious"
	Confidence float64 // LLM self-reported confidence 0-1
	Reasoning  string
	Model      string
	LatencyMs  int
	Cost       float64
}

// ClassifyRequest is the input to the classifier.
type ClassifyRequest struct {
	Tool        string
	Args        map[string]any
	SessionLast []SessionEntry // last 5 tool calls
	ProjectLang string         // go, python, node, etc.
}

// SessionEntry is a recent tool call for context.
type SessionEntry struct {
	Tool    string
	Summary string
	AgoS    int
}

// Classifier calls an LLM to determine intent for ambiguous cases.
type Classifier struct {
	client    *http.Client
	model     string
	apiKey    string
	baseURL   string
	timeout   time.Duration
	budget    *rateLimiter
	callCount atomic.Int64
	totalCost atomic.Value // float64
}

// New creates a classifier using the given model and API key env var.
// If apiKeyEnv is empty, tries OPENAI_API_KEY then ANTHROPIC_API_KEY.
func New(model, apiKeyEnv string, maxCallsPerMin int) (*Classifier, error) {
	if model == "" {
		model = "gpt-4o-mini"
	}
	if maxCallsPerMin <= 0 {
		maxCallsPerMin = 10
	}

	keyEnv := apiKeyEnv
	if keyEnv == "" {
		if os.Getenv("OPENAI_API_KEY") != "" {
			keyEnv = "OPENAI_API_KEY"
		} else if os.Getenv("ANTHROPIC_API_KEY") != "" {
			keyEnv = "ANTHROPIC_API_KEY"
		}
	}

	key := os.Getenv(keyEnv)
	if key == "" {
		return nil, fmt.Errorf("no API key found (set %s)", keyEnv)
	}

	baseURL := "https://api.openai.com/v1"
	if keyEnv == "ANTHROPIC_API_KEY" {
		baseURL = "https://api.anthropic.com/v1"
	}

	c := &Classifier{
		client:  &http.Client{Timeout: 10 * time.Second},
		model:   model,
		apiKey:  key,
		baseURL: baseURL,
		timeout: 500 * time.Millisecond,
		budget:  newRateLimiter(maxCallsPerMin),
	}
	c.totalCost.Store(float64(0))
	return c, nil
}

// Classify sends the request to the LLM and returns the intent signal.
// Returns an error and fail-secure (deny) on any failure.
func (c *Classifier) Classify(ctx context.Context, req *ClassifyRequest) (*IntentSignal, error) {
	if !c.budget.Allow() {
		return nil, fmt.Errorf("budget exceeded: max %d calls/minute reached", c.budget.max)
	}

	prompt := buildPrompt(req)

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	start := time.Now()
	raw, model, err := c.callLLM(ctx, prompt)
	latency := int(time.Since(start).Milliseconds())

	if err != nil {
		return nil, fmt.Errorf("LLM call failed: %w", err)
	}

	sig, err := parseResponse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse LLM response: %w", err)
	}

	sig.Model = model
	sig.LatencyMs = latency
	c.callCount.Add(1)

	return sig, nil
}

func buildPrompt(req *ClassifyRequest) string {
	argsJSON, _ := json.Marshal(req.Args)

	context := ""
	for _, e := range req.SessionLast {
		context += fmt.Sprintf("  - %ds ago: %s(%s)\n", e.AgoS, e.Tool, e.Summary)
	}
	if context == "" {
		context = "  (no recent calls)\n"
	}

	projectCtx := ""
	if req.ProjectLang != "" {
		projectCtx = fmt.Sprintf("\nProject type: %s", req.ProjectLang)
	}

	return fmt.Sprintf(`You are a security classifier for AI agent tool calls. Classify the intent of this tool call.

Tool: %s
Arguments: %s%s

Recent session context:
%s
Respond with ONLY valid JSON (no markdown, no explanation):
{"intent": "legitimate|suspicious|malicious", "confidence": 0.0-1.0, "reasoning": "one sentence"}

Guidelines:
- "legitimate": normal development work (building, testing, deploying, reading docs)
- "suspicious": unusual but possibly justified; needs human review
- "malicious": clearly attempting unauthorized access, exfiltration, or destruction
- confidence should reflect your certainty; if uncertain use 0.5-0.6`,
		req.Tool, string(argsJSON), projectCtx, context)
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Model string `json:"model"`
}

func (c *Classifier) callLLM(ctx context.Context, prompt string) (string, string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens":  256,
		"temperature": 0,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", "", fmt.Errorf("LLM API error %d: %s", resp.StatusCode, body)
	}

	var oai openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&oai); err != nil {
		return "", "", fmt.Errorf("decode response: %w", err)
	}
	if len(oai.Choices) == 0 {
		return "", "", fmt.Errorf("no choices in response")
	}
	return oai.Choices[0].Message.Content, oai.Model, nil
}

type llmOutput struct {
	Intent     string  `json:"intent"`
	Confidence float64 `json:"confidence"`
	Reasoning  string  `json:"reasoning"`
}

func parseResponse(raw string) (*IntentSignal, error) {
	var out llmOutput
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("invalid JSON from LLM: %w", err)
	}
	switch out.Intent {
	case "legitimate", "suspicious", "malicious":
	default:
		return nil, fmt.Errorf("unexpected intent value: %q", out.Intent)
	}
	return &IntentSignal{
		Intent:     out.Intent,
		Confidence: out.Confidence,
		Reasoning:  out.Reasoning,
	}, nil
}

// rateLimiter is a simple token-bucket rate limiter.
type rateLimiter struct {
	max      int
	tokens   int
	lastReset time.Time
	mu       chan struct{}
}

func newRateLimiter(maxPerMin int) *rateLimiter {
	r := &rateLimiter{
		max:      maxPerMin,
		tokens:   maxPerMin,
		lastReset: time.Now(),
		mu:       make(chan struct{}, 1),
	}
	r.mu <- struct{}{}
	return r
}

func (r *rateLimiter) Allow() bool {
	<-r.mu
	defer func() { r.mu <- struct{}{} }()

	now := time.Now()
	if now.Sub(r.lastReset) >= time.Minute {
		r.tokens = r.max
		r.lastReset = now
	}
	if r.tokens <= 0 {
		return false
	}
	r.tokens--
	return true
}
