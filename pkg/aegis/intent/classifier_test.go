package intent

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockLLMServer creates a test HTTP server returning the given body and status code.
// The LLM response body must be a valid OpenAI-compatible chat completion response.
func mockLLMServer(t *testing.T, intentJSON string, statusCode int, delayMs int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if delayMs > 0 {
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
		if statusCode != http.StatusOK {
			http.Error(w, "server error", statusCode)
			return
		}
		// Wrap intent JSON as the content field inside a chat completion response
		body := fmt.Sprintf(`{"choices":[{"message":{"content":%s}}],"model":"gpt-4o-mini"}`,
			intentJSON)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, body)
	}))
}

// newTestClassifier creates a Classifier pointing at the given server URL.
func newTestClassifier(t *testing.T, serverURL string, maxCallsPerMin int) *Classifier {
	t.Helper()
	if maxCallsPerMin == 0 {
		maxCallsPerMin = 10
	}
	c := &Classifier{
		client:  &http.Client{Timeout: 5 * time.Second},
		model:   "gpt-4o-mini",
		apiKey:  "test-key",
		baseURL: serverURL + "/v1",
		timeout: 2 * time.Second,
		budget:  newRateLimiter(maxCallsPerMin),
	}
	c.totalCost.Store(float64(0))
	return c
}

// ── Rate limiter tests ────────────────────────────────────────────────────

func TestRateLimiter_AllowsUpToMax(t *testing.T) {
	rl := newRateLimiter(3)
	for i := 0; i < 3; i++ {
		if !rl.Allow() {
			t.Fatalf("Allow() %d: want true, got false", i+1)
		}
	}
	// Budget exhausted
	if rl.Allow() {
		t.Error("Allow() 4th call: want false (budget exhausted)")
	}
}

func TestRateLimiter_ZeroMaxAlwaysBlocks(t *testing.T) {
	rl := newRateLimiter(0)
	if rl.Allow() {
		t.Error("Allow() with max=0: want false")
	}
}

func TestRateLimiter_ResetsAfterMinute(t *testing.T) {
	rl := newRateLimiter(2)
	rl.Allow() //nolint
	rl.Allow() //nolint
	if rl.Allow() {
		t.Fatal("budget should be exhausted")
	}

	// Simulate time passing by backdating lastReset
	<-rl.mu
	rl.lastReset = time.Now().Add(-2 * time.Minute)
	rl.tokens = 0
	rl.mu <- struct{}{}

	if !rl.Allow() {
		t.Error("Allow() after reset: want true")
	}
}

// ── parseResponse tests ───────────────────────────────────────────────────

func TestParseResponse_Malicious(t *testing.T) {
	sig, err := parseResponse(`{"intent":"malicious","confidence":0.95,"reasoning":"dangerous rm command"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Intent != "malicious" {
		t.Errorf("intent: want malicious, got %q", sig.Intent)
	}
	if sig.Confidence != 0.95 {
		t.Errorf("confidence: want 0.95, got %.2f", sig.Confidence)
	}
}

func TestParseResponse_Legitimate(t *testing.T) {
	sig, err := parseResponse(`{"intent":"legitimate","confidence":0.92,"reasoning":"normal git workflow"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Intent != "legitimate" {
		t.Errorf("intent: want legitimate, got %q", sig.Intent)
	}
}

func TestParseResponse_Suspicious(t *testing.T) {
	sig, err := parseResponse(`{"intent":"suspicious","confidence":0.88,"reasoning":"unusual network activity"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Intent != "suspicious" {
		t.Errorf("intent: want suspicious, got %q", sig.Intent)
	}
}

func TestParseResponse_UnknownIntent(t *testing.T) {
	_, err := parseResponse(`{"intent":"confused","confidence":0.9,"reasoning":"???"}`)
	if err == nil {
		t.Error("expected error for unknown intent value")
	}
	if !strings.Contains(err.Error(), "unexpected intent") {
		t.Errorf("error should mention unexpected intent, got: %v", err)
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	_, err := parseResponse(`{not valid json`)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseResponse_MissingIntentField(t *testing.T) {
	_, err := parseResponse(`{"confidence":0.9,"reasoning":"ok"}`)
	if err == nil {
		t.Error("expected error for missing intent field (empty string fails validation)")
	}
}

// ── Classify() integration tests ─────────────────────────────────────────

func TestClassify_MaliciousHighConfidence(t *testing.T) {
	srv := mockLLMServer(t, `"{\"intent\":\"malicious\",\"confidence\":0.95,\"reasoning\":\"rm -rf attack\"}"`, 200, 0)
	defer srv.Close()

	c := newTestClassifier(t, srv.URL, 10)
	sig, err := c.Classify(context.Background(), &ClassifyRequest{Tool: "Shell", Args: map[string]any{"command": "rm -rf /etc"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Intent != "malicious" {
		t.Errorf("intent: want malicious, got %q", sig.Intent)
	}
	if sig.Confidence != 0.95 {
		t.Errorf("confidence: want 0.95, got %.2f", sig.Confidence)
	}
}

func TestClassify_LegitimateHighConfidence(t *testing.T) {
	srv := mockLLMServer(t, `"{\"intent\":\"legitimate\",\"confidence\":0.92,\"reasoning\":\"normal dev work\"}"`, 200, 0)
	defer srv.Close()

	c := newTestClassifier(t, srv.URL, 10)
	sig, err := c.Classify(context.Background(), &ClassifyRequest{Tool: "Shell", Args: map[string]any{"command": "git status"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sig.Intent != "legitimate" {
		t.Errorf("intent: want legitimate, got %q", sig.Intent)
	}
}

func TestClassify_HTTPError(t *testing.T) {
	srv := mockLLMServer(t, "", 503, 0)
	defer srv.Close()

	c := newTestClassifier(t, srv.URL, 10)
	_, err := c.Classify(context.Background(), &ClassifyRequest{Tool: "Shell"})
	if err == nil {
		t.Fatal("expected error for HTTP 503")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should mention status 503, got: %v", err)
	}
}

func TestClassify_BudgetExhausted(t *testing.T) {
	srv := mockLLMServer(t, `"{\"intent\":\"legitimate\",\"confidence\":0.9,\"reasoning\":\"ok\"}"`, 200, 0)
	defer srv.Close()

	// max=1 call per minute
	c := newTestClassifier(t, srv.URL, 1)
	req := &ClassifyRequest{Tool: "Shell", Args: map[string]any{"command": "git status"}}

	_, err := c.Classify(context.Background(), req) // uses the 1 allowed call
	if err != nil {
		t.Fatalf("first call unexpected error: %v", err)
	}

	_, err = c.Classify(context.Background(), req) // budget exhausted
	if err == nil {
		t.Fatal("expected error when budget exhausted")
	}
	if !strings.Contains(err.Error(), "budget exceeded") {
		t.Errorf("error should mention budget exceeded, got: %v", err)
	}
}

func TestClassify_ContextCancelled(t *testing.T) {
	// Server that delays 200ms; context expires in 5ms
	srv := mockLLMServer(t, `"{\"intent\":\"legitimate\",\"confidence\":0.9,\"reasoning\":\"ok\"}"`, 200, 200)
	defer srv.Close()

	c := newTestClassifier(t, srv.URL, 10)
	c.timeout = 5 * time.Millisecond // very short timeout

	ctx := context.Background()
	_, err := c.Classify(ctx, &ClassifyRequest{Tool: "Shell"})
	if err == nil {
		t.Error("expected timeout error for slow server")
	}
}
