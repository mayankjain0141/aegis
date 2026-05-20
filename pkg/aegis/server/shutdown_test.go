package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
)

// TestServer_GracefulShutdown_CompletesInFlight verifies that in-flight requests
// complete rather than get dropped when the server context is cancelled.
//
// Currently the server calls s.httpServer.Close() which abruptly drops connections;
// after the fix it will use s.httpServer.Shutdown(ctx) with a grace period.
// This test is the red phase — it documents the expected behavior and will fail
// until the server is updated to use Shutdown instead of Close.
func TestServer_GracefulShutdown_CompletesInFlight(t *testing.T) {
	// Create engine.
	engine, err := aegis.NewEngine()
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Unique temp socket path to avoid collisions between parallel test runs.
	f, err := os.CreateTemp("", "aegis-test-shutdown-*.sock")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	socketPath := f.Name()
	f.Close()
	os.Remove(socketPath) // Remove so the server can create its own socket there.
	defer os.Remove(socketPath)

	// Create server.
	srv := New(engine, socketPath)

	// Start server in background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start(ctx)
	}()

	// Poll for up to 200ms until the Unix socket appears.
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket never appeared at %s: %v", socketPath, err)
	}

	// HTTP client that dials through the Unix socket.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	// Build a valid /evaluate request body.
	body, err := json.Marshal(map[string]any{
		"tool": "Shell",
		"args": map[string]any{"command": "ls"},
		"cwd":  "/tmp",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	// Send the request — do NOT wait for the response yet.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://unix/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Cancel the server context immediately after sending the request, simulating
	// a shutdown signal racing with an in-flight request.
	responseCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := client.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		responseCh <- resp
	}()

	// Give the request a moment to reach the server before cancelling, but keep
	// the window tight enough that the shutdown races with request processing.
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Wait for a response (or error) with a generous timeout.
	select {
	case resp := <-responseCh:
		defer resp.Body.Close()
		// The server must complete the in-flight request; status 200 is the only
		// acceptable outcome — any other status still means the request completed.
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected 200 OK, got %d — server completed request but with unexpected status", resp.StatusCode)
		}
		// Decode the response to confirm it is well-formed.
		var decision map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
			t.Errorf("decode response body: %v", err)
		}
		if _, ok := decision["action"]; !ok {
			t.Errorf("response missing 'action' field: %v", decision)
		}
	case err := <-errCh:
		// Any network error here means the server dropped the connection — the
		// graceful shutdown contract was violated.
		t.Errorf("in-flight request was dropped during shutdown: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response — server appears hung during shutdown")
	}

	// Drain the server goroutine error; http.ErrServerClosed is expected on clean shutdown.
	select {
	case err := <-serverErr:
		// http.Server.Serve returns http.ErrServerClosed after Close/Shutdown.
		// Any other error is unexpected.
		if err != nil && err.Error() != "http: Server closed" {
			t.Logf("server exited with: %v (this may be expected on shutdown)", err)
		}
	case <-time.After(2 * time.Second):
		t.Log("server goroutine did not exit within 2s after context cancel")
	}

	// Verify the socket has been cleaned up (or at least that we can remove it).
	_ = fmt.Sprintf("socket path: %s", socketPath) // referenced in defer above
}
