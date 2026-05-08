package ws_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	ws "github.com/mayjain/aegis/internal/ws"
)

func startTestHub(t *testing.T) (*ws.Hub, context.CancelFunc) {
	t.Helper()
	hub := ws.NewHub()
	ctx, cancel := context.WithCancel(context.Background())
	go hub.Run(ctx)
	return hub, cancel
}

func startTestServer(t *testing.T, hub *ws.Hub) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			t.Logf("ws accept: %v", err)
			return
		}
		client := ws.NewClient(hub, conn)
		client.Serve(r.Context())
	}))
	return srv
}

func dialWS(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	return conn
}

func readMessage(t *testing.T, conn *websocket.Conn, timeout time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read ws: %v", err)
	}
	return string(data)
}

func TestHub_BroadcastToClients(t *testing.T) {
	hub, cancel := startTestHub(t)
	defer cancel()

	srv := startTestServer(t, hub)
	defer srv.Close()

	c1 := dialWS(t, srv)
	defer c1.CloseNow()
	c2 := dialWS(t, srv)
	defer c2.CloseNow()

	// Wait for clients to register
	deadline := time.Now().Add(2 * time.Second)
	for hub.ClientCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.ClientCount() < 2 {
		t.Fatal("clients did not register in time")
	}

	hub.Broadcast([]byte(`{"event":"test"}`))

	msg1 := readMessage(t, c1, 2*time.Second)
	msg2 := readMessage(t, c2, 2*time.Second)

	if msg1 != `{"event":"test"}` {
		t.Fatalf("c1 got %q", msg1)
	}
	if msg2 != `{"event":"test"}` {
		t.Fatalf("c2 got %q", msg2)
	}
}

func TestHub_ClientDisconnect_Cleaned(t *testing.T) {
	hub, cancel := startTestHub(t)
	defer cancel()

	srv := startTestServer(t, hub)
	defer srv.Close()

	c1 := dialWS(t, srv)

	deadline := time.Now().Add(2 * time.Second)
	for hub.ClientCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.ClientCount() != 1 {
		t.Fatalf("expected 1 client, got %d", hub.ClientCount())
	}

	c1.Close(websocket.StatusNormalClosure, "bye")

	deadline = time.Now().Add(2 * time.Second)
	for hub.ClientCount() > 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after disconnect, got %d", hub.ClientCount())
	}
}

func TestHub_ReplayOnConnect(t *testing.T) {
	hub, cancel := startTestHub(t)
	defer cancel()

	srv := startTestServer(t, hub)
	defer srv.Close()

	// Broadcast messages before any client connects
	for i := 0; i < 5; i++ {
		hub.Broadcast([]byte(`{"n":` + itoa(i) + `}`))
	}

	// Give hub time to process broadcasts
	time.Sleep(50 * time.Millisecond)

	c1 := dialWS(t, srv)
	defer c1.CloseNow()

	// New client should receive the 5 replayed messages
	for i := 0; i < 5; i++ {
		msg := readMessage(t, c1, 2*time.Second)
		expected := `{"n":` + itoa(i) + `}`
		if msg != expected {
			t.Fatalf("replay[%d]: got %q, want %q", i, msg, expected)
		}
	}
}

func TestHub_SlowClient_MessageDropped(t *testing.T) {
	hub, cancel := startTestHub(t)
	defer cancel()

	srv := startTestServer(t, hub)
	defer srv.Close()

	c1 := dialWS(t, srv)
	defer c1.CloseNow()

	deadline := time.Now().Add(2 * time.Second)
	for hub.ClientCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Flood the hub with more messages than the client send buffer (256)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			hub.Broadcast([]byte(`{"flood":` + itoa(i) + `}`))
		}
	}()
	wg.Wait()

	// Give hub time to process
	time.Sleep(100 * time.Millisecond)

	// Read what we can — the test passes if we don't hang (some messages dropped)
	received := 0
	for {
		ctx, ctxCancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, _, err := c1.Read(ctx)
		ctxCancel()
		if err != nil {
			break
		}
		received++
	}

	// We sent 500 but buffer is 256 — should have dropped some
	if received >= 500 {
		t.Fatalf("expected some messages to be dropped, but received all %d", received)
	}
	t.Logf("received %d/500 messages (dropped %d)", received, 500-received)
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
