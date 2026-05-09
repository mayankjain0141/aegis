package trace

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func makeEvent(tool string) *TraceEvent {
	return &TraceEvent{
		SessionID: "sess-001",
		RequestID: "req-001",
		AgentID:   "agent-001",
		Timestamp: time.Now(),
		Tool:      tool,
		RiskScore: 0.5,
		Decision:  "allow",
		Mode:      "enforce",
		LatencyUs: 10,
	}
}

func TestCollector_EmitAndFlush(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())
	defer bc.Close()

	bc.Emit(makeEvent("shell_exec"))
	bc.Emit(makeEvent("file_read"))
	bc.Emit(makeEvent("file_write"))

	// Wait for flush (timer-based)
	time.Sleep(200 * time.Millisecond)

	written, dropped := bc.Stats()
	if written != 3 {
		t.Errorf("written = %d, want 3", written)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

func TestCollector_NonBlocking_WhenFull(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())
	defer bc.Close()

	// Fill the channel
	for i := 0; i < defaultChannelSize; i++ {
		bc.ch <- makeEvent("filler")
	}

	// This should NOT block
	done := make(chan struct{})
	go func() {
		bc.Emit(makeEvent("overflow"))
		close(done)
	}()

	select {
	case <-done:
		// Good — Emit returned immediately
	case <-time.After(1 * time.Second):
		t.Fatal("Emit blocked when channel was full")
	}
}

func TestCollector_DroppedCounter(t *testing.T) {
	// Use a tiny channel (size 1) with a long flush interval so the loop
	// can't drain fast enough for our rapid-fire emits.
	bc := newBatchCollector(nil, testLogger(), 1, defaultBatchSize, 10*time.Second)

	// Fill the single slot — the loop might grab it, but we'll overshoot
	// enough to guarantee drops.
	bc.Emit(makeEvent("slot"))

	// These should all be dropped since channel is full and interval is huge
	// We need to give the loop time to potentially consume, but with a 10s
	// flush interval and batch size 64, the loop will block on the timer,
	// leaving our 1-slot channel occupied.
	time.Sleep(5 * time.Millisecond)

	dropped := int64(0)
	for i := 0; i < 100; i++ {
		bc.Emit(makeEvent("overflow"))
	}
	_, dropped = bc.Stats()
	if dropped == 0 {
		t.Error("expected some dropped events when channel is saturated")
	}

	bc.Close()
}

func TestCollector_FlushOnInterval(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())
	defer bc.Close()

	bc.Emit(makeEvent("timer_test"))

	// Wait for the flush interval (100ms) plus buffer
	time.Sleep(250 * time.Millisecond)

	written, _ := bc.Stats()
	if written < 1 {
		t.Errorf("expected at least 1 written by timer, got %d", written)
	}
}

func TestCollector_FlushOnBatchSize(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())
	defer bc.Close()

	// Emit exactly defaultBatchSize events (64) rapidly
	for i := 0; i < defaultBatchSize; i++ {
		bc.Emit(makeEvent("batch_fill"))
	}

	// Give the background loop time to drain and flush
	time.Sleep(50 * time.Millisecond)

	written, _ := bc.Stats()
	if written < int64(defaultBatchSize) {
		t.Errorf("written = %d, want at least %d (batch size trigger)", written, defaultBatchSize)
	}
}

func TestCollector_Close_DrainsRemaining(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())

	// Emit a few events
	for i := 0; i < 5; i++ {
		bc.Emit(makeEvent("drain_test"))
	}

	// Close should drain and flush remaining
	if err := bc.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	written, dropped := bc.Stats()
	if written != 5 {
		t.Errorf("written = %d, want 5", written)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

func TestCollector_ConcurrentEmit(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())

	const goroutines = 10
	const eventsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < eventsPerGoroutine; i++ {
				bc.Emit(makeEvent("concurrent"))
			}
		}()
	}
	wg.Wait()

	if err := bc.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}

	written, dropped := bc.Stats()
	total := written + dropped
	expected := int64(goroutines * eventsPerGoroutine)
	if total != expected {
		t.Errorf("written(%d) + dropped(%d) = %d, want %d", written, dropped, total, expected)
	}
}

func TestCollector_CloseIdempotent(t *testing.T) {
	bc := NewBatchCollector(nil, testLogger())
	bc.Emit(makeEvent("idempotent"))

	if err := bc.Close(); err != nil {
		t.Fatalf("first Close error: %v", err)
	}
	if err := bc.Close(); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
}
