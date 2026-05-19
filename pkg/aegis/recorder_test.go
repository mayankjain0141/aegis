package aegis

import (
	"sync"
	"testing"
)

// mockRecorder records calls for test inspection.
type mockRecorder struct {
	mu    sync.Mutex
	calls int
}

func (m *mockRecorder) Record(req *Request, d *Decision, composite float64, bundle interface{}) {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
}

func TestRecorder_WritesEveryDecision(t *testing.T) {
	rec := &mockRecorder{}
	rec.Record(&Request{}, &Decision{}, 0.5, nil)
	rec.Record(&Request{}, &Decision{}, 0.3, nil)
	if rec.calls != 2 {
		t.Errorf("expected 2 recorded calls, got %d", rec.calls)
	}
}

func TestRecorder_ConcurrentSafe(t *testing.T) {
	rec := &mockRecorder{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec.Record(&Request{}, &Decision{}, 0.5, nil)
		}()
	}
	wg.Wait()
	if rec.calls != 100 {
		t.Errorf("expected 100 calls, got %d", rec.calls)
	}
}
