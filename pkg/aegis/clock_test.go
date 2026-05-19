package aegis

import (
	"testing"
	"time"
)

var baseTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func TestClock_Deterministic(t *testing.T) {
	c1 := NewTestClock(baseTime)
	c2 := NewTestClock(baseTime)

	c1.Advance(5 * time.Second)
	c2.Advance(5 * time.Second)

	if c1.Now() != c2.Now() {
		t.Errorf("TestClock not deterministic: c1=%v c2=%v", c1.Now(), c2.Now())
	}

	c1.Advance(10 * time.Second)
	c2.Advance(10 * time.Second)

	if c1.Now() != c2.Now() {
		t.Errorf("TestClock diverged after second advance: c1=%v c2=%v", c1.Now(), c2.Now())
	}
}

func TestRealClock_ReturnsCurrentTime(t *testing.T) {
	before := time.Now()
	rc := RealClock{}
	got := rc.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("RealClock.Now() = %v, want between %v and %v", got, before, after)
	}
}
