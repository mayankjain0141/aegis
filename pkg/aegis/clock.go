package aegis

import "time"

// Clock abstracts time so tests can control it deterministically.
type Clock interface {
	Now() time.Time
}

// RealClock uses the system clock. Used in production.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// TestClock is a controllable clock for tests. Start from a fixed base and
// advance manually. Two TestClocks with the same base and same Advance calls
// always produce identical Now() — enabling replay determinism.
type TestClock struct {
	t time.Time
}

func NewTestClock(base time.Time) *TestClock  { return &TestClock{t: base} }
func (c *TestClock) Now() time.Time           { return c.t }
func (c *TestClock) Advance(d time.Duration)  { c.t = c.t.Add(d) }
