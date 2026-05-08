package circuit

import (
	"sync"
	"time"
)

// State represents the circuit breaker state.
type State int

const (
	Closed   State = iota // normal — requests pass through
	Open                  // broken — reject immediately
	HalfOpen              // probing — allow one request
)

func (s State) String() string {
	switch s {
	case Closed:
		return "closed"
	case Open:
		return "open"
	case HalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

const (
	DefaultThreshold = 5
	DefaultCooldown  = 30 * time.Second
)

// Breaker implements a per-tool-server circuit breaker state machine.
type Breaker struct {
	name        string
	state       State
	failures    int
	threshold   int
	cooldown    time.Duration
	lastFailure time.Time
	mu          sync.Mutex
}

func NewBreaker(name string, threshold int, cooldown time.Duration) *Breaker {
	return &Breaker{
		name:      name,
		state:     Closed,
		threshold: threshold,
		cooldown:  cooldown,
	}
}

// Allow reports whether a request should be permitted through the breaker.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state {
	case Closed:
		return true
	case Open:
		if time.Since(b.lastFailure) >= b.cooldown {
			b.state = HalfOpen
			return true
		}
		return false
	case HalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful call. In HalfOpen, this closes the breaker.
func (b *Breaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == HalfOpen {
		b.state = Closed
		b.failures = 0
	}
}

// RecordFailure records a failed call.
// In Closed: increments failure count, trips to Open if threshold exceeded.
// In HalfOpen: immediately re-opens.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.lastFailure = time.Now()

	switch b.state {
	case Closed:
		b.failures++
		if b.failures >= b.threshold {
			b.state = Open
		}
	case HalfOpen:
		b.state = Open
		b.failures = 0
	}
}

// State returns the current breaker state.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Reset resets the breaker to Closed with zero failures.
func (b *Breaker) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = Closed
	b.failures = 0
	b.lastFailure = time.Time{}
}
