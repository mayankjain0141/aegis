package circuit

import (
	"testing"
	"time"
)

func TestBreaker_StartsClosed(t *testing.T) {
	b := NewBreaker("test", 5, 30*time.Second)
	if s := b.State(); s != Closed {
		t.Errorf("state = %v, want Closed", s)
	}
	if !b.Allow() {
		t.Error("Allow() = false, want true for Closed breaker")
	}
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	b := NewBreaker("test", 3, 30*time.Second)

	for i := 0; i < 3; i++ {
		b.RecordFailure()
	}

	if s := b.State(); s != Open {
		t.Errorf("state = %v, want Open after %d failures", s, 3)
	}
}

func TestBreaker_RejectsFast_WhenOpen(t *testing.T) {
	b := NewBreaker("test", 2, 1*time.Hour)

	b.RecordFailure()
	b.RecordFailure()

	if b.State() != Open {
		t.Fatal("expected Open state")
	}
	if b.Allow() {
		t.Error("Allow() = true, want false when Open and cooldown not elapsed")
	}
}

func TestBreaker_TransitionsToHalfOpen_AfterCooldown(t *testing.T) {
	b := NewBreaker("test", 2, 10*time.Millisecond)

	b.RecordFailure()
	b.RecordFailure()

	if b.State() != Open {
		t.Fatal("expected Open state")
	}

	time.Sleep(15 * time.Millisecond)

	if !b.Allow() {
		t.Error("Allow() = false, expected true after cooldown (transition to HalfOpen)")
	}
	if s := b.State(); s != HalfOpen {
		t.Errorf("state = %v, want HalfOpen after cooldown", s)
	}
}

func TestBreaker_ClosesOnSuccessfulProbe(t *testing.T) {
	b := NewBreaker("test", 2, 10*time.Millisecond)

	b.RecordFailure()
	b.RecordFailure()

	time.Sleep(15 * time.Millisecond)

	// Transition to HalfOpen
	if !b.Allow() {
		t.Fatal("expected Allow() = true to transition to HalfOpen")
	}

	// Successful probe
	b.RecordSuccess()

	if s := b.State(); s != Closed {
		t.Errorf("state = %v, want Closed after successful probe", s)
	}
	if !b.Allow() {
		t.Error("Allow() = false, want true after breaker closed")
	}
}

func TestBreaker_ReopensOnFailedProbe(t *testing.T) {
	b := NewBreaker("test", 2, 10*time.Millisecond)

	b.RecordFailure()
	b.RecordFailure()

	time.Sleep(15 * time.Millisecond)

	// Transition to HalfOpen
	if !b.Allow() {
		t.Fatal("expected Allow() = true to transition to HalfOpen")
	}

	// Failed probe
	b.RecordFailure()

	if s := b.State(); s != Open {
		t.Errorf("state = %v, want Open after failed probe in HalfOpen", s)
	}
	if b.Allow() {
		t.Error("Allow() = true, want false immediately after re-opening")
	}
}
