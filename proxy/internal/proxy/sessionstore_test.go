package proxy

import (
	"testing"
	"time"
)

func TestSessionStore_ReusesWithinTTL(t *testing.T) {
	s := NewSessionStore()
	id1, err := s.GetOrCreate("key", time.Hour)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	id2, err := s.GetOrCreate("key", time.Hour)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if id1 != id2 {
		t.Errorf("expected same session id within TTL, got %q then %q", id1, id2)
	}
	if len(id1) != 8 {
		t.Errorf("session id length = %d, want 8 (IPRoyal's documented format)", len(id1))
	}
}

func TestSessionStore_NewIDAfterExpiry(t *testing.T) {
	s := NewSessionStore()
	id1, err := s.GetOrCreate("key", 10*time.Millisecond)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	time.Sleep(30 * time.Millisecond)
	id2, err := s.GetOrCreate("key", time.Hour)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if id1 == id2 {
		t.Error("expected a new session id after expiry, got the same one")
	}
}

func TestSessionStore_IndependentKeys(t *testing.T) {
	s := NewSessionStore()
	idA, _ := s.GetOrCreate("a", time.Hour)
	idB, _ := s.GetOrCreate("b", time.Hour)
	if idA == idB {
		t.Error("different keys got the same session id (astronomically unlikely unless something's wrong)")
	}
}
