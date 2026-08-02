package proxy

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// SessionStore hands out sticky IPRoyal session IDs keyed by caller-
// chosen string (e.g. profile+destination host), reusing an existing
// unexpired ID rather than minting a new one — that's what makes a
// session "sticky" (same exit IP) for its TTL. Safe for concurrent use.
type SessionStore struct {
	mu      sync.Mutex
	entries map[string]sessionEntry
}

type sessionEntry struct {
	id        string
	expiresAt time.Time
}

func NewSessionStore() *SessionStore {
	return &SessionStore{entries: make(map[string]sessionEntry)}
}

// GetOrCreate returns the current sticky session ID for key if one
// exists and hasn't expired, otherwise mints a fresh 8-char alphanumeric
// ID (matching IPRoyal's documented session format) valid for ttl.
func (s *SessionStore) GetOrCreate(key string, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.entries[key]; ok && time.Now().Before(e.expiresAt) {
		return e.id, nil
	}

	id, err := newSessionID()
	if err != nil {
		return "", fmt.Errorf("sessionstore: generate id: %w", err)
	}
	s.entries[key] = sessionEntry{id: id, expiresAt: time.Now().Add(ttl)}
	return id, nil
}

const sessionIDAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func newSessionID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	out := make([]byte, 8)
	for i, v := range raw {
		out[i] = sessionIDAlphabet[int(v)%len(sessionIDAlphabet)]
	}
	return string(out), nil
}
