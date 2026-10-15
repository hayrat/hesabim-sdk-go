package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math"
	"sync"
	"time"
)

// Session is everything the BFF knows about one browser. It lives ONLY on the
// server; the browser holds nothing but an opaque, HttpOnly cookie with ID.
type Session struct {
	ID string

	// Pending login: written by /auth/login, consumed by /auth/callback.
	State        string
	Nonce        string
	CodeVerifier string
	ReturnTo     string

	// Established session: written by /auth/callback and every refresh.
	Subject      string
	AccessToken  string
	RefreshToken string // rotates on EVERY refresh — always store the new one
	IDToken      string // kept for id_token_hint at logout
	AccessExpiry time.Time

	// RefreshPending is written (conditionally) BEFORE a refresh request
	// leaves this server and cleared only by a stored outcome. Finding it set
	// means an earlier refresh may have spent the refresh token — a crash, a
	// lost lease, a failed write — so the token is never sent again.
	RefreshPending   bool
	RefreshStartedAt time.Time

	// Version is the store's optimistic-concurrency counter: Save succeeds
	// only if the stored row still has the version this copy was read with.
	Version int64
}

func (s *Session) authenticated() bool { return s.Subject != "" && s.RefreshToken != "" }

var (
	errNoSession = errors.New("no such session")
	errConflict  = errors.New("session changed or was deleted concurrently")
)

// Store persists sessions. The in-memory implementation below is for a single
// process. With more than one replica, implement this interface over Redis
// (one key per session, value = JSON, TTL = the ttl argument) — the handlers
// do not change.
type Store interface {
	// Get returns errNoSession if the session is absent or expired, and any
	// other error (connection, timeout) AS IS — the handlers answer those
	// with 503 and keep the cookie; only errNoSession means "logged out".
	Get(ctx context.Context, id string) (*Session, error)
	// Save writes s only if the stored row still has expectedVersion
	// (0 = the id must not exist yet: a new session), then sets s.Version to
	// the new version. Otherwise — another writer got there first, or the
	// session was deleted (logout, new login) — it returns errConflict and
	// writes nothing. With Redis this is one Lua script (IMPLEMENTATION.md §6.3).
	Save(ctx context.Context, s *Session, ttl time.Duration, expectedVersion int64) error
	Delete(ctx context.Context, id string) error
}

type memoryStore struct {
	mu   sync.Mutex
	rows map[string]memoryRow
}

type memoryRow struct {
	s       Session
	expires time.Time
}

func newMemoryStore() *memoryStore { return &memoryStore{rows: map[string]memoryRow{}} }

// Get returns a COPY: a handler mutating its session must Save it to make the
// change visible, exactly as it would with Redis.
func (m *memoryStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.rows[id]
	if !ok || time.Now().After(row.expires) {
		delete(m.rows, id)
		return nil, errNoSession
	}
	s := row.s
	return &s, nil
}

func (m *memoryStore) Save(_ context.Context, s *Session, ttl time.Duration, expectedVersion int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, exists := m.rows[s.ID]
	if exists && time.Now().After(row.expires) {
		delete(m.rows, s.ID)
		exists = false
	}
	switch {
	case expectedVersion == math.MaxInt64: // cannot advance; never wrap around
		return errConflict
	case expectedVersion == 0 && exists,
		expectedVersion != 0 && (!exists || row.s.Version != expectedVersion):
		return errConflict
	}
	s.Version = expectedVersion + 1
	m.rows[s.ID] = memoryRow{s: *s, expires: time.Now().Add(ttl)}
	return nil
}

func (m *memoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, id)
	return nil
}

// sessionLocks serializes refreshes per session. Two concurrent refreshes with
// the same refresh token are not a race you can win: the second one presents
// an already-rotated token, the issuer treats that as theft (reuse detection)
// and revokes the whole session. With more than one replica this must be a
// distributed lock with an owner token, a lease clearly longer than
// refreshBudget and compare-and-delete release — IMPLEMENTATION.md §6.3.
type sessionLocks struct{ m sync.Map }

func (l *sessionLocks) lock(id string) func() {
	v, _ := l.m.LoadOrStore(id, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

func (l *sessionLocks) forget(id string) { l.m.Delete(id) }

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
