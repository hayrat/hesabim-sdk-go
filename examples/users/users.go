// Package users is the application's own projection of Hesabım users.
//
// Hesabım is an identity provider, not a user directory: there is no endpoint
// that lists users or returns someone else's profile. An application that needs
// to show "who did this" keeps its own users table, keyed by the token's `sub`,
// and refreshes the row every time that user signs in.
//
// `sub` is the user's permanent UUID at the issuer. It never changes and is
// never reused, even when the user changes their e-mail or phone, so it is the
// PRIMARY KEY — never an e-mail address, never a phone number (neither is in
// any token anyway).
package users

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	hesabim "github.com/hayrat/hesabim-sdk-go"
)

// User is one row of the projection. Add your application's own columns next
// to these (class, school, preferences…) — the issuer will never hold them.
type User struct {
	Sub        string // users.sub — UUID from the token, primary key
	Name       string // ID token `name`: first and last name in ONE field
	Gender     string // ID token `gender`: "male", "female" or ""
	ProfileVer int64  // `hayrat_profile_ver` from the VERIFIED access token; 0 if absent
	LastSeenAt time.Time
}

// Store persists the projection.
type Store interface {
	// Upsert creates the row on first sign-in and refreshes name/gender on
	// every later one.
	Upsert(ctx context.Context, u User) error
	Get(ctx context.Context, sub string) (User, bool, error)
}

// PostgresSchema is the minimal table. Run it as a migration in your project.
const PostgresSchema = `
CREATE TABLE IF NOT EXISTS users (
    sub          UUID PRIMARY KEY,
    name         TEXT        NOT NULL DEFAULT '',
    gender       TEXT        NOT NULL DEFAULT '' CHECK (gender IN ('', 'male', 'female')),
    profile_ver  BIGINT      NOT NULL DEFAULT 0,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);`

// SQLStore is a database/sql implementation for PostgreSQL. It imports no
// driver; open the *sql.DB with whichever driver your project already uses
// (pgx stdlib, lib/pq).
type SQLStore struct{ DB *sql.DB }

func (s SQLStore) Upsert(ctx context.Context, u User) error {
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO users (sub, name, gender, profile_ver, last_seen_at)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (sub) DO UPDATE
SET name = EXCLUDED.name, gender = EXCLUDED.gender,
    profile_ver = EXCLUDED.profile_ver, last_seen_at = EXCLUDED.last_seen_at`,
		u.Sub, u.Name, u.Gender, u.ProfileVer, u.LastSeenAt)
	return err
}

func (s SQLStore) Get(ctx context.Context, sub string) (User, bool, error) {
	var u User
	err := s.DB.QueryRowContext(ctx,
		`SELECT sub, name, gender, profile_ver, last_seen_at FROM users WHERE sub = $1`, sub).
		Scan(&u.Sub, &u.Name, &u.Gender, &u.ProfileVer, &u.LastSeenAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, false, nil
	}
	return u, err == nil, err
}

// MemoryStore is for tests and local experiments only.
type MemoryStore struct {
	mu   sync.Mutex
	rows map[string]User
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{rows: map[string]User{}} }

func (m *MemoryStore) Upsert(_ context.Context, u User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[u.Sub] = u
	return nil
}

func (m *MemoryStore) Get(_ context.Context, sub string) (User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.rows[sub]
	return u, ok, nil
}

// ValidGender reports whether g is a value the issuer emits (or empty).
func ValidGender(g string) bool { return g == "" || g == "male" || g == "female" }

const maxNameRunes = 200

// SyncHandler serves `POST /api/me/sync` for the SPA topology.
//
// In that topology the backend only ever sees the ACCESS token, which carries
// no name. The browser SDK reads `name`/`gender` from the ID token it verified
// (`hesabim.getUser()`) and posts them here after every login (and whenever
// `user.profileVersion` changes):
//
//	await fetch('/api/me/sync', { method: 'POST',
//	  headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
//	  body: JSON.stringify({ name: user.name ?? null, gender: user.gender ?? null }) })
//
// A null or missing name/gender is stored as "". Any other field in the body
// (sub, profile_ver…) is ignored.
//
// The row's KEY comes from the verified access token, so a caller can only ever
// write their own row; so does profile_ver (`hayrat_profile_ver`), which the
// issuer signed. The name and gender in the body are asserted by the
// user's own browser: treat them as display data, never as an input to an
// authorization decision. If the application needs issuer-attested profile
// data, use the BFF topology, where the backend verifies the ID token itself.
//
// Must be mounted behind Verifier.Middleware.
func SyncHandler(store Store) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := hesabim.FromContext(r.Context())
		if !ok {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		var body struct {
			Name   string `json:"name"`
			Gender string `json:"gender"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		body.Name = strings.TrimSpace(body.Name)
		if utf8.RuneCountInString(body.Name) > maxNameRunes || !ValidGender(body.Gender) {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		u := User{Sub: p.Subject, Name: body.Name, Gender: body.Gender, ProfileVer: p.ProfileVersion, LastSeenAt: time.Now().UTC()}
		if err := store.Upsert(r.Context(), u); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
