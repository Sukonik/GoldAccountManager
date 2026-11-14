// Package server is the optional server mode of GoldAccountManager.
//
// It uses the same packet as the identity, then adds what a packet cannot do
// alone: a shared directory of public profiles, roles, sessions and admin
// tools. Login is challenge-response, so no password is ever stored.
package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Sukonik/goldaccountmanager/packet"
)

// Role controls what an account may do.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// Account is the server's record of a registered packet holder.
type Account struct {
	ID        string         `json:"id"`
	PublicKey string         `json:"public_key"`
	Role      Role           `json:"role"`
	Profile   map[string]any `json:"profile,omitempty"` // public profile only
	CreatedAt time.Time      `json:"created_at"`
}

// Store persists accounts. Swap in Postgres, SQLite or anything else.
type Store interface {
	Get(id string) (*Account, error)
	Put(a *Account) error
}

var ErrNotFound = errors.New("server: account not found")

// MemoryStore is an in-memory Store for tests and local development.
type MemoryStore struct {
	mu sync.RWMutex
	m  map[string]*Account
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{m: map[string]*Account{}} }

func (s *MemoryStore) Get(id string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.m[id]
	if !ok {
		return nil, ErrNotFound
	}
	c := *a
	return &c, nil
}

func (s *MemoryStore) Put(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := *a
	s.m[a.ID] = &c
	return nil
}

type session struct {
	accountID string
	expires   time.Time
}

type challenge struct {
	accountID string
	expires   time.Time
}

// Server wires the HTTP handlers to a Store.
type Server struct {
	store      Store
	mu         sync.Mutex
	challenges map[string]challenge // nonce -> challenge, single use
	sessions   map[string]session   // token -> session
	SessionTTL time.Duration
	now        func() time.Time
}

// New creates a Server backed by the given Store.
func New(store Store) *Server {
	return &Server{
		store:      store,
		challenges: map[string]challenge{},
		sessions:   map[string]session{},
		SessionTTL: 24 * time.Hour,
		now:        time.Now,
	}
}

// Handler returns the HTTP routes:
//
//	POST /register   body: packet JSON          -> account
//	POST /challenge  body: {"id": "..."}        -> {"nonce": "..."}
//	POST /login      body: {"id","nonce","signature"} -> {"token": "..."}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /challenge", s.challenge)
	mux.HandleFunc("POST /login", s.login)
	return mux
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&raw); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p, err := packet.Decode(raw)
	if err != nil {
		http.Error(w, "invalid packet", http.StatusBadRequest)
		return
	}
	if _, err := s.store.Get(p.ID); err == nil {
		http.Error(w, "already registered", http.StatusConflict)
		return
	}
	// Only the public profile is stored. Settings stay with the user.
	a := &Account{ID: p.ID, PublicKey: p.PublicKey, Role: RoleUser, Profile: p.Profile, CreatedAt: s.now().UTC()}
	if err := s.store.Put(a); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := s.store.Get(req.ID); err != nil {
		http.Error(w, "unknown account", http.StatusNotFound)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.challenges[nonce] = challenge{accountID: req.ID, expires: s.now().Add(2 * time.Minute)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"nonce": nonce})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID        string `json:"id"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"` // base64url
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	ch, ok := s.challenges[req.Nonce]
	delete(s.challenges, req.Nonce) // single use, even on failure
	s.mu.Unlock()
	if !ok || ch.accountID != req.ID || s.now().After(ch.expires) {
		http.Error(w, "invalid challenge", http.StatusUnauthorized)
		return
	}
	acct, err := s.store.Get(req.ID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	nonceBytes, err2 := base64.RawURLEncoding.DecodeString(req.Nonce)
	if err != nil || err2 != nil || !packet.VerifyChallenge(acct.PublicKey, nonceBytes, sig) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := randomToken(32)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.sessions[token] = session{accountID: acct.ID, expires: s.now().Add(s.SessionTTL)}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// Authenticate resolves a bearer token to its account. Use it in your own
// handlers, and RequireRole for admin routes.
func (s *Server) Authenticate(token string) (*Account, error) {
	s.mu.Lock()
	sess, ok := s.sessions[token]
	if ok && s.now().After(sess.expires) {
		delete(s.sessions, token)
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("server: invalid or expired session")
	}
	return s.store.Get(sess.accountID)
}

// RequireRole reports whether the account has at least the given role.
func RequireRole(a *Account, want Role) bool {
	if want == RoleUser {
		return a != nil
	}
	return a != nil && a.Role == want
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
