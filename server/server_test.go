package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sukonik/goldaccountmanager/packet"
)

func post(t *testing.T, h http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRegisterAndLogin(t *testing.T) {
	srv := New(NewMemoryStore())
	h := srv.Handler()

	id, _ := packet.NewIdentity()
	p, _ := id.NewPacket(map[string]any{"name": "Nathan"}, map[string]any{"private": "stays local"})
	data, _ := p.Encode()

	if rec := post(t, h, "/register", data); rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body)
	}
	if rec := post(t, h, "/register", data); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register should conflict, got %d", rec.Code)
	}
	acct, _ := srv.store.Get(p.ID)
	if _, leaked := acct.Profile["private"]; leaked {
		t.Fatal("settings must not be stored on the server")
	}

	body, _ := json.Marshal(map[string]string{"id": p.ID})
	rec := post(t, h, "/challenge", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge: %d", rec.Code)
	}
	var ch struct{ Nonce string }
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
	sig := base64.RawURLEncoding.EncodeToString(id.SignChallenge(nonce))

	login, _ := json.Marshal(map[string]string{"id": p.ID, "nonce": ch.Nonce, "signature": sig})
	rec = post(t, h, "/login", login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	var tok struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &tok)
	got, err := srv.Authenticate(tok.Token)
	if err != nil || got.ID != p.ID {
		t.Fatalf("authenticate: %v", err)
	}

	// nonce is single use
	if rec := post(t, h, "/login", login); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed login should fail, got %d", rec.Code)
	}
}

func TestLoginRejectsWrongKey(t *testing.T) {
	srv := New(NewMemoryStore())
	h := srv.Handler()
	victim, _ := packet.NewIdentity()
	attacker, _ := packet.NewIdentity()
	p, _ := victim.NewPacket(nil, nil)
	data, _ := p.Encode()
	post(t, h, "/register", data)

	body, _ := json.Marshal(map[string]string{"id": p.ID})
	rec := post(t, h, "/challenge", body)
	var ch struct{ Nonce string }
	_ = json.Unmarshal(rec.Body.Bytes(), &ch)
	nonce, _ := base64.RawURLEncoding.DecodeString(ch.Nonce)
	sig := base64.RawURLEncoding.EncodeToString(attacker.SignChallenge(nonce))
	login, _ := json.Marshal(map[string]string{"id": p.ID, "nonce": ch.Nonce, "signature": sig})
	if rec := post(t, h, "/login", login); rec.Code != http.StatusUnauthorized {
		t.Fatalf("attacker login should fail, got %d", rec.Code)
	}
}

func TestRegisterRejectsTamperedPacket(t *testing.T) {
	srv := New(NewMemoryStore())
	id, _ := packet.NewIdentity()
	p, _ := id.NewPacket(map[string]any{"name": "A"}, nil)
	p.Profile["name"] = "B"
	data, _ := json.Marshal(p)
	if rec := post(t, srv.Handler(), "/register", data); rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered packet should be rejected, got %d", rec.Code)
	}
}
