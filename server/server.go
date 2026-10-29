package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/verify"
)

// Request size limits. Everything the API accepts is tiny.
const (
	maxJSONBody = 4 << 10
	maxFormBody = 2 << 10
)

type outcome int

const (
	waiting outcome = iota
	confirmed
	full
	waitlisted
)

// confirmation is one unfinished or just-finished email confirmation. It holds
// a hash of the pickup secret, never the secret, and the subject hash, never
// the address.
type confirmation struct {
	appID      string
	packetID   string
	subject    string
	pickupHash [sha256.Size]byte
	expires    time.Time
	outcome    outcome
	att        *packet.Attestation
}

type ctxKey struct{}

// startInfo travels in the context from the start handler to the channel's
// Deliver function, which runs inside Start.
type startInfo struct {
	app  *App
	conf *confirmation
}

// Server is the confirmation service. Create one with New and serve Handler.
type Server struct {
	cfg     Config
	apps    map[string]*App
	channel *verify.MagicLinkChannel
	limit   *limiter
	log     *slog.Logger
	base    string

	mu      sync.Mutex
	pending map[string]*confirmation
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, apps: map[string]*App{}, limit: newLimiter(), log: cfg.Logger,
		base: strings.TrimRight(cfg.BaseURL, "/"), pending: map[string]*confirmation{},
	}
	for i := range cfg.Apps {
		a := cfg.Apps[i]
		if a.OnLimit == "" {
			a.OnLimit = LimitBlock
		}
		s.apps[a.ID] = &a
	}
	s.channel = &verify.MagicLinkChannel{TTL: cfg.LinkTTL, Now: cfg.Now, Max: cfg.MaxPending, Deliver: s.deliver}
	return s, nil
}

// Handler returns the HTTP handler. It does not terminate TLS: run it behind
// HTTPS, and set an http.Server with timeouts around it (cmd/goldd does).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/apps/{app}/confirm/start", s.handleStart)
	mux.HandleFunc("POST /v1/apps/{app}/confirm/pickup", s.handlePickup)
	mux.HandleFunc("OPTIONS /v1/apps/{app}/confirm/{action}", s.handlePreflight)
	mux.HandleFunc("GET /v1/confirm/link", s.handleLinkPage)
	mux.HandleFunc("POST /v1/confirm/link", s.handleLinkConfirm)
	mux.HandleFunc("GET /v1/keys", s.handleKeys)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		secureHeaders(w, false)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	if s.cfg.Dev {
		mux.HandleFunc("GET /dev/inbox", s.handleDevInbox)
	}
	return mux
}

// ---------- helpers ----------

func secureHeaders(w http.ResponseWriter, page bool) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer") // confirmation links carry a secret in the URL
	h.Set("X-Frame-Options", "DENY")
	if page {
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	} else {
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// apiError is the body of every error. Messages are fixed text and never echo
// request input.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: code, Message: msg})
}

// readJSON decodes a small, strict JSON request body into dst.
func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		fail(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "send Content-Type: application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			fail(w, http.StatusRequestEntityTooLarge, "too_large", "the request is too large")
			return false
		}
		fail(w, http.StatusBadRequest, "bad_request", "the request body is not valid for this endpoint")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "bad_request", "the request body has extra data")
		return false
	}
	return true
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1]) // the entry our own proxy appended
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cors answers browser calls from an app's allowed origins and no others.
// CORS is not authentication: it only lets a browser page read the response.
func (s *Server) cors(w http.ResponseWriter, r *http.Request, app *App) {
	origin := r.Header.Get("Origin")
	if origin == "" || !app.allowsOrigin(origin) {
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Allow-Methods", "POST")
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	h.Set("Access-Control-Max-Age", "600")
}

func (s *Server) app(w http.ResponseWriter, r *http.Request) *App {
	app := s.apps[r.PathValue("app")]
	if app == nil {
		secureHeaders(w, false)
		fail(w, http.StatusNotFound, "unknown_app", "no such app")
	}
	return app
}

func randomSecret() (secret string, hash [sha256.Size]byte, err error) {
	var raw [32]byte
	if _, err = rand.Read(raw[:]); err != nil {
		return "", hash, err
	}
	secret = base64.RawURLEncoding.EncodeToString(raw[:])
	return secret, sha256.Sum256([]byte(secret)), nil
}

// prune drops expired confirmations. Callers hold s.mu.
func (s *Server) prune(now time.Time) {
	for id, c := range s.pending {
		if !now.Before(c.expires) {
			delete(s.pending, id)
		}
	}
}

// ---------- start ----------

type startRequest struct {
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	PacketID string `json:"packetId"`
	Method   string `json:"method"`
}

type startResponse struct {
	ChallengeID string `json:"challengeId"`
	Pickup      string `json:"pickup"`
	ExpiresIn   int    `json:"expiresIn"`
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	secureHeaders(w, false)
	if app := s.apps[r.PathValue("app")]; app != nil {
		s.cors(w, r, app)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	secureHeaders(w, false)
	app := s.app(w, r)
	if app == nil {
		return
	}
	s.cors(w, r, app)

	var req startRequest
	if !readJSON(w, r, &req) {
		return
	}
	method := packet.Method(req.Method)
	if req.Method == "" {
		method = packet.MethodEmailLink
	}
	if packet.Kind(req.Kind) != packet.KindEmail || !app.allows(method) || method != packet.MethodEmailLink {
		fail(w, http.StatusBadRequest, "unsupported", "this app confirms email addresses by link only")
		return
	}
	if !packet.IsPacketID(req.PacketID) {
		fail(w, http.StatusBadRequest, "bad_request", "packetId is not a valid packet id")
		return
	}
	email, err := verify.Normalize(packet.KindEmail, req.Target)
	if err != nil {
		fail(w, http.StatusBadRequest, "bad_request", "target is not a valid email address")
		return
	}
	subject, err := verify.Subject(app.Secret, app.ID, packet.KindEmail, email)
	if err != nil {
		s.log.Error("subject hash failed", "app", app.ID)
		fail(w, http.StatusInternalServerError, "server_error", "something went wrong")
		return
	}

	now := s.cfg.Now()
	if !s.limit.allow("ip:"+app.ID+":"+s.clientIP(r), s.cfg.StartsPerIPPerHour, time.Hour, now) ||
		!s.limit.allow("sub:"+app.ID+":"+subject, s.cfg.StartsPerSubjectPerHour, time.Hour, now) {
		w.Header().Set("Retry-After", "3600")
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many requests, try again later")
		return
	}

	pickup, pickupHash, err := randomSecret()
	if err != nil {
		fail(w, http.StatusInternalServerError, "server_error", "something went wrong")
		return
	}
	conf := &confirmation{appID: app.ID, packetID: req.PacketID, subject: subject, pickupHash: pickupHash, expires: now.Add(s.cfg.LinkTTL)}

	s.mu.Lock()
	s.prune(now)
	busy := len(s.pending) >= s.cfg.MaxPending
	s.mu.Unlock()
	if busy {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusServiceUnavailable, "busy", "the service is busy, try again shortly")
		return
	}

	// Start generates the challenge, calls s.deliver (which records conf and
	// sends the email), and returns the challenge id.
	ctx := context.WithValue(r.Context(), ctxKey{}, &startInfo{app: app, conf: conf})
	id, err := s.channel.Start(ctx, email)
	switch {
	case errors.Is(err, verify.ErrRateLimited):
		fail(w, http.StatusServiceUnavailable, "busy", "the service is busy, try again shortly")
		return
	case err != nil:
		s.log.Warn("confirmation email failed", "app", app.ID) // no address, no error text that could contain one
		fail(w, http.StatusBadGateway, "mail_failed", "the email could not be sent, try again later")
		return
	}
	s.log.Info("confirmation started", "app", app.ID)
	writeJSON(w, http.StatusAccepted, startResponse{ChallengeID: id, Pickup: pickup, ExpiresIn: int(s.cfg.LinkTTL.Seconds())})
}

// deliver is the channel's Deliver function. It records the confirmation before
// the email goes out, so a fast click can never arrive first.
func (s *Server) deliver(ctx context.Context, target, challengeID, token string) error {
	info, _ := ctx.Value(ctxKey{}).(*startInfo)
	if info == nil {
		return errors.New("server: missing start context")
	}
	s.mu.Lock()
	s.pending[challengeID] = info.conf
	s.mu.Unlock()

	link := s.base + "/v1/confirm/link?" + url.Values{"c": {challengeID}, "t": {token}}.Encode()
	err := s.cfg.Mailer.SendMagicLink(ctx, MagicLink{To: target, AppName: info.app.Name, Link: link, ExpiresIn: s.cfg.LinkTTL})
	if err != nil {
		s.mu.Lock()
		delete(s.pending, challengeID)
		s.mu.Unlock()
	}
	return err
}

// ---------- the link the user opens ----------

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{{.Title}}</title>
<style>
body{font:16px/1.6 system-ui,sans-serif;margin:0;background:#f4f7ff;color:#0b1530;display:grid;place-items:center;min-height:100vh}
main{background:#fff;border:1px solid #d3dcf0;border-radius:16px;padding:32px;max-width:440px;margin:16px}
h1{font-size:1.4rem;margin:0 0 12px}p{margin:0 0 16px}
button{min-height:44px;padding:0 24px;border:0;border-radius:10px;background:#1a4fd6;color:#fff;font:inherit;font-weight:650;cursor:pointer}
button:focus-visible{outline:2px solid #1a4fd6;outline-offset:2px}
@media (prefers-color-scheme:dark){body{background:#0a1226;color:#e8eeff}main{background:#111c38;border-color:#22325a}button{background:#6c9bff;color:#06122e}}
</style></head><body><main>
<h1>{{.Title}}</h1>
<p>{{.Message}}</p>
{{if .Form}}<form method="post" action="/v1/confirm/link"><input type="hidden" name="c" value="{{.C}}"><input type="hidden" name="t" value="{{.T}}"><button type="submit">Confirm</button></form>{{end}}
</main></body></html>
`))

type page struct {
	Title, Message string
	Form           bool
	C, T           string
}

func renderPage(w http.ResponseWriter, status int, p page) {
	secureHeaders(w, true)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = pageTmpl.Execute(w, p)
}

var invalidPage = page{Title: "This link does not work", Message: "It may have expired or already been used. Go back to the app and ask for a new one."}

// handleLinkPage shows a Confirm button. It changes nothing: mail scanners and
// link previews open every link in a message.
func (s *Server) handleLinkPage(w http.ResponseWriter, r *http.Request) {
	c, t := r.URL.Query().Get("c"), r.URL.Query().Get("t")
	s.mu.Lock()
	conf := s.pending[c]
	ok := conf != nil && conf.outcome == waiting && s.cfg.Now().Before(conf.expires)
	var name string
	if ok {
		name = s.apps[conf.appID].Name
	}
	s.mu.Unlock()
	if !ok || len(t) > 64 {
		renderPage(w, http.StatusNotFound, invalidPage)
		return
	}
	renderPage(w, http.StatusOK, page{Title: "Confirm your email", Message: "Press Confirm to finish confirming your email address for " + name + ".", Form: true, C: c, T: t})
}

func (s *Server) handleLinkConfirm(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		renderPage(w, http.StatusBadRequest, invalidPage)
		return
	}
	c, t := r.PostForm.Get("c"), r.PostForm.Get("t")

	s.mu.Lock()
	conf := s.pending[c]
	live := conf != nil && conf.outcome == waiting && s.cfg.Now().Before(conf.expires)
	s.mu.Unlock()
	if !live {
		renderPage(w, http.StatusBadRequest, invalidPage)
		return
	}
	if _, err := s.channel.Complete(r.Context(), c, t); err != nil {
		renderPage(w, http.StatusBadRequest, invalidPage)
		return
	}

	app := s.apps[conf.appID]
	res, err := s.cfg.Store.Admit(app.ID, conf.subject, app.MaxSubjects)
	if err != nil {
		s.log.Error("store failed", "app", app.ID)
		renderPage(w, http.StatusInternalServerError, page{Title: "Something went wrong", Message: "Please try again in a moment."})
		return
	}

	now := s.cfg.Now()
	switch {
	case res.Admitted:
		att, err := s.cfg.Signer.Attest(app.ID, conf.packetID, packet.KindEmail, packet.MethodEmailLink, conf.subject, now, now.Add(app.ttl()))
		if err != nil {
			s.log.Error("signing failed", "app", app.ID)
			renderPage(w, http.StatusInternalServerError, page{Title: "Something went wrong", Message: "Please try again in a moment."})
			return
		}
		s.mu.Lock()
		conf.outcome, conf.att = confirmed, &att
		s.mu.Unlock()
		s.log.Info("confirmation completed", "app", app.ID, "outcome", "confirmed")
		renderPage(w, http.StatusOK, page{Title: "Email confirmed", Message: "You can go back to " + app.Name + ". It will pick this up by itself."})
	case app.OnLimit == LimitWaitlist:
		_ = s.cfg.Store.Waitlist(app.ID, conf.subject)
		s.mu.Lock()
		conf.outcome = waitlisted
		s.mu.Unlock()
		s.log.Info("confirmation completed", "app", app.ID, "outcome", "waitlisted")
		renderPage(w, http.StatusOK, page{Title: "You are on the waitlist", Message: app.Name + " is full right now. Your email address was added to the waitlist."})
	default:
		s.mu.Lock()
		conf.outcome = full
		s.mu.Unlock()
		s.log.Info("confirmation completed", "app", app.ID, "outcome", "full")
		renderPage(w, http.StatusOK, page{Title: "This app is full", Message: app.Name + " is not accepting new people right now. Your existing account, if you have one, is not affected."})
	}
}

// ---------- pickup ----------

type pickupRequest struct {
	ChallengeID string `json:"challengeId"`
	Pickup      string `json:"pickup"`
}

type pickupResponse struct {
	Status      string              `json:"status"` // pending, confirmed, full or waitlisted
	Attestation *packet.Attestation `json:"attestation,omitempty"`
}

func (s *Server) handlePickup(w http.ResponseWriter, r *http.Request) {
	secureHeaders(w, false)
	app := s.app(w, r)
	if app == nil {
		return
	}
	s.cors(w, r, app)
	var req pickupRequest
	if !readJSON(w, r, &req) {
		return
	}
	now := s.cfg.Now()
	// Polling is limited per challenge, so a leaked challenge id cannot be used to hammer the server.
	if !s.limit.allow("pickup:"+req.ChallengeID, 120, 10*time.Minute, now) {
		w.Header().Set("Retry-After", "60")
		fail(w, http.StatusTooManyRequests, "rate_limited", "too many requests, try again later")
		return
	}
	got := sha256.Sum256([]byte(req.Pickup))

	s.mu.Lock()
	conf := s.pending[req.ChallengeID]
	// The same "not found" for a wrong id, a wrong secret, another app and an
	// expired challenge: a caller learns nothing about which part was wrong.
	if conf == nil || conf.appID != app.ID || !now.Before(conf.expires) || subtle.ConstantTimeCompare(got[:], conf.pickupHash[:]) != 1 {
		s.mu.Unlock()
		fail(w, http.StatusNotFound, "not_found", "no such confirmation")
		return
	}
	resp := pickupResponse{Status: "pending"}
	status := http.StatusAccepted
	switch conf.outcome {
	case confirmed:
		resp, status = pickupResponse{Status: "confirmed", Attestation: conf.att}, http.StatusOK
		delete(s.pending, req.ChallengeID) // handed over once
	case full:
		resp, status = pickupResponse{Status: "full"}, http.StatusOK
		delete(s.pending, req.ChallengeID)
	case waitlisted:
		resp, status = pickupResponse{Status: "waitlisted"}, http.StatusOK
		delete(s.pending, req.ChallengeID)
	}
	s.mu.Unlock()
	writeJSON(w, status, resp)
}

// ---------- keys and dev ----------

type keyInfo struct {
	KeyID     string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"` // base64url, no padding
}

// handleKeys publishes the public key apps use to check attestations.
func (s *Server) handleKeys(w http.ResponseWriter, _ *http.Request) {
	secureHeaders(w, false)
	writeJSON(w, http.StatusOK, map[string][]keyInfo{"keys": {{
		KeyID: s.cfg.Signer.KeyID(), Algorithm: "ed25519",
		PublicKey: base64.RawURLEncoding.EncodeToString(s.cfg.Signer.PublicKey()),
	}}})
}

func (s *Server) handleDevInbox(w http.ResponseWriter, _ *http.Request) {
	secureHeaders(w, false)
	d, ok := s.cfg.Mailer.(*DevMailer)
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "the dev inbox needs the dev mailer")
		return
	}
	type item struct {
		To      string `json:"to"`
		App     string `json:"app"`
		Link    string `json:"link"`
		Minutes int    `json:"expiresInMinutes"`
	}
	sent := d.Sent()
	out := make([]item, 0, len(sent))
	for i := len(sent) - 1; i >= 0; i-- { // newest first
		out = append(out, item{To: sent[i].To, App: sent[i].AppName, Link: sent[i].Link, Minutes: int(sent[i].ExpiresIn.Minutes())})
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": out})
}
