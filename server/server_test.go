package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/verify"
)

var epoch = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// clock is a settable time source shared by the server and the test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func secretFor(name string) []byte {
	sum := sha256.Sum256([]byte("test secret " + name))
	return sum[:]
}

type env struct {
	ts     *httptest.Server
	srv    *Server
	mail   *DevMailer
	store  *MemoryStore
	signer *verify.Signer
	clk    *clock
	logs   *bytes.Buffer
}

// newEnv starts a real HTTP server on a loopback port with three apps: an
// unlimited one, a tiny one that blocks new people, and one with a waitlist.
func newEnv(t *testing.T, tweak func(*Config)) *env {
	t.Helper()
	seed := sha256.Sum256([]byte("test signing key"))
	signer, err := verify.NewSigner("test-key", ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{mail: &DevMailer{}, store: NewMemoryStore(), signer: signer, clk: &clock{t: epoch}, logs: &bytes.Buffer{}}
	e.ts = httptest.NewUnstartedServer(nil)
	cfg := Config{
		BaseURL: "http://" + e.ts.Listener.Addr().String(),
		Apps: []App{
			{ID: "notes-demo", Name: "Notes Demo", Secret: secretFor("notes"), Origins: []string{"https://notes.example.com"}},
			{ID: "tiny-app", Name: "Tiny App", Secret: secretFor("tiny"), MaxSubjects: 1},
			{ID: "wait-app", Name: "Wait App", Secret: secretFor("wait"), MaxSubjects: 1, OnLimit: LimitWaitlist},
		},
		Signer: signer, Mailer: e.mail, Store: e.store, Now: e.clk.now,
		Logger: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tweak != nil {
		tweak(&cfg)
	}
	e.srv, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.ts.Config.Handler = e.srv.Handler()
	e.ts.Start()
	t.Cleanup(e.ts.Close)
	return e
}

type reply struct {
	status int
	header http.Header
	body   string
}

func (r reply) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(r.body), v); err != nil {
		t.Fatalf("not JSON (%d): %q", r.status, r.body)
	}
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func do(t *testing.T, req *http.Request) reply {
	t.Helper()
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, resp.Header, string(b)}
}

func (e *env) post(t *testing.T, path, body string, headers ...string) reply {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	return do(t, req)
}

func (e *env) get(t *testing.T, path string) reply {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
	return do(t, req)
}

type started struct{ ChallengeID, Pickup, Link string }

func jsonBody(v any) string { b, _ := json.Marshal(v); return string(b) }

// start asks for a confirmation and returns the challenge, the pickup secret and
// the link from the email that was "sent".
func (e *env) start(t *testing.T, app, email, packetID string) started {
	t.Helper()
	r := e.post(t, "/v1/apps/"+app+"/confirm/start", jsonBody(map[string]string{"kind": "email", "target": email, "packetId": packetID}))
	if r.status != http.StatusAccepted {
		t.Fatalf("start: %d %s", r.status, r.body)
	}
	var sr struct {
		ChallengeID string `json:"challengeId"`
		Pickup      string `json:"pickup"`
	}
	r.json(t, &sr)
	sent := e.mail.Sent()
	if len(sent) == 0 {
		t.Fatal("no email was sent")
	}
	return started{sr.ChallengeID, sr.Pickup, sent[len(sent)-1].Link}
}

// press opens the link's form target the way a browser's Confirm button does.
func (e *env) press(t *testing.T, link string) reply {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"c": {u.Query().Get("c")}, "t": {u.Query().Get("t")}}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/v1/confirm/link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(t, req)
}

func (e *env) pickup(t *testing.T, app string, s started) reply {
	t.Helper()
	return e.post(t, "/v1/apps/"+app+"/confirm/pickup", jsonBody(map[string]string{"challengeId": s.ChallengeID, "pickup": s.Pickup}))
}

type pickupBody struct {
	Status      string              `json:"status"`
	Attestation *packet.Attestation `json:"attestation"`
}

func pk(t *testing.T) string { t.Helper(); return packet.NewID("pk") }

func TestHappyPathIssuesAnAttestationThatVerifies(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	p, _ := packet.New("notes-demo", "Sam's notes", packet.AppInfo{}, epoch)
	s := e.start(t, "notes-demo", "Sam@Example.com", p.PacketID)

	if !strings.HasPrefix(s.Link, e.ts.URL+"/v1/confirm/link?") {
		t.Fatalf("link should use the configured base address, got %s", s.Link)
	}
	if got := e.mail.Sent()[0].To; got != "sam@example.com" {
		t.Errorf("email went to %q, want the normalized address", got)
	}

	var pb pickupBody
	r := e.pickup(t, "notes-demo", s)
	r.json(t, &pb)
	if r.status != http.StatusAccepted || pb.Status != "pending" {
		t.Fatalf("before confirming: %d %s", r.status, r.body)
	}

	page := e.press(t, s.Link)
	if page.status != http.StatusOK || !strings.Contains(page.body, "Email confirmed") {
		t.Fatalf("confirm page: %d %s", page.status, page.body)
	}

	r = e.pickup(t, "notes-demo", s)
	r.json(t, &pb)
	if r.status != http.StatusOK || pb.Status != "confirmed" || pb.Attestation == nil {
		t.Fatalf("after confirming: %d %s", r.status, r.body)
	}

	// The attestation goes into the packet and verifies against the published key.
	p.Attestations = append(p.Attestations, *pb.Attestation)
	file, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, warns, err := packet.Parse(file, packet.ParseOptions{ExpectAppID: "notes-demo"})
	if err != nil || len(warns) != 0 {
		t.Fatalf("packet with attestation: %v %v", err, warns)
	}
	var keys struct {
		Keys []struct{ KeyID, Algorithm, PublicKey string }
	}
	kr := e.get(t, "/v1/keys")
	if kr.status != http.StatusOK {
		t.Fatalf("keys: %d", kr.status)
	}
	if err := json.Unmarshal([]byte(strings.NewReplacer(`"keyId"`, `"KeyID"`, `"algorithm"`, `"Algorithm"`, `"publicKey"`, `"PublicKey"`).Replace(kr.body)), &keys); err != nil || len(keys.Keys) != 1 {
		t.Fatalf("keys body: %s", kr.body)
	}
	pub, _ := base64.RawURLEncoding.DecodeString(keys.Keys[0].PublicKey)
	checker := verify.NewChecker(map[string]ed25519.PublicKey{keys.Keys[0].KeyID: pub})
	res := checker.Check(back, e.clk.now())
	if len(res) != 1 || res[0].Status != verify.Valid || res[0].Attestation.Method != packet.MethodEmailLink {
		t.Fatalf("attestation does not verify: %+v", res)
	}

	// The subject is the keyed hash of the address, and the address appears nowhere.
	want, _ := verify.Subject(secretFor("notes"), "notes-demo", packet.KindEmail, "sam@example.com")
	if pb.Attestation.Subject != want {
		t.Error("subject is not the keyed hash of the normalized address")
	}
	if strings.Contains(string(file), "example.com") {
		t.Error("the packet must not contain the email address")
	}

	// Handed over once.
	if again := e.pickup(t, "notes-demo", s); again.status != http.StatusNotFound {
		t.Errorf("second pickup = %d, want 404", again.status)
	}
	// An attestation for one packet does not work on another.
	other, _ := packet.New("notes-demo", "Other", packet.AppInfo{}, epoch)
	other.Attestations = []packet.Attestation{*pb.Attestation}
	if r := checker.Check(other, e.clk.now()); r[0].Status != verify.BadSig {
		t.Errorf("attestation moved to another packet: %s", r[0].Status)
	}
}

func TestOpeningTheLinkNeverConfirms(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	s := e.start(t, "notes-demo", "a@example.com", pk(t))

	// A mail scanner or link preview fetches the link, perhaps several times.
	for i := 0; i < 3; i++ {
		page := e.get(t, strings.TrimPrefix(s.Link, e.ts.URL))
		if page.status != http.StatusOK || !strings.Contains(page.body, `<button type="submit">Confirm</button>`) {
			t.Fatalf("link page: %d %s", page.status, page.body)
		}
	}
	var pb pickupBody
	e.pickup(t, "notes-demo", s).json(t, &pb)
	if pb.Status != "pending" {
		t.Fatalf("a GET confirmed the address: %+v", pb)
	}
	if r := e.press(t, s.Link); r.status != http.StatusOK {
		t.Fatalf("pressing Confirm: %d", r.status)
	}
	e.pickup(t, "notes-demo", s).json(t, &pb)
	if pb.Status != "confirmed" {
		t.Fatalf("status = %s", pb.Status)
	}
}

func TestWrongTokenAndReplay(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	s := e.start(t, "notes-demo", "a@example.com", pk(t))
	u, _ := url.Parse(s.Link)

	bad := url.Values{"c": {u.Query().Get("c")}, "t": {"not-the-token"}}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/v1/confirm/link", strings.NewReader(bad.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if r := do(t, req); r.status != http.StatusBadRequest || !strings.Contains(r.body, "does not work") {
		t.Fatalf("wrong token: %d", r.status)
	}
	if r := e.press(t, s.Link); r.status != http.StatusOK {
		t.Fatalf("real token after a wrong one: %d", r.status)
	}
	if r := e.press(t, s.Link); r.status != http.StatusBadRequest {
		t.Fatalf("replaying the link = %d, want 400", r.status)
	}
	if r := e.get(t, strings.TrimPrefix(s.Link, e.ts.URL)); r.status != http.StatusNotFound {
		t.Fatalf("opening a used link = %d, want 404", r.status)
	}
	// Garbage and a GET carrying a form are refused without echoing input.
	r := e.get(t, "/v1/confirm/link?c=%3Cscript%3Ealert(1)%3C/script%3E&t=x")
	if r.status != http.StatusNotFound || strings.Contains(r.body, "alert(1)") {
		t.Fatalf("garbage link: %d %q", r.status, r.body)
	}
}

func TestPickupLeaksNothingAboutWhatWasWrong(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	s := e.start(t, "notes-demo", "a@example.com", pk(t))

	cases := map[string]reply{
		"wrong pickup secret": e.post(t, "/v1/apps/notes-demo/confirm/pickup", jsonBody(map[string]string{"challengeId": s.ChallengeID, "pickup": "wrong"})),
		"unknown challenge":   e.post(t, "/v1/apps/notes-demo/confirm/pickup", jsonBody(map[string]string{"challengeId": "ch_nope", "pickup": s.Pickup})),
		"another app":         e.post(t, "/v1/apps/tiny-app/confirm/pickup", jsonBody(map[string]string{"challengeId": s.ChallengeID, "pickup": s.Pickup})),
	}
	var first string
	for name, r := range cases {
		if r.status != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", name, r.status)
		}
		if first == "" {
			first = r.body
		} else if r.body != first {
			t.Errorf("%s: body differs, so it reveals which part was wrong", name)
		}
	}
	if r := e.pickup(t, "notes-demo", s); r.status != http.StatusAccepted {
		t.Errorf("the real secret still works after wrong attempts: %d", r.status)
	}
}

func TestStartRejectsBadRequests(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	good := map[string]string{"kind": "email", "target": "a@example.com", "packetId": pk(t)}
	with := func(k, v string) string {
		m := map[string]string{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[k] = v
		return jsonBody(m)
	}
	tests := []struct {
		name string
		path string
		body string
		ct   string
		want int
	}{
		{"unknown app", "/v1/apps/nope/confirm/start", jsonBody(good), "application/json", 404},
		{"not json", "/v1/apps/notes-demo/confirm/start", "nope", "application/json", 400},
		{"unknown field", "/v1/apps/notes-demo/confirm/start", `{"kind":"email","target":"a@example.com","packetId":"` + good["packetId"] + `","extra":1}`, "application/json", 400},
		{"trailing data", "/v1/apps/notes-demo/confirm/start", jsonBody(good) + `{}`, "application/json", 400},
		{"wrong content type", "/v1/apps/notes-demo/confirm/start", jsonBody(good), "text/plain", 415},
		{"too large", "/v1/apps/notes-demo/confirm/start", `{"target":"` + strings.Repeat("a", 5000) + `"}`, "application/json", 413},
		{"phone not offered", "/v1/apps/notes-demo/confirm/start", with("kind", "phone"), "application/json", 400},
		{"sms not offered", "/v1/apps/notes-demo/confirm/start", with("method", "sms"), "application/json", 400},
		{"bad email", "/v1/apps/notes-demo/confirm/start", with("target", "not an email"), "application/json", 400},
		{"header injection in email", "/v1/apps/notes-demo/confirm/start", with("target", "a@example.com\r\nBcc: x@y.co"), "application/json", 400},
		{"bad packet id", "/v1/apps/notes-demo/confirm/start", with("packetId", "pk_BAD"), "application/json", 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, _ := http.NewRequest(http.MethodPost, e.ts.URL+tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.ct)
			r := do(t, req)
			if r.status != tc.want {
				t.Fatalf("status %d, want %d (%s)", r.status, tc.want, r.body)
			}
			var ae apiError
			r.json(t, &ae)
			if ae.Error == "" || strings.Contains(r.body, "Bcc") {
				t.Errorf("bad error body: %s", r.body)
			}
		})
	}
	if n := len(e.mail.Sent()); n != 0 {
		t.Errorf("%d emails were sent for rejected requests", n)
	}
	// Methods other than POST are refused by the router.
	req, _ := http.NewRequest(http.MethodGet, e.ts.URL+"/v1/apps/notes-demo/confirm/start", nil)
	if r := do(t, req); r.status != http.StatusMethodNotAllowed {
		t.Errorf("GET start = %d, want 405", r.status)
	}
}

func TestStartLooksTheSameForEveryAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	e.start(t, "tiny-app", "member@example.com", pk(t))
	// Whether or not an address is already a member, the reply has the same shape.
	shape := func(email string) []string {
		r := e.post(t, "/v1/apps/tiny-app/confirm/start", jsonBody(map[string]string{"kind": "email", "target": email, "packetId": pk(t)}))
		var m map[string]any
		r.json(t, &m)
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		return append(keys, http.StatusText(r.status))
	}
	a, b := shape("member@example.com"), shape("stranger@example.com")
	if len(a) != len(b) || a[len(a)-1] != b[len(b)-1] {
		t.Errorf("replies differ: %v vs %v", a, b)
	}
}

func TestRateLimits(t *testing.T) {
	t.Parallel()
	t.Run("per address", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, nil)
		for i := 1; i <= 7; i++ {
			// Different clients, so only the per-address limit can trip.
			r := e.post(t, "/v1/apps/notes-demo/confirm/start", jsonBody(map[string]string{"kind": "email", "target": "victim@example.com", "packetId": pk(t)}), "X-Forwarded-For", "198.51.100."+string(rune('0'+i)))
			want := http.StatusAccepted
			if i > 5 {
				want = http.StatusTooManyRequests
			}
			if r.status != want {
				t.Fatalf("request %d: %d, want %d", i, r.status, want)
			}
		}
		if n := len(e.mail.Sent()); n != 5 {
			t.Errorf("%d emails sent, want 5: the victim must not be mail-bombed", n)
		}
	})
	t.Run("per client", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, nil)
		for i := 1; i <= 22; i++ {
			r := e.post(t, "/v1/apps/notes-demo/confirm/start", jsonBody(map[string]string{"kind": "email", "target": "user" + strings.Repeat("x", i) + "@example.com", "packetId": pk(t)}))
			want := http.StatusAccepted
			if i > 20 {
				want = http.StatusTooManyRequests
			}
			if r.status != want {
				t.Fatalf("request %d: %d, want %d", i, r.status, want)
			}
		}
	})
	t.Run("forwarded header is ignored unless trusted", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, nil) // not trusted: a client cannot dodge the limit by lying
		for i := 1; i <= 21; i++ {
			r := e.post(t, "/v1/apps/notes-demo/confirm/start", jsonBody(map[string]string{"kind": "email", "target": "u" + strings.Repeat("y", i) + "@example.com", "packetId": pk(t)}), "X-Forwarded-For", "203.0.113."+string(rune('a'+i)))
			if i == 21 && r.status != http.StatusTooManyRequests {
				t.Fatalf("a forged X-Forwarded-For dodged the limit: %d", r.status)
			}
		}
	})
	t.Run("window resets", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, nil)
		for i := 0; i < 5; i++ {
			e.start(t, "notes-demo", "a@example.com", pk(t))
		}
		if r := e.post(t, "/v1/apps/notes-demo/confirm/start", jsonBody(map[string]string{"kind": "email", "target": "a@example.com", "packetId": pk(t)})); r.status != 429 {
			t.Fatalf("sixth: %d", r.status)
		}
		e.clk.advance(61 * time.Minute)
		e.start(t, "notes-demo", "a@example.com", pk(t))
	})
	t.Run("pickup polling is limited per challenge", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, nil)
		s := e.start(t, "notes-demo", "a@example.com", pk(t))
		limited := false
		for i := 0; i < 130; i++ {
			if e.pickup(t, "notes-demo", s).status == http.StatusTooManyRequests {
				limited = true
				break
			}
		}
		if !limited {
			t.Error("polling was never limited")
		}
	})
}

func TestQuotaBlocksNewPeopleButNeverExistingOnes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	confirmAs := func(email string) (pickupBody, reply) {
		s := e.start(t, "tiny-app", email, pk(t))
		page := e.press(t, s.Link)
		var pb pickupBody
		e.pickup(t, "tiny-app", s).json(t, &pb)
		return pb, page
	}
	if pb, _ := confirmAs("first@example.com"); pb.Status != "confirmed" {
		t.Fatalf("first person: %s", pb.Status)
	}
	pb, page := confirmAs("second@example.com")
	if pb.Status != "full" || pb.Attestation != nil || !strings.Contains(page.body, "This app is full") {
		t.Fatalf("second person should be told the app is full: %s", pb.Status)
	}
	// The first person is not locked out: a new packet on a new device still confirms.
	if pb, _ := confirmAs("FIRST@example.com"); pb.Status != "confirmed" {
		t.Fatalf("an existing member was refused by a full app: %s", pb.Status)
	}
	if n, _ := e.store.Members("tiny-app"); n != 1 {
		t.Errorf("members = %d, want 1", n)
	}
	// Apps are isolated: the same address in another app is a separate person.
	s := e.start(t, "notes-demo", "second@example.com", pk(t))
	e.press(t, s.Link)
	var other pickupBody
	e.pickup(t, "notes-demo", s).json(t, &other)
	if other.Status != "confirmed" {
		t.Errorf("another app's quota affected this one: %s", other.Status)
	}
}

func TestQuotaWaitlist(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	for _, email := range []string{"one@example.com", "two@example.com"} {
		s := e.start(t, "wait-app", email, pk(t))
		e.press(t, s.Link)
		var pb pickupBody
		e.pickup(t, "wait-app", s).json(t, &pb)
		if email == "two@example.com" && (pb.Status != "waitlisted" || pb.Attestation != nil) {
			t.Fatalf("second person: %s", pb.Status)
		}
	}
	if e.store.Waiting("wait-app") != 1 {
		t.Errorf("waiting = %d, want 1", e.store.Waiting("wait-app"))
	}
}

func TestLinksExpire(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	s := e.start(t, "notes-demo", "a@example.com", pk(t))
	e.clk.advance(31 * time.Minute)
	if r := e.get(t, strings.TrimPrefix(s.Link, e.ts.URL)); r.status != http.StatusNotFound {
		t.Errorf("expired link page = %d", r.status)
	}
	if r := e.press(t, s.Link); r.status != http.StatusBadRequest {
		t.Errorf("expired confirm = %d", r.status)
	}
	if r := e.pickup(t, "notes-demo", s); r.status != http.StatusNotFound {
		t.Errorf("expired pickup = %d", r.status)
	}
}

func TestAttestationsExpireAfterTheAppTTL(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *Config) { c.Apps[0].AttestationTTL = 24 * time.Hour })
	s := e.start(t, "notes-demo", "a@example.com", pk(t))
	e.press(t, s.Link)
	var pb pickupBody
	e.pickup(t, "notes-demo", s).json(t, &pb)
	if pb.Attestation == nil || pb.Attestation.ExpiresAt != "2026-10-30T12:00:00.000Z" {
		t.Fatalf("expiry = %+v", pb.Attestation)
	}
}

func TestBrowserAccess(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	body := jsonBody(map[string]string{"kind": "email", "target": "a@example.com", "packetId": pk(t)})

	allowed := e.post(t, "/v1/apps/notes-demo/confirm/start", body, "Origin", "https://notes.example.com")
	if allowed.header.Get("Access-Control-Allow-Origin") != "https://notes.example.com" || allowed.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Errorf("allowed origin headers: %v", allowed.header)
	}
	evil := e.post(t, "/v1/apps/notes-demo/confirm/start", body, "Origin", "https://evil.example.net")
	if evil.header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("a foreign origin must not be allowed")
	}
	none := e.post(t, "/v1/apps/tiny-app/confirm/start", body, "Origin", "https://notes.example.com")
	if none.header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("an app with no origins must allow none, even another app's origin")
	}
	req, _ := http.NewRequest(http.MethodOptions, e.ts.URL+"/v1/apps/notes-demo/confirm/start", nil)
	req.Header.Set("Origin", "https://notes.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	pre := do(t, req)
	if pre.status != http.StatusNoContent || pre.header.Get("Access-Control-Allow-Origin") != "https://notes.example.com" {
		t.Errorf("preflight: %d %v", pre.status, pre.header)
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	s := e.start(t, "notes-demo", "a@example.com", pk(t))
	for name, r := range map[string]reply{
		"api error": e.post(t, "/v1/apps/nope/confirm/start", "{}"),
		"keys":      e.get(t, "/v1/keys"),
		"link page": e.get(t, strings.TrimPrefix(s.Link, e.ts.URL)),
		"health":    e.get(t, "/healthz"),
	} {
		h := r.header
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Frame-Options") != "DENY" || h.Get("Content-Security-Policy") == "" {
			t.Errorf("%s: missing security headers: %v", name, h)
		}
	}
	csp := e.get(t, strings.TrimPrefix(s.Link, e.ts.URL)).header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "form-action 'self'") || strings.Contains(csp, "script-src") {
		t.Errorf("link page CSP = %q", csp)
	}
}

func TestMailFailureLeavesNoState(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *Config) { c.Mailer = failingMailer{} })
	r := e.post(t, "/v1/apps/notes-demo/confirm/start", jsonBody(map[string]string{"kind": "email", "target": "a@example.com", "packetId": pk(t)}))
	if r.status != http.StatusBadGateway || strings.Contains(r.body, "a@example.com") || strings.Contains(r.body, "smtp") {
		t.Fatalf("mail failure: %d %s", r.status, r.body)
	}
	e.srv.mu.Lock()
	n := len(e.srv.pending)
	e.srv.mu.Unlock()
	if n != 0 || e.srv.channel.Pending() != 0 {
		t.Errorf("state left behind: %d pending, %d challenges", n, e.srv.channel.Pending())
	}
}

type failingMailer struct{}

func (failingMailer) SendMagicLink(context.Context, MagicLink) error {
	return errors.New("smtp: user sam@example.com rejected")
}

func TestBusyServerSaysSo(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *Config) { c.MaxPending = 1 })
	e.start(t, "notes-demo", "a@example.com", pk(t))
	r := e.post(t, "/v1/apps/notes-demo/confirm/start", jsonBody(map[string]string{"kind": "email", "target": "b@example.com", "packetId": pk(t)}))
	if r.status != http.StatusServiceUnavailable || r.header.Get("Retry-After") == "" {
		t.Fatalf("full server: %d %v", r.status, r.header)
	}
}

func TestDevInboxIsOffUnlessAsked(t *testing.T) {
	t.Parallel()
	if r := newEnv(t, nil).get(t, "/dev/inbox"); r.status != http.StatusNotFound {
		t.Errorf("inbox without Dev = %d, want 404", r.status)
	}
	e := newEnv(t, func(c *Config) { c.Dev = true })
	e.start(t, "notes-demo", "a@example.com", pk(t))
	r := e.get(t, "/dev/inbox")
	var inbox struct{ Messages []struct{ To, Link string } }
	if err := json.Unmarshal([]byte(strings.NewReplacer(`"to"`, `"To"`, `"link"`, `"Link"`).Replace(r.body)), &inbox); err != nil || len(inbox.Messages) != 1 || inbox.Messages[0].To != "a@example.com" {
		t.Fatalf("inbox: %d %s", r.status, r.body)
	}
}

// Secrets and addresses must never reach the log, even at debug level.
func TestNothingSensitiveIsLogged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, nil)
	s := e.start(t, "notes-demo", "private.person@example.com", pk(t))
	e.press(t, s.Link)
	e.pickup(t, "notes-demo", s)
	u, _ := url.Parse(s.Link)
	logs := e.logs.String()
	for name, secret := range map[string]string{"address": "private.person", "token": u.Query().Get("t"), "pickup secret": s.Pickup, "challenge id": s.ChallengeID} {
		if secret != "" && strings.Contains(logs, secret) {
			t.Errorf("the log contains the %s", name)
		}
	}
	if !strings.Contains(logs, "confirmation started") || !strings.Contains(logs, "confirmation completed") {
		t.Errorf("expected events are missing from the log: %s", logs)
	}
}

func TestConfigValidation(t *testing.T) {
	t.Parallel()
	seed := sha256.Sum256([]byte("k"))
	signer, _ := verify.NewSigner("k", ed25519.NewKeyFromSeed(seed[:]))
	good := func() Config {
		return Config{
			BaseURL: "https://auth.example.com", Signer: signer, Mailer: &DevMailer{},
			Apps: []App{{ID: "notes-demo", Name: "Notes", Secret: secretFor("n")}},
		}
	}
	if _, err := New(good()); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	tests := map[string]func(*Config){
		"plain http on a real host": func(c *Config) { c.BaseURL = "http://auth.example.com" },
		"base with query":           func(c *Config) { c.BaseURL = "https://auth.example.com/?x=1" },
		"no scheme":                 func(c *Config) { c.BaseURL = "auth.example.com" },
		"no signer":                 func(c *Config) { c.Signer = nil },
		"no mailer":                 func(c *Config) { c.Mailer = nil },
		"no apps":                   func(c *Config) { c.Apps = nil },
		"short secret":              func(c *Config) { c.Apps[0].Secret = []byte("short") },
		"bad app id":                func(c *Config) { c.Apps[0].ID = "Bad App" },
		"duplicate app":             func(c *Config) { c.Apps = append(c.Apps, c.Apps[0]) },
		"newline in name":           func(c *Config) { c.Apps[0].Name = "Notes\nBcc: x" },
		"unimplemented method":      func(c *Config) { c.Apps[0].Methods = []packet.Method{packet.MethodSMS} },
		"negative quota":            func(c *Config) { c.Apps[0].MaxSubjects = -1 },
		"bad onLimit":               func(c *Config) { c.Apps[0].OnLimit = "explode" },
		"origin with a path":        func(c *Config) { c.Apps[0].Origins = []string{"https://x.example.com/app"} },
		"plain http origin":         func(c *Config) { c.Apps[0].Origins = []string{"http://x.example.com"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := good()
			mutate(&c)
			if _, err := New(c); err == nil {
				t.Fatal("expected a configuration error")
			}
		})
	}
	local := good()
	local.BaseURL = "http://127.0.0.1:8080"
	local.Apps[0].Origins = []string{"http://localhost:3000"}
	if _, err := New(local); err != nil {
		t.Errorf("localhost over http should be allowed for development: %v", err)
	}
}

func TestMemoryStoreNeverExceedsItsLimitUnderLoad(t *testing.T) {
	t.Parallel()
	s := NewMemoryStore()
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.Admit("app", fmt.Sprintf("subject-%d", i), 10)
		}()
	}
	wg.Wait()
	if n, _ := s.Members("app"); n > 10 {
		t.Fatalf("members = %d, the limit is 10", n)
	}
}

func TestLimiter(t *testing.T) {
	t.Parallel()
	l := newLimiter()
	now := epoch
	for i := 0; i < 3; i++ {
		if !l.allow("k", 3, time.Minute, now) {
			t.Fatalf("event %d refused", i)
		}
	}
	if l.allow("k", 3, time.Minute, now) {
		t.Error("fourth event allowed")
	}
	if !l.allow("other", 3, time.Minute, now) {
		t.Error("keys must be independent")
	}
	if !l.allow("k", 3, time.Minute, now.Add(time.Minute)) {
		t.Error("the window should reset")
	}
	// A full table refuses new keys instead of growing, then recovers once windows expire.
	small := &limiter{windows: map[string]*window{}, max: 2}
	small.allow("a", 1, time.Minute, now)
	small.allow("b", 1, time.Minute, now)
	if small.allow("c", 1, time.Minute, now) {
		t.Error("a full limiter should refuse new keys")
	}
	if !small.allow("c", 1, time.Minute, now.Add(2*time.Minute)) {
		t.Error("expired windows should be swept to make room")
	}
}

// Behind a proxy, only the last X-Forwarded-For entry (the one our own proxy
// appended) can be trusted. A client can put anything in the earlier ones.
func TestTrustedForwardedForUsesTheLastEntry(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(c *Config) { c.TrustForwardedFor = true })
	var last reply
	for i := 1; i <= 21; i++ {
		last = e.post(t, "/v1/apps/notes-demo/confirm/start",
			jsonBody(map[string]string{"kind": "email", "target": "n" + strings.Repeat("z", i) + "@example.com", "packetId": pk(t)}),
			"X-Forwarded-For", "10.0.0."+string(rune('a'+i))+", 203.0.113.9") // spoofed first entry, real last entry
	}
	if last.status != http.StatusTooManyRequests {
		t.Fatalf("a spoofed first X-Forwarded-For entry dodged the limit: %d", last.status)
	}
	// A different real client has its own allowance.
	r := e.post(t, "/v1/apps/notes-demo/confirm/start",
		jsonBody(map[string]string{"kind": "email", "target": "someone@example.com", "packetId": pk(t)}),
		"X-Forwarded-For", "10.0.0.1, 203.0.113.77")
	if r.status != http.StatusAccepted {
		t.Fatalf("a different client was limited: %d", r.status)
	}
}
