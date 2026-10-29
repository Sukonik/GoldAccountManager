package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/verify"
)

func b64(n int, fill byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, n))
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func goodConfig() fileConfig {
	var c fileConfig
	_ = json.Unmarshal([]byte(`{"baseUrl":"https://auth.example.com","keyId":"k1",
		"apps":[{"id":"notes-demo","name":"Notes Demo","maxSubjects":100,"onLimit":"waitlist","attestationDays":30,"origins":["https://notes.example.com"]}],
		"smtp":{"addr":"smtp.example.com:587","from":"noreply@example.com","username":"mailer"}}`), &c)
	return c
}

func goodEnv() map[string]string {
	return map[string]string{envSigningSeed: b64(32, 1), secretEnvName("notes-demo"): b64(32, 2), envSMTPPass: "hunter2-smtp"} //nolint:gosec // fake values for a test
}

func TestSecretEnvName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"notes-demo": "GOLD_APP_SECRET_NOTES_DEMO", "a1": "GOLD_APP_SECRET_A1", "x-y-z": "GOLD_APP_SECRET_X_Y_Z"} {
		if got := secretEnvName(in); got != want {
			t.Errorf("secretEnvName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeygen(t *testing.T) {
	t.Parallel()
	run1 := func() string {
		var out, errOut bytes.Buffer
		if code := keygenCmd([]string{"-app", "notes-demo", "-app", "legal-app"}, &out, &errOut); code != 0 {
			t.Fatalf("keygen: %d %s", code, errOut.String())
		}
		return out.String()
	}
	a, b := run1(), run1()
	if a == b {
		t.Fatal("two runs gave the same keys")
	}
	vars, other := parseVars(a), parseVars(b)
	// Each secret must differ between runs on its own: one fixed value among random ones must not hide.
	for k, v := range vars {
		if other[k] == v {
			t.Errorf("%s is identical in two runs", k)
		}
		raw, _ := decodeKey(v)
		if len(bytes.Trim(raw, "\x00")) == 0 {
			t.Errorf("%s is all zero bytes", k)
		}
	}
	var pub string
	for _, line := range strings.Split(a, "\n") {
		if rest, ok := strings.CutPrefix(line, "# public key (ed25519, base64url): "); ok {
			pub = rest
		}
	}
	seed, err := decodeKey(vars[envSigningSeed])
	if err != nil || len(seed) != 32 {
		t.Fatalf("signing seed: %v len=%d", err, len(seed))
	}
	for _, app := range []string{"notes-demo", "legal-app"} {
		s, err := decodeKey(vars[secretEnvName(app)])
		if err != nil || len(s) != 32 {
			t.Errorf("secret for %s: %v len=%d", app, err, len(s))
		}
	}
	want := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if pub != want {
		t.Errorf("the printed public key does not belong to the printed seed")
	}
	// The output must work as a server environment.
	if _, err := buildServer(goodConfig(), envOf(map[string]string{envSigningSeed: vars[envSigningSeed], secretEnvName("notes-demo"): vars[secretEnvName("notes-demo")], envSMTPPass: "x"}), slog.New(slog.DiscardHandler)); err != nil {
		t.Errorf("keygen output rejected by buildServer: %v", err)
	}
	var out, errOut bytes.Buffer
	if code := keygenCmd([]string{"-app", "Bad App"}, &out, &errOut); code != 1 || out.Len() != 0 {
		t.Errorf("bad app id: code %d, stdout %q", code, out.String())
	}
}

func parseVars(out string) map[string]string {
	vars := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && strings.HasPrefix(k, "GOLD_") {
			vars[k] = v
		}
	}
	return vars
}

func TestBuildServerAcceptsAGoodConfig(t *testing.T) {
	t.Parallel()
	if _, err := buildServer(goodConfig(), envOf(goodEnv()), slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
}

func TestBuildServerErrorsNameTheProblemAndNeverPrintSecrets(t *testing.T) {
	t.Parallel()
	const sentinel = "SENTINEL-SECRET-VALUE"
	tests := []struct {
		name    string
		mutate  func(*fileConfig, map[string]string)
		mention string
	}{
		{"no signing seed", func(_ *fileConfig, e map[string]string) { delete(e, envSigningSeed) }, envSigningSeed},
		{"signing seed too short", func(_ *fileConfig, e map[string]string) { e[envSigningSeed] = b64(16, 1) }, envSigningSeed},
		{"signing seed not base64", func(_ *fileConfig, e map[string]string) { e[envSigningSeed] = sentinel + "!!!" }, envSigningSeed},
		{"no app secret", func(_ *fileConfig, e map[string]string) { delete(e, secretEnvName("notes-demo")) }, "GOLD_APP_SECRET_NOTES_DEMO"},
		{"app secret too short", func(_ *fileConfig, e map[string]string) { e[secretEnvName("notes-demo")] = b64(8, 3) }, "GOLD_APP_SECRET_NOTES_DEMO"},
		{"no smtp", func(c *fileConfig, _ map[string]string) { c.SMTP = nil }, "smtp"},
		{"bad smtp address", func(c *fileConfig, _ map[string]string) { c.SMTP.Addr = "smtp.example.com" }, "host:587"},
		{"username without password", func(_ *fileConfig, e map[string]string) { delete(e, envSMTPPass) }, envSMTPPass},
		{"plain http base url", func(c *fileConfig, _ map[string]string) { c.BaseURL = "http://auth.example.com" }, "https"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, e := goodConfig(), goodEnv()
			tc.mutate(&c, e)
			_, err := buildServer(c, envOf(e), slog.New(slog.DiscardHandler))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.mention) {
				t.Errorf("error %q should mention %q", err, tc.mention)
			}
			for _, secret := range []string{sentinel, e[envSigningSeed], e[secretEnvName("notes-demo")], e[envSMTPPass]} {
				if secret != "" && strings.Contains(err.Error(), secret) {
					t.Errorf("the error leaks a secret value: %q", err)
				}
			}
		})
	}
}

func TestConfigFileIsStrict(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := readFileConfig(write("ok.json", `{"baseUrl":"https://a.example.com","apps":[]}`)); err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
	if _, err := readFileConfig(write("typo.json", `{"baseUrl":"https://a.example.com","maxSubjectz":1}`)); err == nil {
		t.Error("a misspelled setting must be an error, not silently ignored")
	}
	if _, err := readFileConfig(write("secret.json", `{"baseUrl":"https://a.example.com","signingSeed":"abc"}`)); err == nil {
		t.Error("secrets are not accepted in the config file")
	}
	if _, err := readFileConfig(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("a missing file must be an error")
	}
}

func TestServerHasTimeouts(t *testing.T) {
	t.Parallel()
	s := httpServer(http.NotFoundHandler())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
		t.Errorf("a public server needs every timeout and a header cap: %+v", s)
	}
}

func TestServeCommandUsage(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	if code := serveCmd(nil, &out, &errOut); code != 2 {
		t.Errorf("no flags: code %d, want 2", code)
	}
	if code := serveCmd([]string{"-config", filepath.Join(t.TempDir(), "nope.json")}, &out, &errOut); code != 1 {
		t.Errorf("missing config: code %d, want 1", code)
	}
}

// The whole dev-mode flow over a real socket: email, click, pickup, verify.
func TestDevServerEndToEnd(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + ln.Addr().String()
	var mailLog bytes.Buffer
	srv, err := demoServer(base, &mailLog, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveOn(ctx, ln, srv.Handler()) }()

	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(method, path, ctype, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	p, _ := packet.New("demo-work", "Sam", packet.AppInfo{}, time.Now())
	status, body := call("POST", "/v1/apps/demo-work/confirm/start", "application/json",
		`{"kind":"email","target":"sam@example.com","packetId":"`+p.PacketID+`"}`)
	if status != http.StatusAccepted {
		t.Fatalf("start: %d %s", status, body)
	}
	var started struct{ ChallengeID, Pickup string }
	if err := json.Unmarshal([]byte(strings.NewReplacer(`"challengeId"`, `"ChallengeID"`, `"pickup"`, `"Pickup"`).Replace(body)), &started); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mailLog.String(), "sam@example.com") || !strings.Contains(mailLog.String(), base+"/v1/confirm/link") {
		t.Fatalf("the dev mailer should print the link: %q", mailLog.String())
	}

	_, inbox := call("GET", "/dev/inbox", "", "")
	var box struct{ Messages []struct{ Link string } }
	if err := json.Unmarshal([]byte(strings.Replace(inbox, `"link"`, `"Link"`, 1)), &box); err != nil || len(box.Messages) != 1 {
		t.Fatalf("inbox: %s", inbox)
	}
	link, _ := url.Parse(box.Messages[0].Link)
	form := url.Values{"c": {link.Query().Get("c")}, "t": {link.Query().Get("t")}}
	if status, body := call("POST", "/v1/confirm/link", "application/x-www-form-urlencoded", form.Encode()); status != http.StatusOK {
		t.Fatalf("confirm: %d %s", status, body)
	}

	status, body = call("POST", "/v1/apps/demo-work/confirm/pickup", "application/json", `{"challengeId":"`+started.ChallengeID+`","pickup":"`+started.Pickup+`"}`)
	var pb struct {
		Status      string
		Attestation *packet.Attestation
	}
	if err := json.Unmarshal([]byte(strings.NewReplacer(`"status"`, `"Status"`, `"attestation"`, `"Attestation"`).Replace(body)), &pb); err != nil || status != 200 || pb.Status != "confirmed" || pb.Attestation == nil {
		t.Fatalf("pickup: %d %s", status, body)
	}

	// Verify with the key the server publishes, the way an app would.
	_, keysBody := call("GET", "/v1/keys", "", "")
	var keys struct {
		Keys []struct{ KeyID, PublicKey string }
	}
	if err := json.Unmarshal([]byte(strings.NewReplacer(`"keyId"`, `"KeyID"`, `"publicKey"`, `"PublicKey"`).Replace(keysBody)), &keys); err != nil || len(keys.Keys) != 1 {
		t.Fatalf("keys: %s", keysBody)
	}
	pub, _ := base64.RawURLEncoding.DecodeString(keys.Keys[0].PublicKey)
	p.Attestations = []packet.Attestation{*pb.Attestation}
	res := verify.NewChecker(map[string]ed25519.PublicKey{keys.Keys[0].KeyID: pub}).Check(p, time.Now())
	if len(res) != 1 || res[0].Status != verify.Valid {
		t.Fatalf("the attestation does not verify with the published key: %+v", res)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not shut down")
	}
}
