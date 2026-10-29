package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/server"
	"github.com/sukonik/goldaccountmanager/verify"
)

// fileConfig is the JSON config file. It holds no secrets: the signing key and
// every app's secret come from the environment, so the file can be committed
// and shared safely.
type fileConfig struct {
	BaseURL string    `json:"baseUrl"`
	KeyID   string    `json:"keyId"`
	Apps    []fileApp `json:"apps"`
	SMTP    *struct {
		Addr     string `json:"addr"`
		From     string `json:"from"`
		Username string `json:"username"`
	} `json:"smtp"`
}

type fileApp struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	MaxSubjects     int      `json:"maxSubjects"`
	OnLimit         string   `json:"onLimit"`
	AttestationDays int      `json:"attestationDays"`
	Origins         []string `json:"origins"`
}

const (
	envSigningSeed = "GOLD_SIGNING_SEED"
	envSMTPPass    = "GOLD_SMTP_PASSWORD" //nolint:gosec // the name of an environment variable, not a credential
)

// secretEnvName is the environment variable holding an app's subject secret,
// for example notes-demo becomes GOLD_APP_SECRET_NOTES_DEMO.
func secretEnvName(appID string) string {
	return "GOLD_APP_SECRET_" + strings.ToUpper(strings.ReplaceAll(appID, "-", "_"))
}

func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

func readFileConfig(path string) (fileConfig, error) {
	var c fileConfig
	raw, err := os.ReadFile(path) //nolint:gosec // the operator names the config file
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // a misspelled setting should be an error, not silently ignored
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// buildServer turns a config and an environment into a Server. getenv is a
// parameter so tests do not touch the real environment. Error messages name the
// variable that is missing and never print a secret.
func buildServer(c fileConfig, getenv func(string) string, logger *slog.Logger) (*server.Server, error) {
	seedText := getenv(envSigningSeed)
	if seedText == "" {
		return nil, fmt.Errorf("%s is not set: run `goldd keygen` to make one", envSigningSeed)
	}
	seed, err := decodeKey(seedText)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s must be %d random bytes in base64", envSigningSeed, ed25519.SeedSize)
	}
	keyID := c.KeyID
	if keyID == "" {
		keyID = "k1"
	}
	signer, err := verify.NewSigner(keyID, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		return nil, err
	}

	cfg := server.Config{BaseURL: c.BaseURL, Signer: signer, Logger: logger}
	for _, a := range c.Apps {
		name := secretEnvName(a.ID)
		text := getenv(name)
		if text == "" {
			return nil, fmt.Errorf("%s is not set: it holds the secret for app %q", name, a.ID)
		}
		secret, err := decodeKey(text)
		if err != nil || len(secret) < 32 {
			return nil, fmt.Errorf("%s must be at least 32 random bytes in base64", name)
		}
		cfg.Apps = append(cfg.Apps, server.App{
			ID: a.ID, Name: a.Name, Secret: secret, MaxSubjects: a.MaxSubjects, OnLimit: server.OnLimit(a.OnLimit),
			AttestationTTL: time.Duration(a.AttestationDays) * 24 * time.Hour, Origins: a.Origins,
		})
	}
	if c.SMTP == nil {
		return nil, errors.New("smtp settings are required (addr and from), or use -dev for a demo with no real email")
	}
	host, _, err := net.SplitHostPort(c.SMTP.Addr)
	if err != nil {
		return nil, fmt.Errorf("smtp addr %q must look like host:587", c.SMTP.Addr)
	}
	m := &server.SMTPMailer{Addr: c.SMTP.Addr, From: c.SMTP.From}
	if c.SMTP.Username != "" {
		pass := getenv(envSMTPPass)
		if pass == "" {
			return nil, fmt.Errorf("%s is not set but smtp.username is", envSMTPPass)
		}
		m.Auth = smtp.PlainAuth("", c.SMTP.Username, pass, host)
	}
	cfg.Mailer = m
	return server.New(cfg)
}

// demoServer is the zero-setup dev mode: throwaway keys, two demo apps, and a
// mailer that prints links instead of sending email.
func demoServer(baseURL string, out io.Writer, logger *slog.Logger) (*server.Server, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := verify.NewSigner("demo-key", priv)
	if err != nil {
		return nil, err
	}
	secret := func() []byte { b := make([]byte, 32); _, _ = rand.Read(b); return b }
	return server.New(server.Config{
		BaseURL: baseURL, Signer: signer, Logger: logger, Dev: true,
		Mailer: &server.DevMailer{Out: out},
		Apps: []server.App{
			{ID: "demo-work", Name: "Demo Work App", Secret: secret()},
			{ID: "demo-free", Name: "Demo Free App (2 people max)", Secret: secret(), MaxSubjects: 2, OnLimit: server.LimitWaitlist},
		},
	})
}

// httpServer wraps a handler with the timeouts a public service needs.
func httpServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// serveOn serves h on ln until ctx is cancelled, then shuts down gracefully.
func serveOn(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := httpServer(h)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
		if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func serveCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "address to listen on. Use 127.0.0.1 and put a TLS proxy in front")
	cfgPath := fs.String("config", "", "path to the JSON config file")
	dev := fs.Bool("dev", false, "demo mode: throwaway keys, demo apps, links printed instead of emailed")
	baseURL := fs.String("base-url", "", "public address used in email links (overrides the config file)")
	if fs.Parse(args) != nil {
		return 2
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))

	var srv *server.Server
	var err error
	listenAddr := *addr
	switch {
	case *dev:
		base := *baseURL
		if base == "" {
			base = "http://" + listenAddr
		}
		srv, err = demoServer(base, stdout, logger)
	case *cfgPath != "":
		var c fileConfig
		if c, err = readFileConfig(*cfgPath); err == nil {
			if *baseURL != "" {
				c.BaseURL = *baseURL
			}
			srv, err = buildServer(c, os.Getenv, logger)
		}
	default:
		sayln(stderr, "error: give -config FILE, or -dev for a demo")
		return 2
	}
	if err != nil {
		sayln(stderr, "error:", err)
		return 1
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	if *dev {
		sayf(stdout, "goldd demo server on http://%s\n  apps: demo-work, demo-free (2 people max, then waitlist)\n  emails are printed here and listed at /dev/inbox\n  public keys: /v1/keys\n  try:  curl -s -X POST http://%s/v1/apps/demo-work/confirm/start -H 'content-type: application/json' -d '{\"kind\":\"email\",\"target\":\"sam@example.com\",\"packetId\":\"pk_abcdefgh12345\"}'\n", ln.Addr(), ln.Addr())
	} else {
		sayf(stdout, "goldd listening on %s\n", ln.Addr())
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serveOn(ctx, ln, srv.Handler()); err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	return 0
}

// keygenCmd prints a new signing seed and a secret for each named app.
func keygenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var apps stringList
	fs.Var(&apps, "app", "app id to make a secret for (repeat for several)")
	if fs.Parse(args) != nil {
		return 2
	}
	for _, a := range apps {
		if !packet.IsAppID(a) {
			sayln(stderr, "error: invalid app id:", a)
			return 1
		}
	}
	pub, seed, err := newSeed()
	if err != nil {
		sayln(stderr, "error:", err)
		return 1
	}
	sayln(stdout, "# Secret. Put these in the server's environment, never in the config file or version control.")
	sayf(stdout, "%s=%s\n", envSigningSeed, seed)
	for _, a := range apps {
		secret, err := randomB64(32)
		if err != nil {
			sayln(stderr, "error:", err)
			return 1
		}
		sayf(stdout, "%s=%s\n", secretEnvName(a), secret)
	}
	sayln(stdout, "# Public. Safe to publish: apps use it to check attestations.")
	sayf(stdout, "# public key (ed25519, base64url): %s\n", pub)
	return 0
}

func newSeed() (pub, seed string, err error) {
	raw := make([]byte, ed25519.SeedSize)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	key := ed25519.NewKeyFromSeed(raw)
	return base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), base64.StdEncoding.EncodeToString(raw), nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }
