package server

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
	"github.com/sukonik/goldaccountmanager/verify"
)

// OnLimit says what happens to a new address once an app is at its quota.
type OnLimit string

// Quota behaviors.
const (
	// LimitBlock refuses new addresses. Existing ones keep working.
	LimitBlock OnLimit = "block"
	// LimitWaitlist records the address on a waitlist and refuses it for now.
	LimitWaitlist OnLimit = "waitlist"
)

// App is one isolated account space. Nothing is shared between apps: the same
// address confirmed in two apps gives two unrelated subjects.
type App struct {
	ID   string // lowercase letters, digits and hyphens
	Name string // shown to users in emails and on the confirmation page

	// Secret keys the subject hash (see verify.Subject). At least 32 random
	// bytes, private to the server, different for every app.
	Secret []byte

	// Methods lists the confirmation methods this app offers. Empty means
	// email-link, the only method implemented so far.
	Methods []packet.Method

	// MaxSubjects caps how many different confirmed addresses the app may have.
	// Zero means no cap. This is the free-tier limit.
	MaxSubjects int
	OnLimit     OnLimit // default LimitBlock

	// AttestationTTL is how long an issued attestation is valid. Default one year.
	AttestationTTL time.Duration

	// Origins are the web origins allowed to call the API from a browser,
	// such as "https://notes.example.com". Empty means no browser access.
	Origins []string
}

// Config configures a Server.
type Config struct {
	// BaseURL is the public address of this service, used to build email links.
	// It must be https, except for localhost. It comes from configuration and
	// never from a request header, so a forged Host header cannot change links.
	BaseURL string
	Apps    []App
	Signer  *verify.Signer
	Mailer  Mailer
	Store   Store // default: in memory
	Logger  *slog.Logger
	Now     func() time.Time

	// TrustForwardedFor makes the server use the last X-Forwarded-For entry as
	// the client address. Turn it on only behind a proxy you run, which sets it.
	TrustForwardedFor bool

	// Dev enables GET /dev/inbox, which lists recent emails. Never in production.
	Dev bool

	LinkTTL                 time.Duration // default 30 minutes
	StartsPerIPPerHour      int           // default 20
	StartsPerSubjectPerHour int           // default 5
	MaxPending              int           // most unfinished confirmations at once, default 20000
}

func (c *Config) defaults() {
	if c.Store == nil {
		c.Store = NewMemoryStore()
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.LinkTTL == 0 {
		c.LinkTTL = 30 * time.Minute
	}
	if c.StartsPerIPPerHour == 0 {
		c.StartsPerIPPerHour = 20
	}
	if c.StartsPerSubjectPerHour == 0 {
		c.StartsPerSubjectPerHour = 5
	}
	if c.MaxPending == 0 {
		c.MaxPending = 20000
	}
}

// validate checks the configuration and returns the first problem found.
func (c *Config) validate() error {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("BaseURL must be an absolute http(s) address with no query or fragment")
	}
	if u.Scheme != "https" && !isLocalHost(u.Hostname()) {
		return fmt.Errorf("BaseURL %q must use https: confirmation links carry secrets", c.BaseURL)
	}
	if c.Signer == nil {
		return errors.New("a Signer is required")
	}
	if c.Mailer == nil {
		return errors.New("a Mailer is required")
	}
	if len(c.Apps) == 0 {
		return errors.New("at least one app is required")
	}
	seen := map[string]bool{}
	for i := range c.Apps {
		if err := c.Apps[i].validate(); err != nil {
			return fmt.Errorf("app %q: %w", c.Apps[i].ID, err)
		}
		if seen[c.Apps[i].ID] {
			return fmt.Errorf("app %q is listed twice", c.Apps[i].ID)
		}
		seen[c.Apps[i].ID] = true
	}
	return nil
}

func (a *App) validate() error {
	if !packet.IsAppID(a.ID) {
		return errors.New("id must be 2-40 characters: lowercase letters, digits and hyphens")
	}
	if strings.TrimSpace(a.Name) == "" || len(a.Name) > 80 || strings.ContainsAny(a.Name, "\r\n\x00") {
		return errors.New("name must be 1-80 characters on one line")
	}
	if len(a.Secret) < 32 {
		return errors.New("secret must be at least 32 bytes")
	}
	for _, m := range a.Methods {
		if m != packet.MethodEmailLink {
			return fmt.Errorf("method %q is not implemented yet (only %q is)", m, packet.MethodEmailLink)
		}
	}
	if a.MaxSubjects < 0 {
		return errors.New("maxSubjects cannot be negative")
	}
	switch a.OnLimit {
	case "", LimitBlock, LimitWaitlist:
	default:
		return fmt.Errorf("onLimit %q must be %q or %q", a.OnLimit, LimitBlock, LimitWaitlist)
	}
	for _, o := range a.Origins {
		if !validOrigin(o) {
			return fmt.Errorf("origin %q must look like https://app.example.com", o)
		}
	}
	return nil
}

// validOrigin accepts a bare web origin: https, or http for localhost during
// development, with no path.
func validOrigin(o string) bool {
	u, err := url.Parse(o)
	if err != nil || u.Host == "" || u.Path != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return isLocalHost(u.Hostname())
	}
	return false
}

func (a *App) allows(m packet.Method) bool {
	if len(a.Methods) == 0 {
		return m == packet.MethodEmailLink
	}
	return slices.Contains(a.Methods, m)
}

func (a *App) ttl() time.Duration {
	if a.AttestationTTL > 0 {
		return a.AttestationTTL
	}
	return 365 * 24 * time.Hour
}

func (a *App) allowsOrigin(origin string) bool { return slices.Contains(a.Origins, origin) }

func isLocalHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}
