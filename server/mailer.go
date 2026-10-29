package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"time"
)

// MagicLink is one email to send.
type MagicLink struct {
	To        string // already normalized by verify.Normalize
	AppName   string
	Link      string
	ExpiresIn time.Duration
}

// Mailer sends confirmation emails.
type Mailer interface {
	SendMagicLink(ctx context.Context, m MagicLink) error
}

// DevMailer is a Mailer for demos and tests. It sends nothing. It keeps recent
// messages in memory, and can print them to a writer. Never use it in
// production: the messages contain live confirmation links.
type DevMailer struct {
	Out io.Writer // optional: print each message here

	mu   sync.Mutex
	sent []MagicLink
	Keep int // how many to keep, default 50
}

// SendMagicLink implements Mailer.
func (d *DevMailer) SendMagicLink(_ context.Context, m MagicLink) error {
	d.mu.Lock()
	keep := d.Keep
	if keep == 0 {
		keep = 50
	}
	d.sent = append(d.sent, m)
	if len(d.sent) > keep {
		d.sent = d.sent[len(d.sent)-keep:]
	}
	out := d.Out
	d.mu.Unlock()
	if out != nil {
		_, _ = fmt.Fprintf(out, "[dev mail] to=%s app=%q link=%s\n", m.To, m.AppName, m.Link)
	}
	return nil
}

// Sent returns the kept messages, oldest first.
func (d *DevMailer) Sent() []MagicLink {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]MagicLink(nil), d.sent...)
}

// SMTPMailer sends through an SMTP server. It requires TLS (STARTTLS) unless
// the server is on localhost, so credentials and links never cross the network
// in the clear.
type SMTPMailer struct {
	Addr    string    // host:port
	From    string    // envelope and header sender, like noreply@example.com
	Auth    smtp.Auth // optional
	Timeout time.Duration
	// TLSConfig is optional, for tests and private certificate authorities.
	TLSConfig *tls.Config
}

// SendMagicLink implements Mailer.
func (m *SMTPMailer) SendMagicLink(ctx context.Context, msg MagicLink) error {
	if err := checkHeaderValue(m.From); err != nil {
		return fmt.Errorf("smtp: from address: %w", err)
	}
	if err := checkHeaderValue(msg.To); err != nil {
		return fmt.Errorf("smtp: to address: %w", err)
	}
	body := buildMessage(m.From, msg)

	timeout := m.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return fmt.Errorf("smtp: bad address: %w", err)
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", m.Addr)
	if err != nil {
		return fmt.Errorf("smtp: connect: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: greeting: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		cfg := m.TLSConfig
		if cfg == nil {
			cfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
		}
		if err := c.StartTLS(cfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	} else if err := checkTransport(host, false); err != nil {
		return err
	}
	if m.Auth != nil {
		if err := c.Auth(m.Auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp: rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: finish: %w", err)
	}
	return c.Quit()
}

// checkTransport decides whether a connection may carry mail when it has not
// been upgraded to TLS: only if the server is on this machine.
func checkTransport(host string, upgraded bool) error {
	if upgraded || isLocalHost(host) {
		return nil
	}
	return errors.New("smtp: server offers no STARTTLS and is not local: refusing to send in the clear")
}

// checkHeaderValue rejects anything that could break out of a header line.
func checkHeaderValue(s string) error {
	if s == "" || strings.ContainsAny(s, "\r\n\x00<>,;\"") {
		return errors.New("contains characters not allowed in an address")
	}
	return nil
}

// buildMessage writes a plain-text message with CRLF line endings. The app name
// is configuration, but is still stripped of line breaks before it goes into a
// header.
func buildMessage(from string, m MagicLink) []byte {
	name := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, m.AppName)
	var b strings.Builder
	line := func(s string) { b.WriteString(s); b.WriteString("\r\n") }
	line("From: " + from)
	line("To: " + m.To)
	line("Subject: " + mime.QEncoding.Encode("utf-8", "Confirm your email for "+name))
	line("MIME-Version: 1.0")
	line(`Content-Type: text/plain; charset="utf-8"`)
	line("Content-Transfer-Encoding: 8bit")
	line("")
	line("Confirm your email address for " + name + ".")
	line("")
	line("Open this link, then press the Confirm button:")
	line(m.Link)
	line("")
	line(fmt.Sprintf("The link works once and expires in %d minutes.", int(m.ExpiresIn.Minutes())))
	line("If you did not ask for this, ignore this message. Nothing happens unless you press Confirm.")
	return []byte(b.String())
}
