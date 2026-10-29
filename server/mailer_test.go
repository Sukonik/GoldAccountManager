package server

import (
	"bufio"
	"context"
	"net"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server on a loopback port. It offers no STARTTLS,
// which SMTPMailer allows only for local servers.
type fakeSMTP struct {
	ln       net.Listener
	refuseTL bool // advertise STARTTLS, then refuse it
	got      chan fakeMail
	hang     bool
	conns    atomic.Int32 // how many connections were opened
}

type fakeMail struct{ from, rcpt, data string }

func newFakeSMTP(t *testing.T, hang bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, got: make(chan fakeMail, 4), hang: hang}
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *fakeSMTP) addr() string { return f.ln.Addr().String() }

// serve accepts any number of connections, one goroutine each.
func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.conns.Add(1)
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if f.hang {
		time.Sleep(3 * time.Second) // never greet
		return
	}
	tp := textproto.NewConn(conn)
	_ = tp.PrintfLine("220 localhost ESMTP")
	var m fakeMail
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(line); {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			_ = tp.PrintfLine("250-localhost")
			if f.refuseTL {
				_ = tp.PrintfLine("250-STARTTLS")
			}
			_ = tp.PrintfLine("250 8BITMIME")
		case cmd == "STARTTLS":
			_ = tp.PrintfLine("454 TLS not available")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			m.from = line[len("MAIL FROM:"):]
			_ = tp.PrintfLine("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			m.rcpt = line[len("RCPT TO:"):]
			_ = tp.PrintfLine("250 OK")
		case cmd == "DATA":
			_ = tp.PrintfLine("354 go ahead")
			b, err := tp.ReadDotBytes()
			if err != nil {
				return
			}
			m.data = string(b)
			_ = tp.PrintfLine("250 queued")
			f.got <- m
		case cmd == "QUIT":
			_ = tp.PrintfLine("221 bye")
			return
		default:
			_ = tp.PrintfLine("250 OK")
		}
	}
}

func headersOf(raw string) map[string]string {
	h := map[string]string{}
	r := bufio.NewReader(strings.NewReader(raw))
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if err != nil || line == "" {
			return h
		}
		if k, v, ok := strings.Cut(line, ": "); ok {
			h[k] = v
		}
	}
}

func TestSMTPMailerDeliversAWellFormedMessage(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t, false)
	m := &SMTPMailer{Addr: f.addr(), From: "noreply@example.com", Timeout: 5 * time.Second}
	err := m.SendMagicLink(context.Background(), MagicLink{To: "sam@example.com", AppName: "Notes Demo", Link: "https://auth.example.com/v1/confirm/link?c=ch_x&t=tok", ExpiresIn: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	got := <-f.got
	// net/smtp appends BODY=8BITMIME when the server offers it.
	if !strings.HasPrefix(got.from, "<noreply@example.com>") || got.rcpt != "<sam@example.com>" {
		t.Errorf("envelope: from=%q rcpt=%q", got.from, got.rcpt)
	}
	h := headersOf(got.data)
	if h["To"] != "sam@example.com" || h["From"] != "noreply@example.com" || h["MIME-Version"] != "1.0" || !strings.Contains(h["Subject"], "Confirm") {
		t.Errorf("headers: %v", h)
	}
	for _, want := range []string{"https://auth.example.com/v1/confirm/link?c=ch_x&t=tok", "expires in 30 minutes", "ignore this message"} {
		if !strings.Contains(got.data, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

// Anything that could end a header line, or add a recipient, must be refused
// before a connection is even opened.
func TestSMTPMailerRefusesHeaderInjection(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t, false)
	m := &SMTPMailer{Addr: f.addr(), From: "noreply@example.com", Timeout: 2 * time.Second}
	for _, to := range []string{
		"a@example.com\r\nBcc: victim@example.com",
		"a@example.com\nBcc: victim@example.com",
		"a@example.com,victim@example.com",
		"a@example.com;victim@example.com",
		"<a@example.com>",
		`"a"@example.com`,
		"",
		"a@example.com\x00",
	} {
		err := m.SendMagicLink(context.Background(), MagicLink{To: to, AppName: "X", Link: "https://x", ExpiresIn: time.Minute})
		if err == nil {
			t.Errorf("recipient %q was accepted", to)
		}
	}
	bad := &SMTPMailer{Addr: f.addr(), From: "noreply@example.com\r\nBcc: victim@example.com"}
	if err := bad.SendMagicLink(context.Background(), MagicLink{To: "a@example.com", AppName: "X", Link: "https://x", ExpiresIn: time.Minute}); err == nil {
		t.Error("a From address with a line break was accepted")
	}
	// The point is that nothing was even attempted: the address is rejected
	// before a connection is opened, not by the server or by a timeout.
	time.Sleep(100 * time.Millisecond)
	if n := f.conns.Load(); n != 0 {
		t.Errorf("%d connections were opened for addresses that should be refused up front", n)
	}
	select {
	case m := <-f.got:
		t.Errorf("a message was delivered: %+v", m)
	default:
	}
}

func TestMessageNeverGainsHeadersFromTheAppName(t *testing.T) {
	t.Parallel()
	raw := string(buildMessage("noreply@example.com", MagicLink{To: "a@example.com", AppName: "Evil\r\nBcc: victim@example.com\r\n\r\nInjected body", Link: "https://x", ExpiresIn: time.Minute}))
	h := headersOf(raw)
	if _, bcc := h["Bcc"]; bcc {
		t.Fatalf("the app name added a header: %v", h)
	}
	if !strings.Contains(h["Subject"], "Evil") {
		t.Errorf("subject lost the name: %q", h["Subject"])
	}
	// The header block must hold exactly the headers we write, and nothing the name could add.
	want := map[string]bool{"From": true, "To": true, "Subject": true, "MIME-Version": true, "Content-Type": true, "Content-Transfer-Encoding": true}
	if len(h) != len(want) {
		t.Errorf("header block has %d headers, want %d: %v", len(h), len(want), h)
	}
	for k := range h {
		if !want[k] {
			t.Errorf("unexpected header %q", k)
		}
	}
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") || strings.HasPrefix(line, "Injected") {
			t.Errorf("the app name forged a line: %q", line)
		}
	}
	if strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\n") || strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\r") {
		t.Error("bare line breaks in the message")
	}
}

func TestSMTPMailerGivesUpOnASilentServer(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t, true)
	m := &SMTPMailer{Addr: f.addr(), From: "noreply@example.com", Timeout: 300 * time.Millisecond}
	start := time.Now()
	err := m.SendMagicLink(context.Background(), MagicLink{To: "a@example.com", AppName: "X", Link: "https://x", ExpiresIn: time.Minute})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v to give up", time.Since(start))
	}
}

func TestDevMailerKeepsOnlyRecentMessages(t *testing.T) {
	t.Parallel()
	d := &DevMailer{Keep: 3}
	for i := 0; i < 5; i++ {
		_ = d.SendMagicLink(context.Background(), MagicLink{To: strings.Repeat("a", i+1) + "@example.com"})
	}
	sent := d.Sent()
	if len(sent) != 3 || sent[0].To != "aaa@example.com" {
		t.Fatalf("kept %d: %+v", len(sent), sent)
	}
}

func TestCleartextIsOnlyForLocalServers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		host     string
		upgraded bool
		ok       bool
	}{
		{"mail.example.com", false, false},
		{"203.0.113.5", false, false},
		{"mail.example.com", true, true}, // upgraded to TLS: fine anywhere
		{"localhost", false, true},
		{"127.0.0.1", false, true},
		{"::1", false, true},
	}
	for _, tc := range tests {
		err := checkTransport(tc.host, tc.upgraded)
		if (err == nil) != tc.ok {
			t.Errorf("checkTransport(%q, upgraded=%v) = %v, want ok=%v", tc.host, tc.upgraded, err, tc.ok)
		}
	}
}

// A server that advertises STARTTLS and then refuses it must not be talked to in
// the clear: the mailer fails instead of quietly downgrading.
func TestSMTPMailerDoesNotDowngradeWhenTLSFails(t *testing.T) {
	t.Parallel()
	f := newFakeSMTP(t, false)
	f.refuseTL = true
	m := &SMTPMailer{Addr: f.addr(), From: "noreply@example.com", Timeout: 3 * time.Second}
	err := m.SendMagicLink(context.Background(), MagicLink{To: "a@example.com", AppName: "X", Link: "https://x/secret-link", ExpiresIn: time.Minute})
	if err == nil || !strings.Contains(err.Error(), "starttls") {
		t.Fatalf("want a starttls error, got %v", err)
	}
	select {
	case m := <-f.got:
		t.Fatalf("the message was sent in the clear after TLS failed: %q", m.data)
	case <-time.After(150 * time.Millisecond):
	}
}
