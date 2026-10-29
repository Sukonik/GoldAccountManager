package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
)

var (
	t0     = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	secret = []byte(strings.Repeat("s", 32))
)

func TestNormalize(t *testing.T) {
	t.Parallel()
	ok := []struct {
		kind packet.Kind
		in   string
		want string
	}{
		{packet.KindEmail, "  Sam@Example.COM ", "sam@example.com"},
		{packet.KindPhone, "+1 (555) 555-0123", "+15555550123"},
		{packet.KindPhone, "+44.20.7946.0958", "+442079460958"},
	}
	for _, c := range ok {
		got, err := Normalize(c.kind, c.in)
		if err != nil || got != c.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	bad := []struct {
		kind packet.Kind
		in   string
	}{
		{packet.KindEmail, "not-an-email"},
		{packet.KindEmail, "Sam <sam@example.com>"},
		{packet.KindEmail, "a@b@example.com"},
		{packet.KindEmail, "sam@localhost"},
		{packet.KindEmail, "sam@[127.0.0.1]"},
		{packet.KindEmail, "sam@127.0.0.1"},
		{packet.KindEmail, `"sam smith"@example.com`},
		{packet.KindEmail, "sam..smith@example.com"},
		{packet.KindEmail, ".sam@example.com"},
		{packet.KindEmail, "sam@-example.com"},
		{packet.KindEmail, "sam@exämple.com"},
		{packet.KindEmail, "sam@example.com\r\nBcc: x@y.co"},
		{packet.KindEmail, strings.Repeat("a", 65) + "@example.com"},
		{packet.KindPhone, "555-0123"},
		{packet.KindPhone, "+0123456"},
		{packet.KindDevice, "x"},
	}
	for _, c := range bad {
		if got, err := Normalize(c.kind, c.in); err == nil {
			t.Errorf("Normalize(%q) = %q, want error", c.in, got)
		}
	}
}

func TestSubjectIsolation(t *testing.T) {
	t.Parallel()
	a, _ := Subject(secret, "legal-app", packet.KindPhone, "+15555550123")
	b, _ := Subject(secret, "dating-app", packet.KindPhone, "+15555550123")
	c, _ := Subject(secret, "legal-app", packet.KindPhone, "+15555550123")
	if a == b {
		t.Fatal("the same phone in two apps must not share a subject")
	}
	if a != c {
		t.Fatal("subject must be stable for one app and target")
	}
	if strings.Contains(a, "5555550123") || len(a) != 64 {
		t.Fatalf("subject leaks or has wrong shape: %s", a)
	}
	if _, err := Subject([]byte("short"), "x", packet.KindEmail, "a@b.co"); err == nil {
		t.Fatal("short secret accepted")
	}
}

func signer(t *testing.T) *Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := NewSigner("k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newPacket(t *testing.T, app string) *packet.Packet {
	t.Helper()
	p, err := packet.New(app, "T", packet.AppInfo{}, t0)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAttestRoundTrip(t *testing.T) {
	t.Parallel()
	s := signer(t)
	p := newPacket(t, "legal-app")
	sub, _ := Subject(secret, p.AppID, packet.KindEmail, "sam@example.com")
	a, err := s.Attest(p.AppID, p.PacketID, packet.KindEmail, packet.MethodEmailReply, sub, t0, t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	p.Attestations = []packet.Attestation{a}

	// It must survive being written to a file and read back.
	data, _ := p.Marshal()
	back, _, err := packet.Parse(data, packet.ParseOptions{ExpectAppID: "legal-app"})
	if err != nil {
		t.Fatal(err)
	}
	chk := NewChecker(map[string]ed25519.PublicKey{"k1": s.PublicKey()})
	res := chk.Check(back, t0.Add(time.Hour))
	if len(res) != 1 || res[0].Status != Valid {
		t.Fatalf("want valid, got %+v", res)
	}
	if !Has(res, packet.KindEmail) || !Has(res, packet.KindEmail, packet.MethodEmailReply) {
		t.Fatal("Has should find the email attestation")
	}
	if Has(res, packet.KindPhone) || Has(res, packet.KindEmail, packet.MethodSMS) {
		t.Fatal("Has matched the wrong kind or method")
	}
}

func TestAttestationCannotMove(t *testing.T) {
	t.Parallel()
	s := signer(t)
	chk := NewChecker(map[string]ed25519.PublicKey{"k1": s.PublicKey()})
	p := newPacket(t, "legal-app")
	sub, _ := Subject(secret, p.AppID, packet.KindEmail, "sam@example.com")
	a, _ := s.Attest(p.AppID, p.PacketID, packet.KindEmail, packet.MethodGoogle, sub, t0, time.Time{})

	other := newPacket(t, "legal-app") // same app, different packet
	other.Attestations = []packet.Attestation{a}
	if r := chk.Check(other, t0); r[0].Status != BadSig {
		t.Errorf("moved to another packet: %s", r[0].Status)
	}
	otherApp := newPacket(t, "dating-app")
	otherApp.Attestations = []packet.Attestation{a}
	if r := chk.Check(otherApp, t0); r[0].Status != BadSig {
		t.Errorf("moved to another app: %s", r[0].Status)
	}
}

func TestAttestationTamperAndExpiry(t *testing.T) {
	t.Parallel()
	s := signer(t)
	chk := NewChecker(map[string]ed25519.PublicKey{"k1": s.PublicKey()})
	p := newPacket(t, "legal-app")
	sub, _ := Subject(secret, p.AppID, packet.KindPhone, "+15555550123")
	a, _ := s.Attest(p.AppID, p.PacketID, packet.KindPhone, packet.MethodSMS, sub, t0, t0.Add(time.Hour))

	tampered := a
	tampered.Method = packet.MethodPasskey // upgrade the claimed method
	p.Attestations = []packet.Attestation{tampered}
	if r := chk.Check(p, t0); r[0].Status != BadSig {
		t.Errorf("tampered method: %s", r[0].Status)
	}

	p.Attestations = []packet.Attestation{a}
	if r := chk.Check(p, t0.Add(2*time.Hour)); r[0].Status != Expired {
		t.Errorf("want expired, got %s", r[0].Status)
	}
	unknown := NewChecker(nil)
	if r := unknown.Check(p, t0); r[0].Status != UnknownKey {
		t.Errorf("want unknown-key, got %s", r[0].Status)
	}
}

func TestCodeChannel(t *testing.T) {
	t.Parallel()
	now := t0
	var sent, target string
	ch := &CodeChannel{
		M: packet.MethodEmailLink, K: packet.KindEmail, MaxTry: 3,
		Deliver: func(to, code string) { target, sent = to, code },
		Now:     func() time.Time { return now },
	}
	ctx := context.Background()

	if _, err := ch.Start(ctx, "nope"); err == nil {
		t.Fatal("invalid target accepted")
	}
	id, err := ch.Start(ctx, "Sam@Example.com")
	if err != nil || target != "sam@example.com" || len(sent) != 6 {
		t.Fatalf("start: %v target=%q code=%q", err, target, sent)
	}
	if _, err := ch.Complete(ctx, id, "000000x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong code: %v", err)
	}
	got, err := ch.Complete(ctx, id, sent)
	if err != nil || got != "sam@example.com" {
		t.Fatalf("complete: %q %v", got, err)
	}
	if _, err := ch.Complete(ctx, id, sent); !errors.Is(err, ErrInvalid) {
		t.Fatal("a code must work only once")
	}

	id, _ = ch.Start(ctx, "sam@example.com")
	now = now.Add(11 * time.Minute)
	if _, err := ch.Complete(ctx, id, sent); !errors.Is(err, ErrInvalid) {
		t.Fatal("expired code accepted")
	}

	id, _ = ch.Start(ctx, "sam@example.com")
	for i := 0; i < 2; i++ {
		if _, err := ch.Complete(ctx, id, "999999"); !errors.Is(err, ErrInvalid) && sent != "999999" {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := ch.Complete(ctx, id, "999999"); sent != "999999" && !errors.Is(err, ErrTooManyTry) {
		t.Fatalf("want too many attempts, got %v", err)
	}
	if _, err := ch.Complete(ctx, id, sent); !errors.Is(err, ErrInvalid) {
		t.Fatal("challenge should be gone after too many attempts")
	}
}
