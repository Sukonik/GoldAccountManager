package packet

import (
	"testing"
)

func TestRoundTrip(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p, err := id.NewPacket(map[string]any{"name": "Nathan"}, map[string]any{"units": "imperial"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Profile["name"] != "Nathan" {
		t.Fatalf("profile lost: %v", got.Profile)
	}
}

func TestTamperDetected(t *testing.T) {
	id, _ := NewIdentity()
	p, _ := id.NewPacket(nil, map[string]any{"units": "imperial"})
	p.Settings["units"] = "metric" // edit without re-signing
	if err := p.Verify(); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
	if err := id.Sign(p); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err != nil {
		t.Fatalf("re-signed packet should verify: %v", err)
	}
}

func TestForeignKeyCannotResign(t *testing.T) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	p, _ := a.NewPacket(nil, nil)
	// attacker swaps in their own signature but keeps victim's public key
	if err := b.Sign(p); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestSeedRestore(t *testing.T) {
	id, _ := NewIdentity()
	p, _ := id.NewPacket(nil, nil)
	restored, err := IdentityFromSeed(id.Seed())
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Sign(p); err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(); err != nil {
		t.Fatalf("restored identity should produce valid packets: %v", err)
	}
}

func TestChallenge(t *testing.T) {
	id, _ := NewIdentity()
	p, _ := id.NewPacket(nil, nil)
	nonce := []byte("random-nonce")
	sig := id.SignChallenge(nonce)
	if !VerifyChallenge(p.PublicKey, nonce, sig) {
		t.Fatal("valid challenge rejected")
	}
	if VerifyChallenge(p.PublicKey, []byte("other"), sig) {
		t.Fatal("wrong nonce accepted")
	}
}
