package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
)

const domain = "gold-attestation-v1"

var b64 = base64.RawURLEncoding

// Signer issues attestations. Keep the private key on the server only.
type Signer struct {
	keyID string
	key   ed25519.PrivateKey
}

// NewSigner returns a Signer. keyID names the key in issued attestations so
// keys can be rotated.
func NewSigner(keyID string, key ed25519.PrivateKey) (*Signer, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key")
	}
	return &Signer{keyID: keyID, key: key}, nil
}

// PublicKey returns the key to publish so apps and clients can verify.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// KeyID returns the id written into attestations.
func (s *Signer) KeyID() string { return s.keyID }

// signedFields is exactly what is signed. It binds an attestation to one app
// and one packet, so it cannot be moved to another packet or another app. The
// domain string stops a signature made here being reused in another protocol.
type signedFields struct {
	Domain    string        `json:"domain"`
	AppID     string        `json:"appId"`
	PacketID  string        `json:"packetId"`
	Kind      packet.Kind   `json:"kind"`
	Method    packet.Method `json:"method"`
	Subject   string        `json:"subject"`
	IssuedAt  string        `json:"issuedAt"`
	ExpiresAt string        `json:"expiresAt,omitempty"`
	KeyID     string        `json:"keyId"`
}

func message(appID, packetID string, a packet.Attestation) ([]byte, error) {
	c, err := packet.CanonicalJSON(signedFields{
		Domain: domain, AppID: appID, PacketID: packetID,
		Kind: a.Kind, Method: a.Method, Subject: a.Subject,
		IssuedAt: a.IssuedAt, ExpiresAt: a.ExpiresAt, KeyID: a.KeyID,
	})
	return []byte(c), err
}

const stampLayout = "2006-01-02T15:04:05.000Z"

// Attest signs a statement that subject (from Subject) is confirmed for the
// given packet in the given app. A zero expires means it does not expire.
func (s *Signer) Attest(appID, packetID string, kind packet.Kind, method packet.Method, subject string, issued, expires time.Time) (packet.Attestation, error) {
	a := packet.Attestation{
		Kind: kind, Method: method, Subject: subject,
		IssuedAt: issued.UTC().Format(stampLayout), KeyID: s.keyID,
	}
	if !expires.IsZero() {
		a.ExpiresAt = expires.UTC().Format(stampLayout)
	}
	msg, err := message(appID, packetID, a)
	if err != nil {
		return a, err
	}
	a.Signature = b64.EncodeToString(ed25519.Sign(s.key, msg))
	return a, nil
}

// Status is the outcome of checking one attestation.
type Status string

// Statuses returned by Checker.Check.
const (
	Valid      Status = "valid"
	Expired    Status = "expired"
	UnknownKey Status = "unknown-key"
	BadSig     Status = "bad-signature"
)

// Result pairs an attestation with its status.
type Result struct {
	Attestation packet.Attestation
	Status      Status
}

// Checker verifies attestations against a set of trusted public keys.
type Checker struct {
	keys map[string]ed25519.PublicKey
}

// NewChecker returns a Checker that trusts the given keys by key id.
func NewChecker(keys map[string]ed25519.PublicKey) *Checker {
	c := &Checker{keys: make(map[string]ed25519.PublicKey, len(keys))}
	for id, k := range keys {
		c.keys[id] = k
	}
	return c
}

// Check verifies every attestation in p. It never trusts the packet's checksum
// or any unsigned field: the app id and packet id come from the packet itself
// and are part of what was signed, so an attestation copied from another
// packet or another app reports BadSig.
func (c *Checker) Check(p *packet.Packet, now time.Time) []Result {
	out := make([]Result, 0, len(p.Attestations))
	for _, a := range p.Attestations {
		out = append(out, Result{Attestation: a, Status: c.checkOne(p, a, now)})
	}
	return out
}

func (c *Checker) checkOne(p *packet.Packet, a packet.Attestation, now time.Time) Status {
	pub, ok := c.keys[a.KeyID]
	if !ok {
		return UnknownKey
	}
	sig, err := b64.DecodeString(a.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return BadSig
	}
	msg, err := message(p.AppID, p.PacketID, a)
	if err != nil || !ed25519.Verify(pub, msg, sig) {
		return BadSig
	}
	if a.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
		if err != nil || !now.Before(exp) {
			return Expired
		}
	}
	return Valid
}

// Has reports whether any attestation in results is Valid for kind, and, when
// methods are given, was confirmed by one of them. Use it to gate an action:
// for example, require a phone confirmed by anything but SMS-for-free-plans.
func Has(results []Result, kind packet.Kind, methods ...packet.Method) bool {
	for _, r := range results {
		if r.Status != Valid || r.Attestation.Kind != kind {
			continue
		}
		if len(methods) == 0 {
			return true
		}
		for _, m := range methods {
			if r.Attestation.Method == m {
				return true
			}
		}
	}
	return false
}
