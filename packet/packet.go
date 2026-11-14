// Package packet implements Packets: a portable, user-held account file.
//
// A packet is a small JSON document that carries a user's public identity,
// profile and settings, signed with a key that never leaves the user's device.
// An app that receives a packet can verify it without calling any server.
package packet

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version is the current packet format version.
const Version = 1

var (
	ErrBadSignature   = errors.New("packet: signature does not verify")
	ErrMissingKey     = errors.New("packet: missing or malformed public key")
	ErrUnsupportedVer = errors.New("packet: unsupported version")
)

// Packet is the shareable, signed account file.
type Packet struct {
	Version   int            `json:"v"`
	ID        string         `json:"id"`         // base64url of the public key
	PublicKey string         `json:"public_key"` // base64url ed25519 public key
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	Profile   map[string]any `json:"profile,omitempty"`
	Settings  map[string]any `json:"settings,omitempty"`
	Signature string         `json:"signature,omitempty"` // base64url over the signing payload
}

// Identity holds the private key. It stays on the user's device and is stored
// separately from the packet so the packet can be shared or backed up freely.
type Identity struct {
	priv ed25519.PrivateKey
}

// NewIdentity generates a fresh key pair.
func NewIdentity() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{priv: priv}, nil
}

// IdentityFromSeed restores an identity from a 32 byte seed (for backup/restore).
func IdentityFromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("packet: seed must be %d bytes", ed25519.SeedSize)
	}
	return &Identity{priv: ed25519.NewKeyFromSeed(seed)}, nil
}

// Seed returns the 32 byte seed. Treat it like a password.
func (i *Identity) Seed() []byte { return i.priv.Seed() }

// PublicKey returns the public half of the identity.
func (i *Identity) PublicKey() ed25519.PublicKey {
	return i.priv.Public().(ed25519.PublicKey)
}

// NewPacket creates and signs a packet for this identity.
func (i *Identity) NewPacket(profile, settings map[string]any) (*Packet, error) {
	now := time.Now().UTC().Truncate(time.Second)
	pk := enc(i.PublicKey())
	p := &Packet{
		Version:   Version,
		ID:        pk,
		PublicKey: pk,
		CreatedAt: now,
		UpdatedAt: now,
		Profile:   profile,
		Settings:  settings,
	}
	return p, i.Sign(p)
}

// Sign (re)signs a packet, updating UpdatedAt. Call it after any edit.
func (i *Identity) Sign(p *Packet) error {
	p.UpdatedAt = time.Now().UTC().Truncate(time.Second)
	payload, err := p.signingPayload()
	if err != nil {
		return err
	}
	p.Signature = enc(ed25519.Sign(i.priv, payload))
	return nil
}

// Verify checks the packet's signature against the public key it carries.
// A valid packet proves the holder controls the key, not that any profile
// claim is true.
func (p *Packet) Verify() error {
	if p.Version != Version {
		return ErrUnsupportedVer
	}
	pub, err := dec(p.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || p.ID != p.PublicKey {
		return ErrMissingKey
	}
	sig, err := dec(p.Signature)
	if err != nil {
		return ErrBadSignature
	}
	payload, err := p.signingPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return ErrBadSignature
	}
	return nil
}

// Encode serializes the packet to JSON.
func (p *Packet) Encode() ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

// Decode parses and verifies a packet in one step.
func Decode(data []byte) (*Packet, error) {
	var p Packet
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if err := p.Verify(); err != nil {
		return nil, err
	}
	return &p, nil
}

// signingPayload is the packet minus its signature. Go's encoding/json sorts
// map keys, so the output is deterministic within Go. Other languages should
// use RFC 8785 (JCS) canonicalization to produce the same bytes.
func (p *Packet) signingPayload() ([]byte, error) {
	c := *p
	c.Signature = ""
	return json.Marshal(&c)
}

// SignChallenge proves control of the key by signing a server or app nonce.
func (i *Identity) SignChallenge(nonce []byte) []byte {
	return ed25519.Sign(i.priv, challengeMsg(nonce))
}

// VerifyChallenge checks a challenge signature against a packet's public key.
func VerifyChallenge(publicKey string, nonce, sig []byte) bool {
	pub, err := dec(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), challengeMsg(nonce), sig)
}

// challengeMsg domain-separates challenge signatures from packet signatures.
func challengeMsg(nonce []byte) []byte {
	return append([]byte("goldaccountmanager/challenge/v1:"), nonce...)
}

func enc(b []byte) string          { return base64.RawURLEncoding.EncodeToString(b) }
func dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
