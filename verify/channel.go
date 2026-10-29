package verify

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
)

// Channel proves that someone controls a target (an email address or phone
// number). Implementations include a magic link, a reply email, a Telegram
// contact share and a paid SMS. Start sends or presents a challenge. Complete
// checks the user's proof and returns the confirmed, normalized target.
//
// A Channel confirms control only. Binding that to a packet is done by
// Signer.Attest using Subject, so no Channel ever stores a long-lived secret
// or the target itself beyond the life of the challenge.
type Channel interface {
	// Method says which confirmation method this channel represents.
	Method() packet.Method
	// Kind says what it confirms: an email or a phone.
	Kind() packet.Kind
	// Start begins confirming target and returns a challenge id.
	Start(ctx context.Context, target string) (challengeID string, err error)
	// Complete checks proof against the challenge. Challenges are single use.
	Complete(ctx context.Context, challengeID, proof string) (target string, err error)
}

// Errors returned by Complete. They are deliberately few and generic so
// responses do not reveal whether a target exists.
var (
	ErrInvalid     = errors.New("verify: code is invalid or expired")
	ErrTooManyTry  = errors.New("verify: too many attempts")
	ErrRateLimited = errors.New("verify: too many requests, try later")
)

// CodeChannel is a development and demo Channel. It creates a six-digit code
// and hands it to Deliver instead of sending anything, so demos cost nothing.
// Codes expire, allow a few attempts, and work once.
type CodeChannel struct {
	M       packet.Method
	K       packet.Kind
	Deliver func(target, code string) // e.g. print to the terminal
	TTL     time.Duration
	MaxTry  int
	Now     func() time.Time

	mu         sync.Mutex
	challenges map[string]*challenge
}

type challenge struct {
	target  string
	code    string
	expires time.Time
	tries   int
}

// Method implements Channel.
func (c *CodeChannel) Method() packet.Method { return c.M }

// Kind implements Channel.
func (c *CodeChannel) Kind() packet.Kind { return c.K }

func (c *CodeChannel) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Start implements Channel.
func (c *CodeChannel) Start(_ context.Context, target string) (string, error) {
	norm, err := Normalize(c.K, target)
	if err != nil {
		return "", err
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	id := packet.NewID("ch")

	ttl := c.TTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	c.mu.Lock()
	if c.challenges == nil {
		c.challenges = map[string]*challenge{}
	}
	c.challenges[id] = &challenge{target: norm, code: code, expires: c.now().Add(ttl)}
	c.mu.Unlock()

	if c.Deliver != nil {
		c.Deliver(norm, code)
	}
	return id, nil
}

// Complete implements Channel.
func (c *CodeChannel) Complete(_ context.Context, id, proof string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.challenges[id]
	if !ok || !c.now().Before(ch.expires) {
		delete(c.challenges, id)
		return "", ErrInvalid
	}
	maxTry := c.MaxTry
	if maxTry == 0 {
		maxTry = 5
	}
	ch.tries++
	if subtle.ConstantTimeCompare([]byte(ch.code), []byte(proof)) != 1 {
		if ch.tries >= maxTry {
			delete(c.challenges, id)
			return "", ErrTooManyTry
		}
		return "", ErrInvalid
	}
	delete(c.challenges, id) // single use
	return ch.target, nil
}
