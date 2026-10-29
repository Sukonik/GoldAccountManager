package verify

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/sukonik/goldaccountmanager/packet"
)

// MagicLinkChannel confirms an email address by emailing a link that carries a
// long random token. It implements Channel: Start sends the link, and Complete
// takes the token from the link as its proof.
//
// Only a SHA-256 hash of the token is kept, so a leaked challenge table cannot
// be used to confirm anything. Tokens expire, work once, and allow a few wrong
// tries. The table is bounded: Start fails with ErrRateLimited rather than grow
// without limit.
//
// Email scanners and link previewers fetch every link in a message. A server
// using this channel must therefore not confirm on a GET request: show a page
// with a button, and call Complete from the button's POST.
type MagicLinkChannel struct {
	// Deliver emails the link to target. It receives the challenge id and the
	// token, which together make up the link. It must not log the token.
	Deliver func(ctx context.Context, target, challengeID, token string) error
	TTL     time.Duration    // default 30 minutes
	MaxTry  int              // default 5 wrong tokens per challenge
	Max     int              // most pending challenges, default 10000
	Now     func() time.Time // default time.Now

	mu         sync.Mutex
	challenges map[string]*linkChallenge
}

type linkChallenge struct {
	target    string
	tokenHash [sha256.Size]byte
	expires   time.Time
	tries     int
}

// Method implements Channel.
func (c *MagicLinkChannel) Method() packet.Method { return packet.MethodEmailLink }

// Kind implements Channel.
func (c *MagicLinkChannel) Kind() packet.Kind { return packet.KindEmail }

func (c *MagicLinkChannel) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Start implements Channel. It returns the challenge id.
func (c *MagicLinkChannel) Start(ctx context.Context, target string) (string, error) {
	if c.Deliver == nil {
		return "", errors.New("verify: MagicLinkChannel has no Deliver function")
	}
	norm, err := Normalize(packet.KindEmail, target)
	if err != nil {
		return "", err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	id := packet.NewID("ch")

	ttl := c.TTL
	if ttl == 0 {
		ttl = 30 * time.Minute
	}
	limit := c.Max
	if limit == 0 {
		limit = 10000
	}
	now := c.now()

	c.mu.Lock()
	if c.challenges == nil {
		c.challenges = map[string]*linkChallenge{}
	}
	for k, v := range c.challenges { // drop expired ones so the table cannot fill with stale entries
		if !now.Before(v.expires) {
			delete(c.challenges, k)
		}
	}
	if len(c.challenges) >= limit {
		c.mu.Unlock()
		return "", ErrRateLimited
	}
	c.challenges[id] = &linkChallenge{target: norm, tokenHash: sha256.Sum256([]byte(token)), expires: now.Add(ttl)}
	c.mu.Unlock()

	if err := c.Deliver(ctx, norm, id, token); err != nil {
		c.mu.Lock()
		delete(c.challenges, id)
		c.mu.Unlock()
		return "", err
	}
	return id, nil
}

// Complete implements Channel. proof is the token from the link.
func (c *MagicLinkChannel) Complete(_ context.Context, id, proof string) (string, error) {
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
	got := sha256.Sum256([]byte(proof))
	if subtle.ConstantTimeCompare(got[:], ch.tokenHash[:]) != 1 {
		if ch.tries >= maxTry {
			delete(c.challenges, id)
			return "", ErrTooManyTry
		}
		return "", ErrInvalid
	}
	delete(c.challenges, id) // single use
	return ch.target, nil
}

// Pending returns how many challenges are waiting. For tests and metrics.
func (c *MagicLinkChannel) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.challenges)
}
