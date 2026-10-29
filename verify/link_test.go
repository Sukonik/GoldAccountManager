package verify

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type sent struct{ target, id, token string }

func newLink(t *testing.T, now *time.Time) (*MagicLinkChannel, *[]sent) {
	t.Helper()
	var log []sent
	ch := &MagicLinkChannel{
		Deliver: func(_ context.Context, target, id, token string) error {
			log = append(log, sent{target, id, token})
			return nil
		},
		Now: func() time.Time { return *now },
	}
	return ch, &log
}

func TestMagicLinkRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ch, log := newLink(t, &now)
	ctx := context.Background()

	id, err := ch.Start(ctx, "  Sam@Example.com ")
	if err != nil {
		t.Fatal(err)
	}
	if len(*log) != 1 || (*log)[0].target != "sam@example.com" || (*log)[0].id != id {
		t.Fatalf("delivery wrong: %+v", *log)
	}
	token := (*log)[0].token
	if len(token) != 43 || strings.ContainsAny(token, "+/=") {
		t.Fatalf("token should be 32 random bytes in base64url, got %q", token)
	}
	if _, err := ch.Complete(ctx, id, "wrong"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong token: %v", err)
	}
	got, err := ch.Complete(ctx, id, token)
	if err != nil || got != "sam@example.com" {
		t.Fatalf("complete: %q %v", got, err)
	}
	if _, err := ch.Complete(ctx, id, token); !errors.Is(err, ErrInvalid) {
		t.Fatal("a link must work only once")
	}
}

func TestMagicLinkExpiryAndAttempts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ch, log := newLink(t, &now)
	ctx := context.Background()

	id, _ := ch.Start(ctx, "a@example.com")
	now = now.Add(31 * time.Minute)
	if _, err := ch.Complete(ctx, id, (*log)[0].token); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expired token accepted: %v", err)
	}

	id, _ = ch.Start(ctx, "a@example.com")
	good := (*log)[1].token
	for i := 0; i < 4; i++ {
		if _, err := ch.Complete(ctx, id, "bad"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("try %d: %v", i, err)
		}
	}
	if _, err := ch.Complete(ctx, id, "bad"); !errors.Is(err, ErrTooManyTry) {
		t.Fatalf("want too many tries, got %v", err)
	}
	if _, err := ch.Complete(ctx, id, good); !errors.Is(err, ErrInvalid) {
		t.Fatal("the challenge should be gone after too many wrong tries")
	}
}

func TestMagicLinkIsBoundedAndCleansUp(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ch, _ := newLink(t, &now)
	ch.Max = 3
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := ch.Start(ctx, "a@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ch.Start(ctx, "a@example.com"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("table should be full: %v", err)
	}
	now = now.Add(time.Hour) // everything expires
	if _, err := ch.Start(ctx, "a@example.com"); err != nil {
		t.Fatalf("expired entries should free space: %v", err)
	}
	if ch.Pending() != 1 {
		t.Errorf("pending = %d, want 1", ch.Pending())
	}
}

func TestMagicLinkDeliveryFailureLeavesNothing(t *testing.T) {
	t.Parallel()
	ch := &MagicLinkChannel{Deliver: func(context.Context, string, string, string) error { return errors.New("smtp down") }}
	if _, err := ch.Start(context.Background(), "a@example.com"); err == nil {
		t.Fatal("expected the delivery error")
	}
	if ch.Pending() != 0 {
		t.Fatal("a failed delivery must not leave a usable challenge behind")
	}
	if _, err := (&MagicLinkChannel{}).Start(context.Background(), "a@example.com"); err == nil {
		t.Fatal("a channel without Deliver must refuse to start")
	}
	if _, err := ch.Start(context.Background(), "not an email"); err == nil {
		t.Fatal("invalid target accepted")
	}
}

func TestMagicLinkTokensAreUnique(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	ch, log := newLink(t, &now)
	for i := 0; i < 200; i++ {
		if _, err := ch.Start(context.Background(), "a@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, s := range *log {
		if seen[s.token] {
			t.Fatal("duplicate token")
		}
		seen[s.token] = true
	}
}
