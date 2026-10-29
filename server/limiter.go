package server

import (
	"sync"
	"time"
)

// limiter is a fixed-window rate limiter keyed by string. It is small on
// purpose: a fixed window lets a burst of up to twice the limit straddle a
// boundary, which is acceptable here because the limits are low and several
// independent limits apply to every request.
type limiter struct {
	mu      sync.Mutex
	windows map[string]*window
	max     int // most keys kept before expired ones are swept
}

type window struct {
	start time.Time
	count int
}

func newLimiter() *limiter { return &limiter{windows: map[string]*window{}, max: 50000} }

// allow counts one event for key and reports whether it is within limit events
// per period.
func (l *limiter) allow(key string, limit int, period time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.windows) >= l.max {
		for k, w := range l.windows {
			if now.Sub(w.start) >= period {
				delete(l.windows, k)
			}
		}
		if len(l.windows) >= l.max {
			return false // still full: refuse rather than grow without bound
		}
	}
	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= period {
		l.windows[key] = &window{start: now, count: 1}
		return true
	}
	if w.count >= limit {
		return false
	}
	w.count++
	return true
}
