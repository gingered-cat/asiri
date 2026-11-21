package service

import (
	"sync"
	"time"

	"github.com/gingered-cat/asiri/internal/domain"
)

// limiter is a token bucket per client. It exists to catch a looping or
// hijacked agent, not to protect capacity.
type limiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	buckets map[domain.ClientID]*bucket
}

type bucket struct {
	tokens      float64
	at          time.Time
	lastAnomaly time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	return &limiter{perSec: float64(perMinute) / 60, burst: float64(burst), buckets: map[domain.ClientID]*bucket{}}
}

// allow takes a token. When it refuses, report says whether this is the
// first refusal in a minute (so the audit log isn't flooded).
func (l *limiter) allow(id domain.ClientID, now time.Time) (ok, report bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[id]
	if b == nil {
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[id] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.at).Seconds()*l.perSec)
	b.at = now
	if b.tokens >= 1 {
		b.tokens--
		return true, false
	}
	if now.Sub(b.lastAnomaly) >= time.Minute {
		b.lastAnomaly = now
		return false, true
	}
	return false, false
}
