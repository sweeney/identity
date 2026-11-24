package service

import (
	"sync"
	"time"
)

// reuseLimiter throttles audit records for revoked refresh tokens that keep
// being presented. A client stuck with a dead token retries on a timer; the
// first presentation is worth a full record, the next few hundred are not.
//
// Per key (a token family), the first observation is recorded. Later ones
// inside the window are only counted, and the first one after the window is
// recorded as a summary carrying that count. State is in memory: a restart
// forgets it, which costs at most one extra record per family.
type reuseLimiter struct {
	mu        sync.Mutex
	window    time.Duration
	idle      time.Duration
	max       int
	entries   map[string]*reuseEntry
	lastPrune time.Time
}

type reuseEntry struct {
	lastRecorded time.Time
	lastSeen     time.Time
	suppressed   int
	since        time.Time // first suppressed observation in the current window
}

func newReuseLimiter(window, idle time.Duration, max int) *reuseLimiter {
	return &reuseLimiter{window: window, idle: idle, max: max, entries: map[string]*reuseEntry{}}
}

// observe reports whether this observation should be recorded and, if so, how
// many were suppressed since the last record and when the first of them was.
func (l *reuseLimiter) observe(key string, now time.Time) (record bool, suppressed int, since time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastPrune) >= l.idle {
		for k, e := range l.entries {
			if now.Sub(e.lastSeen) >= l.idle {
				delete(l.entries, k)
			}
		}
		l.lastPrune = now
	}

	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.max {
			// Losing throttle state costs a few extra records; refusing to
			// record would cost a missing event. Clear and carry on.
			l.entries = map[string]*reuseEntry{}
		}
		l.entries[key] = &reuseEntry{lastRecorded: now, lastSeen: now}
		return true, 0, time.Time{}
	}

	e.lastSeen = now
	if now.Sub(e.lastRecorded) < l.window {
		if e.suppressed == 0 {
			e.since = now
		}
		e.suppressed++
		return false, 0, time.Time{}
	}
	suppressed, since = e.suppressed, e.since
	e.suppressed, e.since, e.lastRecorded = 0, time.Time{}, now
	return true, suppressed, since
}

func (l *reuseLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
