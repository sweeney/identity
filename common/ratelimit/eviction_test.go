package ratelimit

// eviction_test.go covers the third WP6 (GHSA-mpc2-xp7h-7r9x) finding: the
// visitor-map cap turned attacker-controlled key cardinality into a
// service-wide deny-all.
//
// When the map filled, getVisitor returned a deny-all limiter — rate 0, burst
// 0 — to every IP it had not already seen. Combined with a spoofable client-IP
// header (fixed alongside), an attacker could mint a fresh key per request,
// fill the map, and have every genuinely new visitor rejected outright. Even
// without spoofing, an ordinary traffic spike does it.
//
// A full table means we are tracking too many visitors, not that new visitors
// are hostile. Evicting the least recently seen keeps the cap without turning
// it into an outage.

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGetVisitor_FullTable_EvictsRatherThanDenies(t *testing.T) {
	const maxVisitors = 8
	now := time.Now()
	l := &Limiter{
		visitors:    make(map[string]*visitor),
		rate:        10,
		burst:       10,
		maxVisitors: maxVisitors,
		now:         func() time.Time { return now },
	}

	// Fill the table. Every entry is fresh, so the emergency cleanup — which
	// only removes entries older than 30 seconds — has nothing to collect.
	for i := 0; i < maxVisitors; i++ {
		l.getVisitor("10.0.0." + strconv.Itoa(i))
	}
	assert.Equal(t, maxVisitors, l.VisitorCount())

	// A genuine new visitor arrives.
	limiter := l.getVisitor("198.51.100.1")
	assert.True(t, limiter.Allow(),
		"a new visitor must not be denied merely because the table is full")
	assert.LessOrEqual(t, l.VisitorCount(), maxVisitors,
		"the cap must still hold")
}

// The entry evicted is the one seen longest ago, not an arbitrary one.
func TestGetVisitor_FullTable_EvictsLeastRecentlySeen(t *testing.T) {
	const maxVisitors = 4
	now := time.Now()
	l := &Limiter{
		visitors:    make(map[string]*visitor),
		rate:        10,
		burst:       10,
		maxVisitors: maxVisitors,
		now:         func() time.Time { return now },
	}

	for i := 0; i < maxVisitors; i++ {
		l.getVisitor("10.0.0." + strconv.Itoa(i))
		now = now.Add(time.Second)
	}
	// Touch the oldest so it is no longer the least recently seen.
	l.getVisitor("10.0.0.0")
	now = now.Add(time.Second)

	l.getVisitor("198.51.100.1")

	l.mu.Lock()
	defer l.mu.Unlock()
	_, keptTouched := l.visitors["10.0.0.0"]
	_, evicted := l.visitors["10.0.0.1"]
	assert.True(t, keptTouched, "the recently touched visitor must be kept")
	assert.False(t, evicted, "the least recently seen visitor is the one to drop")
}
