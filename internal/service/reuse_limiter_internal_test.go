package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReuseLimiter_KeysAreIndependent(t *testing.T) {
	l := newReuseLimiter(10*time.Minute, time.Hour, 100)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	rec, _, _ := l.observe("fam-a", now)
	assert.True(t, rec)
	rec, _, _ = l.observe("fam-b", now)
	assert.True(t, rec, "another family's first presentation is never suppressed")
	rec, _, _ = l.observe("fam-a", now.Add(time.Second))
	assert.False(t, rec)
}

func TestReuseLimiter_SummaryCountsSuppressed(t *testing.T) {
	l := newReuseLimiter(10*time.Minute, time.Hour, 100)
	t0 := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	l.observe("f", t0)
	l.observe("f", t0.Add(time.Minute))
	l.observe("f", t0.Add(2*time.Minute))
	rec, n, since := l.observe("f", t0.Add(10*time.Minute))
	assert.True(t, rec)
	assert.Equal(t, 2, n)
	assert.Equal(t, t0.Add(time.Minute), since)

	// The count resets with each summary.
	rec, n, _ = l.observe("f", t0.Add(20*time.Minute))
	assert.True(t, rec)
	assert.Equal(t, 0, n)
}

func TestReuseLimiter_PrunesIdleEntries(t *testing.T) {
	l := newReuseLimiter(10*time.Minute, time.Hour, 100)
	t0 := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	l.observe("old", t0)
	l.observe("new", t0.Add(90*time.Minute))
	assert.Equal(t, 1, l.size(), "an entry idle past the idle window is dropped")

	// A pruned family starts afresh: its next presentation is recorded.
	rec, _, _ := l.observe("old", t0.Add(91*time.Minute))
	assert.True(t, rec)
}

// The map is bounded. When full, it is cleared rather than refusing to record:
// losing throttle state costs a few extra lines, never a missing event.
func TestReuseLimiter_BoundedSize(t *testing.T) {
	l := newReuseLimiter(10*time.Minute, time.Hour, 3)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 10; i++ {
		rec, _, _ := l.observe(fmt.Sprintf("fam-%d", i), now)
		assert.True(t, rec)
		assert.LessOrEqual(t, l.size(), 3)
	}
}
