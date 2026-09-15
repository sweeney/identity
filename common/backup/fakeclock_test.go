package backup_test

import (
	"sync"
	"time"
)

// fakeClock is a manually advanced clock. It exists so the schedule and the
// status timestamps can be asserted exactly, rather than by sleeping and
// hoping — see Config.Clock.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

// Now satisfies the Config.Clock signature.
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// mustParse is a helper for writing instants inline in table tests.
func mustParse(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}
