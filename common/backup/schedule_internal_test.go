package backup

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// steppingClock advances by step on every read — the `base + n*step` fake that
// makes a double clock read visible.
type steppingClock struct {
	mu    sync.Mutex
	base  time.Time
	step  time.Duration
	reads int
}

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.base.Add(time.Duration(c.reads) * c.step)
	c.reads++
	return now
}

func (c *steppingClock) Reads() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads
}

// TestScheduleDelay_ReadsTheClockOnce pins the target and the delay to one
// instant. They are two halves of one decision: computing the target from one
// reading of the clock and the delay to it from another means the Manager
// waits for a duration that does not reach the instant it picked.
func TestScheduleDelay_ReadsTheClockOnce(t *testing.T) {
	clock := &steppingClock{
		base: time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC),
		step: time.Hour,
	}
	m := NewManager(Config{
		DBPath:       ":memory:",
		Schedule:     "daily",
		ScheduleHour: 3,
		Clock:        clock.Now,
	}, nil, nil)

	d, ok := m.scheduleDelay()

	assert.True(t, ok)
	assert.Equal(t, 2*time.Hour, d,
		"01:00 to the 03:00 target is two hours; a second clock read would make it one")
	assert.Equal(t, 1, clock.Reads(), "one decision, one reading of the clock")
}

func TestScheduleDelay_OffHasNoDelay(t *testing.T) {
	clock := &steppingClock{base: time.Date(2026, 9, 15, 1, 0, 0, 0, time.UTC), step: time.Hour}
	m := NewManager(Config{DBPath: ":memory:", Schedule: "off", Clock: clock.Now}, nil, nil)

	_, ok := m.scheduleDelay()
	assert.False(t, ok, "Schedule=off never fires, so there is nothing to wait for")
}
