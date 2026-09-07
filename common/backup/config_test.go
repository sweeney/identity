package backup

// config_test.go covers two more WP3 (GHSA-c9v9-fw88-f6qw) items.
//
// NewManager could not tell "ScheduleHour was not set" from "ScheduleHour was
// set to 0", so it rewrote midnight to 03:00. BACKUP_HOUR=0 is documented and
// validated (internal/config accepts 0-23 and stores 0 verbatim), so an
// operator who moved backups to midnight silently got 03:00 — and the startup
// line then printed hour=03:00, so the override was invisible.
//
// NoopManager.RunNow returned nil, reporting success for a backup that never
// happened. It is installed whenever R2 is unconfigured.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_ScheduleHourZeroIsMidnight(t *testing.T) {
	m := NewManager(Config{DBPath: "x.db", ScheduleHour: 0}, nil, nil)
	assert.Equal(t, 0, m.ScheduleHour(),
		"BACKUP_HOUR=0 means midnight UTC, not the default")
}

func TestNewManager_ScheduleHourPreserved(t *testing.T) {
	m := NewManager(Config{DBPath: "x.db", ScheduleHour: 17}, nil, nil)
	assert.Equal(t, 17, m.ScheduleHour())
}

func TestNewManager_ScheduleHourOutOfRangeIsClamped(t *testing.T) {
	// The config loader validates the range, but a direct consumer of this
	// package might not, and an out-of-range hour would silently never fire.
	m := NewManager(Config{DBPath: "x.db", ScheduleHour: 99}, nil, nil)
	assert.GreaterOrEqual(t, m.ScheduleHour(), 0)
	assert.LessOrEqual(t, m.ScheduleHour(), 23)
}

func TestNoopManager_RunNow_DoesNotReportSuccess(t *testing.T) {
	var n NoopManager
	err := n.RunNow()
	require.Error(t, err,
		"a no-op backup must not report success — nothing was backed up")
}
