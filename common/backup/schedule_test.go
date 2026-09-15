package backup_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/common/backup"
	"github.com/sweeney/identity/common/backup/mocks"
)

// schedule_test.go covers issue #45 point 2: the Manager called time.Now
// directly, so nothing about the schedule could be asserted without waiting a
// day for it. Config.Clock makes the existing arithmetic reachable, and
// NextRun exposes the answer the loop already computes.

func TestManager_NextRun(t *testing.T) {
	tests := []struct {
		name     string
		schedule string
		hour     int
		now      string
		want     string
	}{
		{
			name:     "daily before the hour runs today",
			schedule: "daily",
			hour:     3,
			now:      "2026-09-15T01:30:00Z",
			want:     "2026-09-15T03:00:00Z",
		},
		{
			name:     "daily after the hour runs tomorrow",
			schedule: "daily",
			hour:     3,
			now:      "2026-09-15T04:00:00Z",
			want:     "2026-09-16T03:00:00Z",
		},
		{
			// The difference between a daily backup and a tight loop: the run
			// that lands exactly on the scheduled hour must schedule tomorrow,
			// not the instant it is already standing on.
			name:     "daily exactly on the hour runs tomorrow",
			schedule: "daily",
			hour:     3,
			now:      "2026-09-15T03:00:00Z",
			want:     "2026-09-16T03:00:00Z",
		},
		{
			name:     "daily at hour zero is midnight",
			schedule: "daily",
			hour:     0,
			now:      "2026-09-15T12:00:00Z",
			want:     "2026-09-16T00:00:00Z",
		},
		{
			name:     "daily crossing a month boundary",
			schedule: "daily",
			hour:     3,
			now:      "2026-09-30T05:00:00Z",
			want:     "2026-10-01T03:00:00Z",
		},
		{
			// 2026-09-15 is a Tuesday.
			name:     "weekly midweek runs on the coming Sunday",
			schedule: "weekly",
			hour:     3,
			now:      "2026-09-15T04:00:00Z",
			want:     "2026-09-20T03:00:00Z",
		},
		{
			name:     "weekly on Sunday before the hour runs today",
			schedule: "weekly",
			hour:     3,
			now:      "2026-09-20T01:00:00Z",
			want:     "2026-09-20T03:00:00Z",
		},
		{
			name:     "weekly exactly on the hour runs next Sunday",
			schedule: "weekly",
			hour:     3,
			now:      "2026-09-20T03:00:00Z",
			want:     "2026-09-27T03:00:00Z",
		},
		{
			name:     "monthly midmonth runs on the first of next month",
			schedule: "monthly",
			hour:     3,
			now:      "2026-09-15T04:00:00Z",
			want:     "2026-10-01T03:00:00Z",
		},
		{
			name:     "monthly on the first before the hour runs today",
			schedule: "monthly",
			hour:     3,
			now:      "2026-09-01T02:59:59Z",
			want:     "2026-09-01T03:00:00Z",
		},
		{
			name:     "monthly exactly on the hour runs next month",
			schedule: "monthly",
			hour:     3,
			now:      "2026-09-01T03:00:00Z",
			want:     "2026-10-01T03:00:00Z",
		},
		{
			// 2026-12-28 is a Monday; the coming Sunday is in the next year.
			name:     "weekly rolls across a year boundary",
			schedule: "weekly",
			hour:     3,
			now:      "2026-12-28T00:00:00Z",
			want:     "2027-01-03T03:00:00Z",
		},
		{
			name:     "monthly in December rolls into January",
			schedule: "monthly",
			hour:     3,
			now:      "2026-12-20T00:00:00Z",
			want:     "2027-01-01T03:00:00Z",
		},
		{
			name:     "empty schedule defaults to daily",
			schedule: "",
			hour:     3,
			now:      "2026-09-15T04:00:00Z",
			want:     "2026-09-16T03:00:00Z",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock(mustParse(tc.now))
			m := backup.NewManager(backup.Config{
				DBPath:       ":memory:",
				Schedule:     tc.schedule,
				ScheduleHour: tc.hour,
				Clock:        clock.Now,
			}, nil, nil)

			assert.Equal(t, mustParse(tc.want), m.NextRun())
		})
	}
}

func TestManager_NextRun_OffIsZero(t *testing.T) {
	clock := newFakeClock(mustParse("2026-09-15T01:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:   ":memory:",
		Schedule: "off",
		Clock:    clock.Now,
	}, nil, nil)

	assert.True(t, m.NextRun().IsZero(),
		"Schedule=off never fires, so there is no next run to report")
}

func TestManager_NextRun_FollowsTheInjectedClock(t *testing.T) {
	clock := newFakeClock(mustParse("2026-09-15T01:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:       ":memory:",
		Schedule:     "daily",
		ScheduleHour: 3,
		Clock:        clock.Now,
	}, nil, nil)

	require.Equal(t, mustParse("2026-09-15T03:00:00Z"), m.NextRun())

	// Step past today's window; the next run must move with the clock rather
	// than with wall time.
	clock.Advance(4 * time.Hour)
	assert.Equal(t, mustParse("2026-09-16T03:00:00Z"), m.NextRun())
}

func TestManager_NextRun_DefaultsToWallClock(t *testing.T) {
	// A Manager with no Clock keeps the existing behaviour: the next run is
	// computed against time.Now, and is always in the future.
	m := backup.NewManager(backup.Config{
		DBPath:       ":memory:",
		Schedule:     "daily",
		ScheduleHour: 3,
	}, nil, nil)

	next := m.NextRun()
	assert.True(t, next.After(time.Now().UTC()), "next run should be in the future, got %s", next)
	assert.LessOrEqual(t, time.Until(next), 24*time.Hour, "a daily schedule is never more than a day out")
	assert.Equal(t, time.UTC, next.Location(), "the schedule is defined in UTC")
}

func TestManager_RunNow_BackupKeyUsesTheInjectedClock(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var key string
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k, _ string) error {
			key = k
			return nil
		},
	)

	clock := newFakeClock(mustParse("2026-02-03T04:05:06Z"))
	m := backup.NewManager(backup.Config{
		DBPath:      ":memory:",
		BucketName:  "test-bucket",
		Env:         "production",
		ServiceName: "identity",
		Clock:       clock.Now,
	}, uploader, nil)

	require.NoError(t, m.RunNow())

	// The key is derived from the clock, so it is exact rather than "today".
	assert.Equal(t, "production/backups/identity/2026/02/03/identity-2026-02-03T04:05:06Z.sqlite3", key)
	assert.True(t, strings.HasSuffix(key, ".sqlite3"))
}
