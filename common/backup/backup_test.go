package backup_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/common/backup"
	"github.com/sweeney/identity/common/backup/mocks"
)

// --- TriggerAsync coalescing ---

func TestManager_TriggerAsync_CoalescesMultipleTriggers(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	// Only one upload should occur even if TriggerAsync is called many times rapidly.
	done := make(chan struct{})
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string) error {
			close(done)
			return nil
		},
	).Times(1)

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	// Fire all triggers before starting the background goroutine. The channel
	// has capacity 1, so exactly one item is queued; the remaining 9 hit the
	// default branch and are dropped. This makes coalescing deterministic.
	for range 10 {
		m.TriggerAsync()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m.Start(ctx)

	select {
	case <-done:
		// single upload completed — pass
	case <-ctx.Done():
		t.Fatal("timed out waiting for upload")
	}
}

func TestManager_TriggerAsync_NoBlockOnFullChannel(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	m := backup.NewManager(backup.Config{DBPath: ":memory:", BucketName: "test-bucket"}, uploader, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	m.Start(ctx)

	// Should not block even if called in a tight loop
	done := make(chan struct{})
	go func() {
		for range 100 {
			m.TriggerAsync()
		}
		close(done)
	}()

	select {
	case <-done:
		// success — TriggerAsync never blocked
	case <-time.After(500 * time.Millisecond):
		t.Fatal("TriggerAsync blocked unexpectedly")
	}
}

// --- RunNow ---

func TestManager_RunNow_CallsUploader(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	uploader.EXPECT().Upload(
		gomock.Any(),                  // context
		gomock.AssignableToTypeOf(""), // key: string
		gomock.Any(),                  // localPath
	).Return(nil)

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	err := m.RunNow()
	require.NoError(t, err)
}

func TestManager_RunNow_KeyFormat_DefaultsToIdentity(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var capturedKey string
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, key, _ string) error {
			capturedKey = key
			return nil
		},
	)

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
		Env:        "development",
		// ServiceName intentionally left unset to assert the default.
	}, uploader, nil)

	err := m.RunNow()
	require.NoError(t, err)

	// New format includes a service segment; default should be "identity".
	assert.Contains(t, capturedKey, "development/backups/identity/")
	assert.Contains(t, capturedKey, "/identity-")
	assert.True(t, strings.HasSuffix(capturedKey, ".sqlite3"))
}

func TestManager_RunNow_KeyFormat_UsesConfiguredService(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var capturedKey string
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, key, _ string) error {
			capturedKey = key
			return nil
		},
	)

	m := backup.NewManager(backup.Config{
		DBPath:      ":memory:",
		BucketName:  "test-bucket",
		Env:         "production",
		ServiceName: "config",
	}, uploader, nil)

	err := m.RunNow()
	require.NoError(t, err)

	assert.Contains(t, capturedKey, "production/backups/config/")
	assert.Contains(t, capturedKey, "/config-")
	assert.NotContains(t, capturedKey, "/identity-",
		"config backup key must not collide with identity filename prefix")
}

func TestManager_RunNow_UploaderError_Propagates(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(assert.AnError)

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	err := m.RunNow()
	assert.Error(t, err)
}

// --- MinInterval debounce ---

// TestManager_MinInterval_DebouncesRapidTriggers fires many triggers in quick
// succession and asserts the resulting uploads collapse to exactly two: one
// immediate, one deferred to the end of the cooldown window.
func TestManager_MinInterval_DebouncesRapidTriggers(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var uploads atomic.Int32
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string) error {
			uploads.Add(1)
			return nil
		},
	).AnyTimes()

	m := backup.NewManager(backup.Config{
		DBPath:      ":memory:",
		BucketName:  "test-bucket",
		MinInterval: 150 * time.Millisecond,
	}, uploader, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.Start(ctx)

	// First trigger runs immediately (lastRun is zero). Subsequent triggers
	// during the cooldown window are deferred and coalesce into one follow-up.
	m.TriggerAsync()
	time.Sleep(30 * time.Millisecond)
	for range 5 {
		m.TriggerAsync()
		time.Sleep(20 * time.Millisecond)
	}

	// Wait long enough for the deferred trigger to fire and its backup to run.
	time.Sleep(400 * time.Millisecond)

	got := uploads.Load()
	assert.Equal(t, int32(2), got,
		"expected exactly 2 uploads (1 immediate + 1 deferred after cooldown); got %d", got)
}

// TestManager_MinInterval_ZeroDisablesThrottle confirms that the default
// Config (no MinInterval set) behaves as before the debounce feature: every
// queued trigger runs without rate limiting.
func TestManager_MinInterval_ZeroDisablesThrottle(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var uploads atomic.Int32
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string) error {
			uploads.Add(1)
			return nil
		},
	).AnyTimes()

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
		// MinInterval deliberately zero
	}, uploader, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	m.Start(ctx)

	// Trigger, wait for pickup, repeat. Each trigger gets its own upload.
	for i := 0; i < 3; i++ {
		m.TriggerAsync()
		time.Sleep(60 * time.Millisecond)
	}

	assert.GreaterOrEqual(t, uploads.Load(), int32(3),
		"with MinInterval=0 each spaced-out trigger should result in an upload")
}

// TestManager_MinInterval_SpacedTriggersAllRun asserts that triggers spaced
// further apart than MinInterval each produce an upload (no carryover
// throttling).
func TestManager_MinInterval_SpacedTriggersAllRun(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var uploads atomic.Int32
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, _, _ string) error {
			uploads.Add(1)
			return nil
		},
	).AnyTimes()

	m := backup.NewManager(backup.Config{
		DBPath:      ":memory:",
		BucketName:  "test-bucket",
		MinInterval: 80 * time.Millisecond,
	}, uploader, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.Start(ctx)

	// Three triggers each spaced past the cooldown window.
	for i := 0; i < 3; i++ {
		m.TriggerAsync()
		time.Sleep(150 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, int32(3), uploads.Load(),
		"spaced triggers should each run without debouncing")
}
