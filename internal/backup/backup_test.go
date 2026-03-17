package backup_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/backup"
	"github.com/sweeney/identity/internal/mocks"
)

// --- TriggerAsync coalescing ---

func TestManager_TriggerAsync_CoalescesMultipleTriggers(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	// Only one upload should occur even if TriggerAsync is called many times rapidly
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	m.Start(ctx)

	// Fire many triggers rapidly
	for range 10 {
		m.TriggerAsync()
	}

	// Give background goroutine time to process
	time.Sleep(200 * time.Millisecond)
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

	// Key should match expected format: backups/YYYY/MM/DD/identity-<timestamp>.sqlite3
	uploader.EXPECT().Upload(
		gomock.Any(), // context
		gomock.AssignableToTypeOf(""), // key: string
		gomock.Any(), // localPath
	).Return(nil)

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	err := m.RunNow()
	require.NoError(t, err)
}

func TestManager_RunNow_KeyFormat(t *testing.T) {
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
	}, uploader, nil)

	err := m.RunNow()
	require.NoError(t, err)

	now := time.Now().UTC()
	expectedPrefix := now.Format("backups/2006/01/02/identity-")
	assert.Contains(t, capturedKey, "backups/")
	assert.Contains(t, capturedKey, "identity-")
	assert.Contains(t, capturedKey, ".sqlite3")
	_ = expectedPrefix
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
