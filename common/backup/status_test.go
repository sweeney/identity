package backup_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/common/backup"
	"github.com/sweeney/identity/common/backup/mocks"
)

// status_test.go covers issue #45 point 1: the Manager knew what had happened
// to every backup and told nobody, so each consumer that reports health grew
// its own mutex-guarded shadow copy of the same facts.

func TestManager_Status_ZeroBeforeAnyBackup(t *testing.T) {
	clock := newFakeClock(mustParse("2026-09-15T01:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:       ":memory:",
		Schedule:     "daily",
		ScheduleHour: 3,
		Clock:        clock.Now,
	}, nil, nil)

	s := m.Status()
	assert.True(t, s.LastAttempt.IsZero(), "no attempt has been made")
	assert.True(t, s.LastSuccess.IsZero(), "no backup has succeeded")
	assert.Empty(t, s.LastKey)
	assert.Empty(t, s.LastError)
	assert.Zero(t, s.Successes)
	assert.Zero(t, s.Failures)
	assert.Equal(t, mustParse("2026-09-15T03:00:00Z"), s.NextRun,
		"a health report wants the next run alongside the last one")
}

func TestManager_Status_RecordsSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	var key string
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(_ context.Context, k, _ string) error {
			key = k
			return nil
		},
	)

	clock := newFakeClock(mustParse("2026-09-15T03:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
		Clock:      clock.Now,
	}, uploader, nil)

	require.NoError(t, m.RunNow())

	s := m.Status()
	assert.Equal(t, clock.Now(), s.LastAttempt)
	assert.Equal(t, clock.Now(), s.LastSuccess,
		"attempt and success are equal after a healthy backup — that equality is the signal")
	assert.Equal(t, key, s.LastKey)
	assert.Empty(t, s.LastError)
	assert.Equal(t, 1, s.Successes)
	assert.Equal(t, 0, s.Failures)
}

// TestManager_Status_FailureDoesNotMoveLastSuccess is the first of the two
// details the issue calls out: keeping the timestamps apart is the whole
// signal. Equal means healthy; a lagging LastSuccess means failing now.
func TestManager_Status_FailureDoesNotMoveLastSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	gomock.InOrder(
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("connection reset")),
	)

	clock := newFakeClock(mustParse("2026-09-15T03:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
		Clock:      clock.Now,
	}, uploader, nil)

	require.NoError(t, m.RunNow())
	succeededAt := m.Status().LastSuccess

	clock.Advance(24 * time.Hour)
	require.Error(t, m.RunNow())

	s := m.Status()
	assert.Equal(t, succeededAt, s.LastSuccess,
		"a failed attempt must not advance LastSuccess — the gap is how staleness is detected")
	assert.Equal(t, clock.Now(), s.LastAttempt, "the attempt itself did happen")
	assert.Equal(t, 24*time.Hour, s.LastAttempt.Sub(s.LastSuccess))
	assert.Contains(t, s.LastError, "connection reset")
	assert.Equal(t, 1, s.Successes)
	assert.Equal(t, 1, s.Failures)
}

// TestManager_Status_RetainsLastKeyAcrossFailure is the second detail: the
// newest good backup must still be nameable while backups are failing, which
// is exactly when you need to find it.
func TestManager_Status_RetainsLastKeyAcrossFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	gomock.InOrder(
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("bucket unreachable")),
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("bucket unreachable")),
	)

	clock := newFakeClock(mustParse("2026-09-15T03:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:      ":memory:",
		BucketName:  "test-bucket",
		Env:         "production",
		ServiceName: "identity",
		Clock:       clock.Now,
	}, uploader, nil)

	require.NoError(t, m.RunNow())
	goodKey := m.Status().LastKey
	require.NotEmpty(t, goodKey)

	for range 2 {
		clock.Advance(24 * time.Hour)
		require.Error(t, m.RunNow())
	}

	s := m.Status()
	assert.Equal(t, goodKey, s.LastKey,
		"LastKey names the newest good backup, not the newest attempt")
	assert.Equal(t, 2, s.Failures)
}

func TestManager_Status_SuccessClearsLastError(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

	gomock.InOrder(
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("connection reset")),
		uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil),
	)

	clock := newFakeClock(mustParse("2026-09-15T03:00:00Z"))
	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
		Clock:      clock.Now,
	}, uploader, nil)

	require.Error(t, m.RunNow())
	require.NotEmpty(t, m.Status().LastError)

	clock.Advance(time.Hour)
	require.NoError(t, m.RunNow())

	s := m.Status()
	assert.Empty(t, s.LastError,
		"LastError describes the last attempt, so a recovery clears it")
	assert.Equal(t, s.LastAttempt, s.LastSuccess, "recovered: the two timestamps meet again")
}

// TestManager_Status_LastErrorIsRedacted ties point 4 to point 1: the error
// that reaches a health endpoint is the AWS SDK's, and it goes out scrubbed.
func TestManager_Status_LastErrorIsRedacted(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(
		"api error SignatureDoesNotMatch: Credential=AKIAIOSFODNN7EXAMPLE/20260915/auto/s3/aws4_request, " +
			"Signature=6f2a1b9c4d8e7f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a"))

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	require.Error(t, m.RunNow())

	s := m.Status()
	assert.NotContains(t, s.LastError, "AKIAIOSFODNN7EXAMPLE")
	assert.NotContains(t, s.LastError, "6f2a1b9c4d8e7f3a2b1c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a")
	assert.Contains(t, s.LastError, "SignatureDoesNotMatch",
		"the diagnosis survives; only the credential-shaped values go")
}

func TestManager_EventRecorderDetailIsRedacted(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New(
		"put object: x-amz-security-token=IQoJb3JpZ2luX2VjELL9v1AbCdEfGhIjKlMnOpQrStUv"))

	var detail string
	record := func(success bool, d string) { detail = d }

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, record)

	require.Error(t, m.RunNow())
	assert.NotContains(t, detail, "IQoJb3JpZ2luX2VjELL9v1AbCdEfGhIjKlMnOpQrStUv",
		"an audit sink is a surfaced destination too")
}

// TestManager_Status_TracksTriggeredRuns confirms the status is maintained by
// the background loop, not only by the synchronous RunNow path.
func TestManager_Status_TracksTriggeredRuns(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)

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
		Schedule:   "off",
	}, uploader, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	m.Start(ctx)
	m.TriggerAsync()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("timed out waiting for the triggered backup")
	}

	// The upload has returned but the status is written just after; poll
	// briefly rather than racing it.
	require.Eventually(t, func() bool { return m.Status().Successes == 1 }, time.Second, 10*time.Millisecond,
		"a triggered backup is recorded in the status like any other")
	assert.NotEmpty(t, m.Status().LastKey)
}

func TestManager_Status_IsSafeUnderConcurrentBackups(t *testing.T) {
	ctrl := gomock.NewController(t)
	uploader := mocks.NewMockUploader(ctrl)
	uploader.EXPECT().Upload(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	m := backup.NewManager(backup.Config{
		DBPath:     ":memory:",
		BucketName: "test-bucket",
	}, uploader, nil)

	// Readers and writers together: -race must stay quiet. This is the
	// bookkeeping every consumer was writing by hand.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 25 {
				_ = m.RunNow()
			}
		}()
		go func() {
			defer wg.Done()
			for range 25 {
				_ = m.Status()
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 100, m.Status().Successes)
}

func TestNoopManager_Status_IsZero(t *testing.T) {
	var n backup.NoopManager
	s := n.Status()
	assert.True(t, s.LastAttempt.IsZero())
	assert.True(t, s.LastSuccess.IsZero())
	assert.True(t, s.NextRun.IsZero(), "nothing is scheduled when backups are not configured")
	assert.Zero(t, s.Successes)
	assert.Zero(t, s.Failures)
}
