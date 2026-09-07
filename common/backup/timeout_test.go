package backup

// timeout_test.go covers the last WP3 (GHSA-c9v9-fw88-f6qw) item on the upload
// path: run() called Upload with context.Background(), so the request had no
// deadline and the manager's own context was never propagated. A hung
// connection wedged the backup goroutine permanently — the loop is synchronous,
// so every later trigger and every scheduled backup silently stopped happening,
// and shutdown could not cancel it either.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hangingUploader blocks until its context is cancelled, like a connection to a
// host that accepts and then never responds.
type hangingUploader struct{ started chan struct{} }

func (h *hangingUploader) Upload(ctx context.Context, key, localPath string) error {
	close(h.started)
	<-ctx.Done()
	return ctx.Err()
}

func TestRun_UploadHasDeadline(t *testing.T) {
	up := &hangingUploader{started: make(chan struct{})}
	m := NewManager(Config{
		DBPath:        ":memory:",
		UploadTimeout: 100 * time.Millisecond,
	}, up, nil)

	done := make(chan error, 1)
	go func() { done <- m.RunNow() }()

	select {
	case err := <-done:
		require.Error(t, err, "an upload that never completes must fail, not hang")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("upload hung with no deadline — the backup goroutine is wedged")
	}
}
