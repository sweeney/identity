package backup

// download_test.go covers WP3 (GHSA-c9v9-fw88-f6qw) on the restore path.
//
// Download opened the destination with os.Create, which truncates. The
// destination on a restore is the live database (common/cli RestoreBackup
// passes cfg.DBPath straight through), so the existing database was destroyed
// before a single byte of the replacement arrived. A network failure mid-body
// therefore left no database at all — no backup of what was there, and only a
// partial copy of what was coming.
//
// os.Create also applies the process umask, so the credential database was
// world-readable for the whole transfer; the 0600 was applied only on the
// success path, at the end.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingReader yields some bytes and then fails, standing in for a connection
// that drops mid-body.
type failingReader struct {
	data []byte
	n    int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n >= len(r.data) {
		return 0, errors.New("connection reset by peer")
	}
	n := copy(p, r.data[r.n:])
	r.n += n
	return n, nil
}

func TestStreamToFile_MidStreamFailure_LeavesExistingFileIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	original := []byte("the live database nobody backed up")
	require.NoError(t, os.WriteFile(path, original, 0600))

	err := streamToFile(&failingReader{data: []byte("partial replacement")}, path)
	require.Error(t, err, "a failed download must be reported")

	got, readErr := os.ReadFile(path)
	require.NoError(t, readErr, "the existing database must still exist")
	assert.Equal(t, original, got,
		"a failed download must leave the existing database untouched")
}

func TestStreamToFile_Success_ReplacesAtomicallyAndIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0644))

	require.NoError(t, streamToFile(strings.NewReader("new contents"), path))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "new contents", string(got))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, "-rw-------", info.Mode().String(),
		"the restored credential database must be owner-only")
}

func TestStreamToFile_LeavesNoTempFileBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.db")

	err := streamToFile(&failingReader{data: []byte("partial")}, path)
	require.Error(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries,
		"a failed download must not leave a partial file behind")
}

var _ io.Reader = (*failingReader)(nil)
