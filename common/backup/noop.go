package backup

import "errors"

// ErrNotConfigured is returned by NoopManager for operations that cannot be
// carried out because no backup destination is configured.
var ErrNotConfigured = errors.New("backup is not configured")

// NoopManager is a BackupService that does nothing.
// Used when R2 is not configured.
type NoopManager struct{}

// TriggerAsync discards the trigger. Background triggers are best-effort and
// have no caller waiting on them, so there is nobody to tell.
func (n *NoopManager) TriggerAsync() {}

// RunNow reports that no backup was taken. It deliberately does not return nil:
// RunNow is the on-demand path, where a caller asked for a backup and is
// entitled to know it did not happen.
func (n *NoopManager) RunNow() error { return ErrNotConfigured }
