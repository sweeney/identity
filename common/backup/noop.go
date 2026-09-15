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

// Status reports a Manager that has never run, because this one never will:
// the zero Status, whose Configured field is false. That flag is the whole
// point of the method — it lets a health report distinguish "no backup
// destination is configured" from "configured, and nothing has happened yet",
// which are otherwise the same set of zero values.
//
// Note that domain interfaces declaring only TriggerAsync and RunNow — as
// identity's own domain.BackupService does — still need widening before a
// consumer can call this without a type assertion.
func (n *NoopManager) Status() Status { return Status{} }
