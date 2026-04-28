package backup

// NoopManager is a BackupService that does nothing.
// Used when R2 is not configured.
type NoopManager struct{}

func (n *NoopManager) TriggerAsync() {}
func (n *NoopManager) RunNow() error { return nil }
