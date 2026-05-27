package backup

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Uploader is the interface for uploading a backup file to object storage.
// The concrete implementation uses Cloudflare R2 via the S3-compatible API.
//
//go:generate mockgen -destination=mocks/mock_uploader.go -package=mocks github.com/sweeney/identity/common/backup Uploader
type Uploader interface {
	// Upload uploads the file at localPath to the given key in the configured bucket.
	Upload(ctx context.Context, key, localPath string) error
}

// EventRecorder is invoked after every backup attempt. detail is the R2 key
// on success or a short error description on failure. A nil EventRecorder
// disables event recording.
//
// This is a callback rather than an interface so the common module stays
// free of identity's domain types — callers adapt their own audit sinks
// (a domain.AuditRepository, a logger, etc.) into this signature.
type EventRecorder func(success bool, detail string)

// Config holds backup configuration.
type Config struct {
	DBPath     string
	BucketName string
	Env        string // "development" or "production" — used as R2 key prefix
	// ServiceName is used as the per-service key segment and filename prefix.
	// Defaults to "identity" for backward compatibility when unset.
	ServiceName string
	// MinInterval is the minimum time between consecutive triggered backups.
	// Scheduled daily backups are unaffected. Zero disables throttling.
	MinInterval time.Duration
	// Schedule controls when automatic timed backups run.
	// Valid values: "daily" (default), "weekly" (Sundays), "monthly" (1st of month), "off".
	// Empty string defaults to "daily".
	Schedule string
	// ScheduleHour is the UTC hour (0–23) at which scheduled backups run.
	// Defaults to 3 (03:00 UTC) when zero.
	ScheduleHour int
}

// Manager handles scheduled and on-demand database backups.
type Manager struct {
	cfg      Config
	uploader Uploader
	record   EventRecorder
	trigger  chan struct{}

	mu       sync.Mutex
	lastRun  time.Time
	pendingT *time.Timer
}

// NewManager creates a Manager. ServiceName defaults to "identity" if unset.
// record may be nil to disable event recording.
func NewManager(cfg Config, uploader Uploader, record EventRecorder) *Manager {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "identity"
	}
	if cfg.Schedule == "" {
		cfg.Schedule = "daily"
	}
	if cfg.ScheduleHour == 0 {
		cfg.ScheduleHour = 3
	}
	return &Manager{
		cfg:      cfg,
		uploader: uploader,
		record:   record,
		trigger:  make(chan struct{}, 1),
	}
}

// Start launches the background goroutine that processes backup triggers.
// It runs until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	if m.cfg.Schedule == "off" {
		log.Printf("backup: scheduled backups disabled (triggered and on-demand only)")
	} else {
		log.Printf("backup: schedule=%s hour=%02d:00 UTC bucket=%s", m.cfg.Schedule, m.cfg.ScheduleHour, m.cfg.BucketName)
	}
	go m.loop(ctx)
}

// TriggerAsync queues a backup asynchronously. If a backup is already pending
// the send is a no-op (coalescing channel of size 1). When MinInterval is
// configured, triggers arriving inside the cooldown window are deferred to
// fire once at the window's end, so rapid bursts coalesce into a single
// upload.
func (m *Manager) TriggerAsync() {
	select {
	case m.trigger <- struct{}{}:
	default:
		// Already queued; skip
	}
}

// RunNow executes a backup synchronously.
func (m *Manager) RunNow() error {
	return m.run()
}

func (m *Manager) loop(ctx context.Context) {
	scheduled := m.nextScheduledTick()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.trigger:
			m.handleTrigger()
		case <-scheduled:
			scheduled = m.nextScheduledTick()
			if err := m.run(); err != nil {
				log.Printf("scheduled backup failed: %v", err)
			}
			m.markRan()
		}
	}
}

// handleTrigger runs a backup unless we are still inside the cooldown window
// from the last one. In that case the trigger is deferred via a single timer
// so bursts collapse to one upload at the end of the window.
func (m *Manager) handleTrigger() {
	m.mu.Lock()
	if m.cfg.MinInterval > 0 && !m.lastRun.IsZero() {
		sinceLast := time.Since(m.lastRun)
		if sinceLast < m.cfg.MinInterval {
			if m.pendingT == nil {
				remaining := m.cfg.MinInterval - sinceLast
				m.pendingT = time.AfterFunc(remaining, func() {
					m.mu.Lock()
					m.pendingT = nil
					m.mu.Unlock()
					m.TriggerAsync()
				})
			}
			m.mu.Unlock()
			return
		}
	}
	m.mu.Unlock()

	if err := m.run(); err != nil {
		log.Printf("backup failed: %v", err)
	}
	m.markRan()
}

func (m *Manager) markRan() {
	m.mu.Lock()
	m.lastRun = time.Now()
	m.mu.Unlock()
}

func (m *Manager) run() error {
	start := time.Now()
	key := backupKey(m.cfg.Env, m.cfg.ServiceName, start.UTC())

	log.Printf("backup: starting upload to %s/%s", m.cfg.BucketName, key)

	// For :memory: databases (used in tests), skip file creation.
	if m.cfg.DBPath == ":memory:" {
		return m.uploader.Upload(context.Background(), key, "")
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("%s-backup-*.sqlite3", m.cfg.ServiceName))
	if err != nil {
		m.recordBackup(false, fmt.Sprintf("create temp file: %v", err))
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := copyDB(m.cfg.DBPath, tmpPath); err != nil {
		m.recordBackup(false, fmt.Sprintf("copy db: %v", err))
		return fmt.Errorf("copy db: %w", err)
	}

	if err := m.uploader.Upload(context.Background(), key, tmpPath); err != nil {
		m.recordBackup(false, fmt.Sprintf("upload: %v", err))
		return fmt.Errorf("upload backup: %w", err)
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("backup: uploaded %s in %s", key, elapsed)
	m.recordBackup(true, key)
	return nil
}

func (m *Manager) recordBackup(success bool, detail string) {
	if m.record == nil {
		return
	}
	m.record(success, detail)
}

// backupKey returns the R2 object key for a backup at time t.
//
// Format: {env}/backups/{service}/{YYYY/MM/DD}/{service}-{RFC3339}.sqlite3
//
// The service segment lets a single R2 bucket host backups for multiple
// services (identity, config, ...) without collision. Legacy identity
// backups at {env}/backups/{YYYY/MM/DD}/identity-*.sqlite3 remain
// discoverable via ListBackupsWithPrefix because they sit under the same
// {env}/backups/ prefix.
func backupKey(env, service string, t time.Time) string {
	if env == "" {
		env = "development"
	}
	if service == "" {
		service = "identity"
	}
	return filepath.ToSlash(fmt.Sprintf("%s/backups/%s/%s/%s-%s.sqlite3",
		env,
		service,
		t.Format("2006/01/02"),
		service,
		t.Format(time.RFC3339),
	))
}

// copyDB copies a SQLite database file safely using a direct file copy.
// For a production-grade hot backup, replace with the SQLite Online Backup API.
func copyDB(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

// nextScheduledTick returns a channel that fires at the next scheduled backup
// time based on cfg.Schedule and cfg.ScheduleHour. Returns nil (blocks forever
// in select) when Schedule is "off".
func (m *Manager) nextScheduledTick() <-chan time.Time {
	if m.cfg.Schedule == "off" {
		return nil
	}
	now := time.Now().UTC()
	h := m.cfg.ScheduleHour
	var next time.Time
	switch m.cfg.Schedule {
	case "weekly":
		daysUntilSunday := int(time.Sunday-now.Weekday()+7) % 7
		next = time.Date(now.Year(), now.Month(), now.Day()+daysUntilSunday, h, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.Add(7 * 24 * time.Hour)
		}
	case "monthly":
		next = time.Date(now.Year(), now.Month(), 1, h, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = time.Date(now.Year(), now.Month()+1, 1, h, 0, 0, 0, time.UTC)
		}
	default: // "daily"
		next = time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, time.UTC)
		if !next.After(now) {
			next = next.Add(24 * time.Hour)
		}
	}
	return time.After(time.Until(next))
}
