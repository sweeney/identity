package backup

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/domain"

	_ "modernc.org/sqlite"
)

// Uploader is the interface for uploading a backup file to object storage.
// The concrete implementation uses Cloudflare R2 via the S3-compatible API.
//
//go:generate mockgen -destination=../mocks/mock_uploader.go -package=mocks github.com/sweeney/identity/internal/backup Uploader
type Uploader interface {
	// Upload uploads the file at localPath to the given key in the configured bucket.
	Upload(ctx context.Context, key, localPath string) error
}

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
}

// Manager handles scheduled and on-demand database backups.
type Manager struct {
	cfg      Config
	uploader Uploader
	audit    domain.AuditRepository
	trigger  chan struct{}

	mu       sync.Mutex
	lastRun  time.Time
	pendingT *time.Timer
}

// NewManager creates a Manager. ServiceName defaults to "identity" if unset.
func NewManager(cfg Config, uploader Uploader, audit domain.AuditRepository) *Manager {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "identity"
	}
	return &Manager{
		cfg:      cfg,
		uploader: uploader,
		audit:    audit,
		trigger:  make(chan struct{}, 1),
	}
}

// Start launches the background goroutine that processes backup triggers.
// It runs until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
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
	daily := m.nextDailyTick()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.trigger:
			m.handleTrigger()
		case <-daily:
			daily = m.nextDailyTick()
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
	if m.audit == nil {
		return
	}
	eventType := domain.EventBackupSuccess
	if !success {
		eventType = domain.EventBackupFailure
	}
	_ = m.audit.Record(&domain.AuthEvent{
		ID:         uuid.New().String(),
		EventType:  eventType,
		Username:   "system",
		Detail:     detail,
		OccurredAt: time.Now().UTC(),
	})
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

// nextDailyTick returns a channel that fires at the next 03:00 UTC.
func (m *Manager) nextDailyTick() <-chan time.Time {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return time.After(time.Until(next))
}
