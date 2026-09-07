package store

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
)

// AuditStore is the SQLite-backed implementation of domain.AuditRepository.
type AuditStore struct {
	db *db.Database
}

// NewAuditStore creates an AuditStore backed by the given Database.
func NewAuditStore(database *db.Database) *AuditStore {
	return &AuditStore{db: database}
}

func (s *AuditStore) Record(event *domain.AuthEvent) error {
	// Emit to stdout for journalctl / process logs
	log.Print(auditLogLine(event))

	_, err := s.db.DB().Exec(
		`INSERT INTO auth_events (id, event_type, user_id, username, client_id, device_hint, ip_address, detail, occurred_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID,
		event.EventType,
		nullableString(event.UserID),
		event.Username,
		nullableString(event.ClientID),
		nullableString(event.DeviceHint),
		nullableString(event.IPAddress),
		event.Detail,
		formatTime(event.OccurredAt),
	)
	if err != nil {
		return fmt.Errorf("record auth event: %w", err)
	}
	return nil
}

func (s *AuditStore) List(limit int) ([]*domain.AuthEvent, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, event_type, COALESCE(user_id,''), username, COALESCE(client_id,''),
		        COALESCE(device_hint,''), COALESCE(ip_address,''), detail, occurred_at
		 FROM auth_events ORDER BY occurred_at DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list auth events: %w", err)
	}
	defer rows.Close()
	return scanAuthEvents(rows)
}

func (s *AuditStore) ListForUser(userID string, limit int) ([]*domain.AuthEvent, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, event_type, COALESCE(user_id,''), username, COALESCE(client_id,''),
		        COALESCE(device_hint,''), COALESCE(ip_address,''), detail, occurred_at
		 FROM auth_events WHERE user_id = ? ORDER BY occurred_at DESC LIMIT ?`, userID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list auth events for user: %w", err)
	}
	defer rows.Close()
	return scanAuthEvents(rows)
}

func (s *AuditStore) ListFiltered(userID, eventType string, limit, offset int) ([]*domain.AuthEvent, error) {
	rows, err := s.db.DB().Query(
		`SELECT id, event_type, COALESCE(user_id,''), username, COALESCE(client_id,''),
		        COALESCE(device_hint,''), COALESCE(ip_address,''), detail, occurred_at
		 FROM auth_events
		 WHERE (? = '' OR user_id = ?) AND (? = '' OR event_type = ?)
		 ORDER BY occurred_at DESC LIMIT ? OFFSET ?`,
		userID, userID, eventType, eventType, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list filtered auth events: %w", err)
	}
	defer rows.Close()
	return scanAuthEvents(rows)
}

func (s *AuditStore) CountFiltered(userID, eventType string) (int, error) {
	var count int
	err := s.db.DB().QueryRow(
		`SELECT COUNT(*) FROM auth_events
		 WHERE (? = '' OR user_id = ?) AND (? = '' OR event_type = ?)`,
		userID, userID, eventType, eventType,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count filtered auth events: %w", err)
	}
	return count, nil
}

func scanAuthEvents(rows *sql.Rows) ([]*domain.AuthEvent, error) {
	var events []*domain.AuthEvent
	for rows.Next() {
		var e domain.AuthEvent
		var occurredAt string
		err := rows.Scan(
			&e.ID, &e.EventType, &e.UserID, &e.Username,
			&e.ClientID, &e.DeviceHint, &e.IPAddress, &e.Detail, &occurredAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan auth event: %w", err)
		}
		e.OccurredAt, _ = time.Parse(time.RFC3339Nano, occurredAt)
		events = append(events, &e)
	}
	return events, rows.Err()
}

// auditLogLine renders one audit event as a single log line.
//
// Every interpolated value is quoted with %q. Username in particular is
// unauthenticated input — a failed login records whatever was typed — so a
// value containing a newline would otherwise write additional, fully-formed
// audit lines into the process log, forging events that are indistinguishable
// from real ones to anyone reading journalctl or shipping the log elsewhere.
// %q escapes newlines, carriage returns, tabs and other control characters
// while leaving ordinary values readable and greppable.
func auditLogLine(event *domain.AuthEvent) string {
	if event.Detail != "" {
		return fmt.Sprintf("audit: %s user=%q detail=%q ip=%q",
			event.EventType, event.Username, event.Detail, event.IPAddress)
	}
	return fmt.Sprintf("audit: %s user=%q ip=%q",
		event.EventType, event.Username, event.IPAddress)
}
