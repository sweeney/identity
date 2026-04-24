package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/sweeney/identity/internal/domain"
)

// MaxConfigDocumentBytes caps the size of a stored namespace document. The
// limit applies after JSON re-encoding so a tidy 63KB document with
// insignificant whitespace will not be rejected for 65KB of spaces.
const MaxConfigDocumentBytes = 64 * 1024

// configNameRE defines the namespace name grammar: lowercase letters,
// digits, underscore, hyphen — 1..64 characters. Kept strict so names map
// cleanly to URL segments and filesystems.
var configNameRE = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// Caller describes the authenticated principal making a config request.
// Kept small and auth-agnostic so the service has no dependency on JWT
// specifics.
type Caller struct {
	Sub  string // JWT sub claim of the user
	Role string // "admin" or "user"
}

// ConfigService is the business logic layer for the config service. It
// enforces per-namespace role ACLs, validates names / documents, stamps
// audit metadata (updated_by / updated_at), and fires a backup trigger on
// successful mutations.
type ConfigService struct {
	repo   domain.ConfigRepository
	backup domain.BackupService
	now    func() time.Time
}

// NewConfigService constructs a ConfigService.
func NewConfigService(repo domain.ConfigRepository, backup domain.BackupService) *ConfigService {
	return &ConfigService{
		repo:   repo,
		backup: backup,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// ListVisible returns summaries of namespaces the caller is allowed to read.
func (s *ConfigService) ListVisible(caller Caller) ([]domain.ConfigNamespaceSummary, error) {
	all, err := s.repo.List()
	if err != nil {
		return nil, err
	}
	visible := all[:0]
	for _, ns := range all {
		if roleAllows(ns.ReadRole, caller.Role) {
			visible = append(visible, ns)
		}
	}
	return visible, nil
}

// Get returns the full namespace if caller has read access. Returns
// ErrConfigNamespaceNotFound both when the namespace is missing and when
// the caller lacks the read role, so namespace existence is not leaked.
func (s *ConfigService) Get(caller Caller, name string) (*domain.ConfigNamespace, error) {
	if !configNameRE.MatchString(name) {
		return nil, ErrConfigInvalidName
	}
	ns, err := s.repo.Get(name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrConfigNamespaceNotFound
		}
		return nil, err
	}
	if !roleAllows(ns.ReadRole, caller.Role) {
		return nil, ErrConfigNamespaceNotFound
	}
	return ns, nil
}

// CreateNamespaceInput carries all fields required to create a new namespace.
type CreateNamespaceInput struct {
	Name      string
	ReadRole  string
	WriteRole string
	Document  []byte // JSON object; pass []byte("{}") for an empty doc
}

// CreateNamespace creates a new namespace. Restricted to admin callers.
func (s *ConfigService) CreateNamespace(caller Caller, in CreateNamespaceInput) (*domain.ConfigNamespace, error) {
	if caller.Role != domain.ConfigRoleAdmin {
		return nil, ErrConfigForbidden
	}
	if !configNameRE.MatchString(in.Name) {
		return nil, ErrConfigInvalidName
	}
	if !domain.IsValidConfigRole(in.ReadRole) || !domain.IsValidConfigRole(in.WriteRole) {
		return nil, ErrConfigInvalidRole
	}
	normalizedDoc, err := validateDocument(in.Document)
	if err != nil {
		return nil, err
	}

	now := s.now()
	ns := &domain.ConfigNamespace{
		Name:      in.Name,
		ReadRole:  in.ReadRole,
		WriteRole: in.WriteRole,
		Document:  normalizedDoc,
		UpdatedAt: now,
		UpdatedBy: caller.Sub,
		CreatedAt: now,
	}
	if err := s.repo.Create(ns); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, ErrConfigNamespaceExists
		}
		return nil, err
	}

	s.fireBackup()
	return ns, nil
}

// PutDocument replaces the document for an existing namespace. Requires
// the caller's role to match the namespace's write_role. A byte-identical
// re-put is a no-op — it updates no rows and does not fire a backup.
// Returns (changed, error). When changed is false, the stored document
// matched the input and no write occurred.
func (s *ConfigService) PutDocument(caller Caller, name string, document []byte) (bool, error) {
	if !configNameRE.MatchString(name) {
		return false, ErrConfigInvalidName
	}
	normalizedDoc, err := validateDocument(document)
	if err != nil {
		return false, err
	}

	existing, err := s.repo.Get(name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, ErrConfigNamespaceNotFound
		}
		return false, err
	}
	if !roleAllows(existing.WriteRole, caller.Role) {
		// No-existence leak: 404-style for readers, but writers who can
		// read get ErrConfigForbidden. We expose the ns when the caller
		// can read it (to avoid "invisible writes"); otherwise pretend it
		// does not exist.
		if !roleAllows(existing.ReadRole, caller.Role) {
			return false, ErrConfigNamespaceNotFound
		}
		return false, ErrConfigForbidden
	}

	if bytes.Equal(existing.Document, normalizedDoc) {
		return false, nil
	}

	if err := s.repo.UpdateDocument(name, normalizedDoc, caller.Sub, s.now()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, ErrConfigNamespaceNotFound
		}
		return false, err
	}
	s.fireBackup()
	return true, nil
}

// UpdateACL changes a namespace's read/write roles. Admin-only.
func (s *ConfigService) UpdateACL(caller Caller, name, readRole, writeRole string) error {
	if caller.Role != domain.ConfigRoleAdmin {
		return ErrConfigForbidden
	}
	if !configNameRE.MatchString(name) {
		return ErrConfigInvalidName
	}
	if !domain.IsValidConfigRole(readRole) || !domain.IsValidConfigRole(writeRole) {
		return ErrConfigInvalidRole
	}
	if err := s.repo.UpdateACL(name, readRole, writeRole, s.now()); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrConfigNamespaceNotFound
		}
		return err
	}
	s.fireBackup()
	return nil
}

// Delete removes a namespace. Admin-only.
func (s *ConfigService) Delete(caller Caller, name string) error {
	if caller.Role != domain.ConfigRoleAdmin {
		return ErrConfigForbidden
	}
	if !configNameRE.MatchString(name) {
		return ErrConfigInvalidName
	}
	if err := s.repo.Delete(name); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return ErrConfigNamespaceNotFound
		}
		return err
	}
	s.fireBackup()
	return nil
}

// fireBackup triggers an async R2 upload if a backup service is wired in.
// The call is non-blocking; failures are logged by the Manager, not
// surfaced to the user.
func (s *ConfigService) fireBackup() {
	if s.backup != nil {
		s.backup.TriggerAsync()
	}
}

// validateDocument verifies the input is a non-empty JSON object and
// returns a normalized (compact) serialization used for storage. Returns
// ErrConfigInvalidDocument if the input is not an object and
// ErrConfigDocumentTooLarge if the normalized bytes exceed the limit.
func validateDocument(doc []byte) ([]byte, error) {
	if len(doc) == 0 {
		return nil, ErrConfigInvalidDocument
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields() // no effect for map target but preserves strictness posture
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigInvalidDocument, err)
	}
	if dec.More() {
		return nil, ErrConfigInvalidDocument
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigInvalidDocument, err)
	}
	if buf.Len() > MaxConfigDocumentBytes {
		return nil, ErrConfigDocumentTooLarge
	}
	return buf.Bytes(), nil
}

// roleAllows reports whether a token holder with callerRole satisfies the
// namespace's required role. Admin satisfies any role requirement; user
// only satisfies "user".
func roleAllows(required, callerRole string) bool {
	if callerRole == domain.ConfigRoleAdmin {
		return true
	}
	if required == domain.ConfigRoleUser && callerRole == domain.ConfigRoleUser {
		return true
	}
	return false
}
