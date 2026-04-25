package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/sweeney/identity/internal/domain"
)

// MaxConfigDocumentBytes caps the size of a stored namespace document. The
// limit applies after JSON re-encoding so a tidy 63KB document with
// insignificant whitespace will not be rejected for 65KB of spaces.
const MaxConfigDocumentBytes = 64 * 1024

// MaxConfigDocumentDepth caps JSON nesting depth to prevent stack-exhaustion
// DOS via pathological payloads like `{"a":{"a":{...}}}`. A byte budget
// alone is not enough: 128KB of braces fits tens of thousands of nesting
// levels, which can crash the runtime or burn significant CPU on recovery.
// 64 is generous for any plausible config shape.
const MaxConfigDocumentDepth = 64

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
	// Copy into a fresh slice rather than aliasing `all`'s backing array —
	// so nothing downstream accidentally relies on the repo returning a
	// fresh slice on every call.
	visible := make([]domain.ConfigNamespaceSummary, 0, len(all))
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
//
// The role check is done against a tiny ACL-only projection first, so the
// "missing" and "forbidden" code paths perform the same work (fast PK
// lookup; no document read). Only after a successful role check do we
// fetch the full row.
func (s *ConfigService) Get(caller Caller, name string) (*domain.ConfigNamespace, error) {
	if !configNameRE.MatchString(name) {
		return nil, ErrConfigInvalidName
	}
	readRole, _, err := s.repo.GetACL(name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrConfigNamespaceNotFound
		}
		return nil, err
	}
	if !roleAllows(readRole, caller.Role) {
		return nil, ErrConfigNamespaceNotFound
	}
	ns, err := s.repo.Get(name)
	if err != nil {
		// TOCTOU: the namespace could have been deleted between GetACL and
		// Get. Translate to 404 as if it had never been there.
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrConfigNamespaceNotFound
		}
		return nil, err
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
	if !writersAreReaders(in.ReadRole, in.WriteRole) {
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

	// ACL-only projection first so the "forbidden" and "not found" paths
	// perform the same amount of work.
	readRole, writeRole, err := s.repo.GetACL(name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, ErrConfigNamespaceNotFound
		}
		return false, err
	}
	if !roleAllows(writeRole, caller.Role) {
		// Callers who can neither read nor write get 404 (no existence
		// leak). The ACL invariant (writers-are-readers) means anyone who
		// satisfies write_role also satisfies read_role, so "can write but
		// not read" is an unreachable state.
		if !roleAllows(readRole, caller.Role) {
			return false, ErrConfigNamespaceNotFound
		}
		return false, ErrConfigForbidden
	}

	// Caller is allowed — fetch the existing document for the byte-equal
	// no-op check. Safe vs. read-oracle: the ACL invariant guarantees a
	// writer can already read the document.
	existing, err := s.repo.Get(name)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return false, ErrConfigNamespaceNotFound
		}
		return false, err
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

// UpdateACL changes a namespace's read/write roles. Admin-only. The
// caller's Sub is recorded as updated_by so the audit trail for ACL
// changes reflects the admin who made them (not whoever last wrote the
// document body).
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
	if !writersAreReaders(readRole, writeRole) {
		return ErrConfigInvalidRole
	}
	if err := s.repo.UpdateACL(name, readRole, writeRole, caller.Sub, s.now()); err != nil {
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
// returns a normalized serialization used for storage. json.Unmarshal
// rejects trailing garbage and non-object inputs natively, so a single
// Unmarshal + Marshal pair is enough.
//
// NOTE: the wrapped error here contains raw json-decoder output that may
// quote fragments of the attacker-controlled input. It is suitable for
// logs only — callers MUST NOT echo err.Error() to clients. router.go's
// translateError maps this sentinel to a static message for that reason.
func validateDocument(doc []byte) ([]byte, error) {
	if len(doc) == 0 {
		return nil, ErrConfigInvalidDocument
	}
	if err := enforceJSONDepth(doc, MaxConfigDocumentDepth); err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doc, &raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigInvalidDocument, err)
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigInvalidDocument, err)
	}
	if len(out) > MaxConfigDocumentBytes {
		return nil, ErrConfigDocumentTooLarge
	}
	return out, nil
}

// enforceJSONDepth scans doc with a streaming decoder and rejects inputs
// that nest object/array delimiters beyond maxDepth. It runs before full
// Unmarshal so a pathological payload can never reach the recursive
// encoder/json parser that would blow the goroutine stack.
func enforceJSONDepth(doc []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	depth := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrConfigInvalidDocument, err)
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > maxDepth {
					return ErrConfigInvalidDocument
				}
			case '}', ']':
				depth--
			}
		}
	}
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

// writersAreReaders enforces the ACL invariant that every role which
// satisfies write_role must also satisfy read_role. Combined with
// roleAllows, this prevents a PUT with byte-equality comparison from
// becoming a read oracle for the stored document.
//
//	write_role=admin  → only admins can write; admins can read any role → always OK
//	write_role=user   → users can also write; users can read only when read_role=user
func writersAreReaders(readRole, writeRole string) bool {
	if writeRole == domain.ConfigRoleAdmin {
		return true
	}
	return readRole == domain.ConfigRoleUser
}
