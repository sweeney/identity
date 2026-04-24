package domain

import "time"

// Role names accepted by ConfigNamespace ACLs. They intentionally mirror the
// identity service's role constants so JWT claims can be compared directly.
const (
	ConfigRoleAdmin = "admin"
	ConfigRoleUser  = "user"
)

// ConfigNamespace is a named bucket of homelab configuration data. The entire
// namespace is stored as a single JSON document; per-namespace role ACLs
// govern read and write access. Callers who lack the read role receive 404
// rather than 403, so namespace existence is not leaked.
type ConfigNamespace struct {
	Name      string
	ReadRole  string
	WriteRole string
	Document  []byte // JSON object, stored verbatim
	UpdatedAt time.Time
	UpdatedBy string // JWT sub claim of the last writer
	CreatedAt time.Time
}

// ConfigNamespaceSummary is returned by List — no document body, so responses
// stay small even when documents are large.
type ConfigNamespaceSummary struct {
	Name      string
	ReadRole  string
	WriteRole string
	UpdatedAt time.Time
	CreatedAt time.Time
}

// ConfigRepository is the persistence contract for config namespaces.
// Implementations return ErrNotFound for missing namespaces and ErrConflict
// when a uniqueness constraint is violated (e.g. Create on an existing name).
type ConfigRepository interface {
	List() ([]ConfigNamespaceSummary, error)
	// GetACL returns only the ACL columns so the service can make a
	// role-check decision without reading the document body. The size
	// disparity between "row missing" (fast) and "row present with a 64KB
	// document" (slow) would otherwise be a timing-oracle for namespace
	// existence to callers who lack read access.
	GetACL(name string) (readRole, writeRole string, err error)
	Get(name string) (*ConfigNamespace, error)
	Create(ns *ConfigNamespace) error
	UpdateDocument(name string, document []byte, updatedBy string, at time.Time) error
	// UpdateACL stamps updatedBy so the audit trail for ACL changes is
	// distinguishable from document writes.
	UpdateACL(name, readRole, writeRole, updatedBy string, at time.Time) error
	Delete(name string) error
}

// IsValidConfigRole reports whether role is one of the accepted ACL roles.
func IsValidConfigRole(role string) bool {
	return role == ConfigRoleAdmin || role == ConfigRoleUser
}
