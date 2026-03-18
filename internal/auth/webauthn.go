package auth

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/sweeney/identity/internal/domain"
)

// WebAuthnUser adapts a domain.User + credentials to satisfy the webauthn.User interface.
type WebAuthnUser struct {
	User        *domain.User
	Credentials []webauthn.Credential
}

var _ webauthn.User = (*WebAuthnUser)(nil)

func (u *WebAuthnUser) WebAuthnID() []byte                         { return []byte(u.User.ID) }
func (u *WebAuthnUser) WebAuthnName() string                       { return u.User.Username }
func (u *WebAuthnUser) WebAuthnDisplayName() string                { return u.User.DisplayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// DomainCredentialToWebAuthn converts a domain credential to a webauthn.Credential.
func DomainCredentialToWebAuthn(c *domain.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}

	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.UserPresent,
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
		Transport: transports,
	}
}

// DomainCredentialsToWebAuthn converts a slice of domain credentials to webauthn.Credentials.
func DomainCredentialsToWebAuthn(creds []*domain.WebAuthnCredential) []webauthn.Credential {
	result := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		result[i] = DomainCredentialToWebAuthn(c)
	}
	return result
}

// NewWebAuthn creates a configured webauthn.WebAuthn instance.
func NewWebAuthn(rpID, rpDisplayName string, rpOrigins []string) (*webauthn.WebAuthn, error) {
	return webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		},
	})
}
