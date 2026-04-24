package service

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/sweeney/identity/internal/domain"
)

// userCodeCharset is the RFC 8628 §6.1 recommended alphabet minus easily
// confused characters (0/O, 1/I/l). 32 characters → 5 bits per symbol.
const userCodeCharset = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// GrantTypeDeviceCode is re-exported for handler convenience.
const GrantTypeDeviceCode = domain.GrantTypeDeviceCode

// DeviceAuthorizationResult is returned to the device on /oauth/device_authorization
// and /oauth/device/claim.
type DeviceAuthorizationResult struct {
	DeviceCode              string // raw, show to device exactly once
	UserCode                string // XXXX-XXXX, user types on verification page (standard flow)
	ClaimCode               string // empty except for claim flow — echoed back so device can show sticker URL
	VerificationURI         string
	VerificationURIComplete string // verification_uri with the user_code pre-filled
	ExpiresIn               int    // seconds
	Interval                int    // minimum polling interval in seconds
}

// DeviceApprovalView is what the verification page renders before the user approves.
type DeviceApprovalView struct {
	Authorization *domain.DeviceAuthorization
	Client        *domain.OAuthClient
	ClaimCode     *domain.ClaimCode // non-nil only for claim-code sessions
}

// ClaimCodeResult is returned when an admin generates a new claim code.
// The raw code is only available at creation time.
type ClaimCodeResult struct {
	ID       string
	RawCode  string
	Label    string
	ClientID string
}

// DeviceFlowConfig is the runtime configuration for DeviceFlowService.
type DeviceFlowConfig struct {
	// DeviceCodeTTL is how long a device_code / user_code remains valid. RFC 8628
	// recommends 600s (10 min).
	DeviceCodeTTL time.Duration

	// PollInterval is the minimum seconds between polls the device should respect.
	// RFC 8628 recommends 5s.
	PollInterval int

	// VerificationURI is the absolute URL to print on device screens, e.g.
	// "https://id.example.com/device".
	VerificationURI string
}

// DeviceFlowService implements RFC 8628 Device Authorization Grant plus the
// claim-code variant for screenless devices. It wraps an AuthServicer for
// user-token issuance once a device is approved.
type DeviceFlowService struct {
	auth       AuthServicer
	clients    domain.OAuthClientRepository
	devices    domain.DeviceAuthorizationRepository
	claimCodes domain.ClaimCodeRepository
	audit      domain.AuditRepository
	cfg        DeviceFlowConfig
}

// NewDeviceFlowService constructs a DeviceFlowService.
func NewDeviceFlowService(
	auth AuthServicer,
	clients domain.OAuthClientRepository,
	devices domain.DeviceAuthorizationRepository,
	claimCodes domain.ClaimCodeRepository,
	audit domain.AuditRepository,
	cfg DeviceFlowConfig,
) *DeviceFlowService {
	if cfg.DeviceCodeTTL <= 0 {
		cfg.DeviceCodeTTL = 10 * time.Minute
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5
	}
	return &DeviceFlowService{
		auth:       auth,
		clients:    clients,
		devices:    devices,
		claimCodes: claimCodes,
		audit:      audit,
		cfg:        cfg,
	}
}

// IssueDeviceAuthorization handles POST /oauth/device_authorization. The device
// receives a device_code (polling secret) plus a user_code that the user types
// on the verification page.
func (s *DeviceFlowService) IssueDeviceAuthorization(clientID, scope, ip string) (*DeviceAuthorizationResult, error) {
	client, err := s.getClientForDeviceGrant(clientID)
	if err != nil {
		return nil, err
	}
	if err := validateScopeAgainstClient(client, scope); err != nil {
		return nil, err
	}
	session, err := s.issueSession(client, "", scope, ip)
	if err != nil {
		return nil, err
	}
	return session.result, nil
}

// ClaimDevice handles POST /oauth/device/claim. The device presents a
// pre-shared claim_code (printed on its sticker). If the claim code is already
// bound, the resulting session is auto-approved for the bound user.
func (s *DeviceFlowService) ClaimDevice(clientID, rawClaimCode, scope, ip string) (*DeviceAuthorizationResult, error) {
	client, err := s.getClientForDeviceGrant(clientID)
	if err != nil {
		return nil, err
	}
	if err := validateScopeAgainstClient(client, scope); err != nil {
		return nil, err
	}

	cc, err := s.claimCodes.GetByHash(HashToken(normalizeCode(rawClaimCode)))
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalidClaimCode
	}
	if err != nil {
		return nil, fmt.Errorf("lookup claim code: %w", err)
	}
	if cc.IsRevoked() {
		return nil, ErrClaimCodeRevoked
	}
	if cc.ClientID != client.ID {
		return nil, ErrInvalidClaimCode
	}

	session, err := s.issueSession(client, cc.ID, scope, ip)
	if err != nil {
		return nil, err
	}

	// If the claim code has already been bound to a user, the device session is
	// auto-approved — no user interaction needed on this boot.
	if cc.IsBound() {
		if err := s.devices.Approve(session.deviceID(), cc.BoundUserID, time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("auto-approve claimed session: %w", err)
		}
		s.record(&domain.AuthEvent{
			EventType: domain.EventDeviceAuthorizeApproved,
			UserID:    cc.BoundUserID,
			ClientID:  client.ID,
			IPAddress: ip,
			Detail:    "claim_code_id=" + cc.ID,
		})
	}

	session.result.ClaimCode = rawClaimCode
	return session.result, nil
}

// PollForToken handles POST /oauth/token with grant_type=device_code. It
// returns either tokens (on approval) or a domain-specific error the handler
// maps to the RFC 8628 response format.
func (s *DeviceFlowService) PollForToken(clientID, rawDeviceCode, ip string) (*LoginResult, error) {
	if clientID == "" || rawDeviceCode == "" {
		return nil, ErrInvalidDeviceCode
	}

	da, err := s.devices.GetByDeviceHash(HashToken(rawDeviceCode))
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalidDeviceCode
	}
	if err != nil {
		return nil, fmt.Errorf("lookup device authorization: %w", err)
	}

	if da.ClientID != clientID {
		return nil, ErrInvalidDeviceCode
	}

	now := time.Now().UTC()
	if now.After(da.ExpiresAt) {
		return nil, ErrDeviceCodeExpired
	}

	// Capture previous poll time before we overwrite it. The slow_down check
	// compares against the *previous* poll so every call moves the window
	// forward — a device that polls correctly after a slow_down will not be
	// stuck.
	prevPoll := da.LastPolledAt
	if err := s.devices.MarkPolled(da.ID, now); err != nil {
		return nil, fmt.Errorf("mark polled: %w", err)
	}
	if prevPoll != nil {
		minWait := time.Duration(da.PollInterval) * time.Second
		if now.Sub(*prevPoll) < (minWait - 500*time.Millisecond) {
			return nil, ErrDeviceSlowDown
		}
	}

	switch da.Status {
	case domain.DeviceStatusDenied:
		return nil, ErrDeviceAuthorizationDenied
	case domain.DeviceStatusPending:
		return nil, ErrDeviceAuthorizationPending
	case domain.DeviceStatusApproved:
		// fall through
	default:
		return nil, ErrInvalidDeviceCode
	}

	// Atomic single-consume. If a second poll sneaks in after approval and
	// before this call, only one wins.
	if err := s.devices.MarkConsumed(da.ID, now); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, ErrInvalidDeviceCode
		}
		return nil, fmt.Errorf("mark consumed: %w", err)
	}

	client, err := s.clients.GetByID(da.ClientID)
	audience := ""
	if err == nil {
		audience = client.Audience
	}

	result, err := s.auth.IssueTokensForUser(da.UserID, audience)
	if err != nil {
		return nil, err
	}

	s.record(&domain.AuthEvent{
		EventType: domain.EventDeviceTokenIssued,
		UserID:    da.UserID,
		ClientID:  da.ClientID,
		IPAddress: ip,
	})

	return result, nil
}

// LookupForVerification resolves a code entered on /oauth/device into a
// device-authorization session plus contextual metadata (client, claim code).
// The code may be either a user_code (standard flow) or a claim_code (sticker
// flow).
func (s *DeviceFlowService) LookupForVerification(rawCode string) (*DeviceApprovalView, error) {
	normalized := normalizeCode(rawCode)
	if normalized == "" {
		return nil, ErrInvalidUserCode
	}

	// Try user_code first (standard flow).
	da, err := s.devices.GetByUserCode(normalized)
	if err == nil {
		return s.buildApprovalView(da)
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("lookup by user_code: %w", err)
	}

	// Fall back to claim_code lookup.
	cc, err := s.claimCodes.GetByHash(HashToken(normalized))
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrInvalidUserCode
	}
	if err != nil {
		return nil, fmt.Errorf("lookup claim code: %w", err)
	}
	if cc.IsRevoked() {
		return nil, ErrClaimCodeRevoked
	}

	// Find the most recent pending session tied to this claim code, if any.
	// We do this via a user_code trick: claim-flow sessions are looked up by
	// claim_code_id, so we need a dedicated lookup. For now, the verification
	// page only works if there is an in-flight device session — this is the
	// common case (device boots, polls, user sees sticker, approves).
	client, err := s.clients.GetByID(cc.ClientID)
	if err != nil {
		return nil, fmt.Errorf("lookup client: %w", err)
	}

	return &DeviceApprovalView{
		Authorization: nil,
		Client:        client,
		ClaimCode:     cc,
	}, nil
}

// Approve marks the session identified by rawCode as approved for userID.
// rawCode may be a user_code (standard flow) or a claim_code (sticker flow).
// In the claim-code case, the claim code is bound to the user on first
// approval and all in-flight pending sessions for that claim are approved in
// one shot, so the device's next poll returns tokens.
func (s *DeviceFlowService) Approve(rawCode, userID, username, ip string) error {
	normalized := normalizeCode(rawCode)
	if normalized == "" {
		return ErrInvalidUserCode
	}

	// Standard flow: user_code lookup.
	if da, err := s.devices.GetByUserCode(normalized); err == nil {
		if time.Now().UTC().After(da.ExpiresAt) {
			return ErrDeviceCodeExpired
		}
		if da.Status != domain.DeviceStatusPending {
			return ErrInvalidUserCode
		}
		if err := s.devices.Approve(da.ID, userID, time.Now().UTC()); err != nil {
			return fmt.Errorf("approve: %w", err)
		}
		s.record(&domain.AuthEvent{
			EventType: domain.EventDeviceAuthorizeApproved,
			UserID:    userID,
			Username:  username,
			ClientID:  da.ClientID,
			IPAddress: ip,
		})
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return fmt.Errorf("lookup by user_code: %w", err)
	}

	// Claim-code flow.
	cc, err := s.claimCodes.GetByHash(HashToken(normalized))
	if errors.Is(err, domain.ErrNotFound) {
		return ErrInvalidUserCode
	}
	if err != nil {
		return fmt.Errorf("lookup claim code: %w", err)
	}
	if cc.IsRevoked() {
		return ErrClaimCodeRevoked
	}
	if cc.IsBound() && cc.BoundUserID != userID {
		// Already bound to someone else — approving as a different user would
		// silently hand their device to the wrong owner. Refuse.
		return ErrInvalidUserCode
	}

	now := time.Now().UTC()
	if !cc.IsBound() {
		if err := s.claimCodes.Bind(cc.ID, userID, now); err != nil {
			return fmt.Errorf("bind claim code: %w", err)
		}
		s.record(&domain.AuthEvent{
			EventType: domain.EventClaimCodeBound,
			UserID:    userID,
			Username:  username,
			ClientID:  cc.ClientID,
			IPAddress: ip,
			Detail:    "claim_code_id=" + cc.ID,
		})
	}

	// Approve all in-flight pending sessions tied to this claim code. The
	// device's ongoing poll will return tokens on its next attempt.
	pending, err := s.devices.ListPendingByClaimID(cc.ID)
	if err != nil {
		return fmt.Errorf("list pending sessions: %w", err)
	}
	for _, da := range pending {
		if err := s.devices.Approve(da.ID, userID, now); err != nil && !errors.Is(err, domain.ErrNotFound) {
			return fmt.Errorf("approve pending session: %w", err)
		}
		s.record(&domain.AuthEvent{
			EventType: domain.EventDeviceAuthorizeApproved,
			UserID:    userID,
			Username:  username,
			ClientID:  da.ClientID,
			IPAddress: ip,
			Detail:    "claim_code_id=" + cc.ID,
		})
	}
	return nil
}

// Deny marks a pending session as denied. The device's next poll will receive
// ErrDeviceAuthorizationDenied.
func (s *DeviceFlowService) Deny(rawCode, ip string) error {
	normalized := normalizeCode(rawCode)
	if normalized == "" {
		return ErrInvalidUserCode
	}

	da, err := s.devices.GetByUserCode(normalized)
	if errors.Is(err, domain.ErrNotFound) {
		return ErrInvalidUserCode
	}
	if err != nil {
		return fmt.Errorf("lookup by user_code: %w", err)
	}

	if err := s.devices.Deny(da.ID, time.Now().UTC()); err != nil {
		return fmt.Errorf("deny: %w", err)
	}
	s.record(&domain.AuthEvent{
		EventType: domain.EventDeviceAuthorizeDenied,
		ClientID:  da.ClientID,
		IPAddress: ip,
	})
	return nil
}

// CreateClaimCodes generates n claim codes for the given client. The raw codes
// are returned exactly once — only their hashes are persisted.
func (s *DeviceFlowService) CreateClaimCodes(clientID string, labels []string, ip string) ([]*ClaimCodeResult, error) {
	client, err := s.clients.GetByID(clientID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrUnknownClient
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	if !client.HasGrantType(GrantTypeDeviceCode) {
		return nil, ErrUnauthorizedClient
	}

	out := make([]*ClaimCodeResult, 0, len(labels))
	now := time.Now().UTC()
	for _, label := range labels {
		raw, err := generateClaimCode()
		if err != nil {
			return nil, fmt.Errorf("generate claim code: %w", err)
		}
		id := uuid.New().String()
		cc := &domain.ClaimCode{
			ID:        id,
			CodeHash:  HashToken(raw),
			ClientID:  client.ID,
			Label:     label,
			CreatedAt: now,
		}
		if err := s.claimCodes.Create(cc); err != nil {
			return nil, fmt.Errorf("create claim code: %w", err)
		}
		s.record(&domain.AuthEvent{
			EventType: domain.EventClaimCodeCreated,
			ClientID:  client.ID,
			IPAddress: ip,
			Detail:    "claim_code_id=" + id + " label=" + label,
		})
		out = append(out, &ClaimCodeResult{
			ID:       id,
			RawCode:  raw,
			Label:    label,
			ClientID: client.ID,
		})
	}
	return out, nil
}

// ListClaimCodes returns all claim codes for the given client.
func (s *DeviceFlowService) ListClaimCodes(clientID string) ([]*domain.ClaimCode, error) {
	return s.claimCodes.ListByClient(clientID)
}

// RevokeClaimCode marks a claim code as revoked. Device sessions associated
// with the claim code are NOT automatically expired — they will fail at their
// next poll if their approval status depends on the claim code binding.
func (s *DeviceFlowService) RevokeClaimCode(id, ip string) error {
	cc, err := s.claimCodes.GetByID(id)
	if errors.Is(err, domain.ErrNotFound) {
		return ErrInvalidClaimCode
	}
	if err != nil {
		return fmt.Errorf("get claim code: %w", err)
	}

	if err := s.claimCodes.Revoke(id, time.Now().UTC()); err != nil {
		return fmt.Errorf("revoke: %w", err)
	}
	s.record(&domain.AuthEvent{
		EventType: domain.EventClaimCodeRevoked,
		ClientID:  cc.ClientID,
		IPAddress: ip,
		Detail:    "claim_code_id=" + id,
	})
	return nil
}

// --- internal helpers ---

type sessionHandle struct {
	id     string
	result *DeviceAuthorizationResult
}

func (h *sessionHandle) deviceID() string { return h.id }

func (s *DeviceFlowService) getClientForDeviceGrant(clientID string) (*domain.OAuthClient, error) {
	client, err := s.clients.GetByID(clientID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, ErrUnknownClient
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	if !client.HasGrantType(GrantTypeDeviceCode) {
		return nil, ErrUnauthorizedClient
	}
	return client, nil
}

func validateScopeAgainstClient(client *domain.OAuthClient, scope string) error {
	if scope == "" {
		return nil
	}
	for _, requested := range strings.Fields(scope) {
		if !client.HasScope(requested) {
			return ErrInvalidScope
		}
	}
	return nil
}

func (s *DeviceFlowService) issueSession(client *domain.OAuthClient, claimCodeID, scope, ip string) (*sessionHandle, error) {
	rawDeviceCode, err := generateRawToken()
	if err != nil {
		return nil, fmt.Errorf("generate device code: %w", err)
	}

	userCode, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("generate user code: %w", err)
	}

	now := time.Now().UTC()
	da := &domain.DeviceAuthorization{
		ID:             uuid.New().String(),
		DeviceCodeHash: HashToken(rawDeviceCode),
		UserCode:       userCode,
		ClientID:       client.ID,
		ClaimCodeID:    claimCodeID,
		Scope:          scope,
		Status:         domain.DeviceStatusPending,
		IssuedAt:       now,
		ExpiresAt:      now.Add(s.cfg.DeviceCodeTTL),
		PollInterval:   s.cfg.PollInterval,
	}
	if err := s.devices.Create(da); err != nil {
		return nil, fmt.Errorf("create device authorization: %w", err)
	}

	s.record(&domain.AuthEvent{
		EventType: domain.EventDeviceAuthorizeIssued,
		ClientID:  client.ID,
		IPAddress: ip,
	})

	verificationURI := s.cfg.VerificationURI
	complete := ""
	if verificationURI != "" {
		complete = verificationURI + "?user_code=" + userCode
	}

	return &sessionHandle{
		id: da.ID,
		result: &DeviceAuthorizationResult{
			DeviceCode:              rawDeviceCode,
			UserCode:                userCode,
			VerificationURI:         verificationURI,
			VerificationURIComplete: complete,
			ExpiresIn:               int(s.cfg.DeviceCodeTTL.Seconds()),
			Interval:                s.cfg.PollInterval,
		},
	}, nil
}

func (s *DeviceFlowService) buildApprovalView(da *domain.DeviceAuthorization) (*DeviceApprovalView, error) {
	client, err := s.clients.GetByID(da.ClientID)
	if err != nil {
		return nil, fmt.Errorf("lookup client: %w", err)
	}

	view := &DeviceApprovalView{Authorization: da, Client: client}
	if da.ClaimCodeID != "" {
		if cc, err := s.claimCodes.GetByID(da.ClaimCodeID); err == nil {
			view.ClaimCode = cc
		}
	}
	return view, nil
}

func (s *DeviceFlowService) record(event *domain.AuthEvent) {
	if s.audit == nil {
		return
	}
	event.ID = uuid.New().String()
	event.OccurredAt = time.Now().UTC()
	_ = s.audit.Record(event)
}

// generateUserCode returns a user-visible 8-char code formatted XXXX-XXXX using
// the RFC 8628 recommended alphabet (no ambiguous characters).
func generateUserCode() (string, error) {
	return randomCodeGroups(2, 4)
}

// generateClaimCode returns a 12-char code formatted XXXX-XXXX-XXXX using the
// same alphabet. Longer because claim codes are printed once at manufacture
// and live forever on a sticker — they need meaningful entropy.
func generateClaimCode() (string, error) {
	return randomCodeGroups(3, 4)
}

func randomCodeGroups(groups, perGroup int) (string, error) {
	total := groups * perGroup
	buf := make([]byte, 0, total+groups-1)
	max := big.NewInt(int64(len(userCodeCharset)))
	for i := 0; i < groups; i++ {
		if i > 0 {
			buf = append(buf, '-')
		}
		for j := 0; j < perGroup; j++ {
			n, err := rand.Int(rand.Reader, max)
			if err != nil {
				return "", err
			}
			buf = append(buf, userCodeCharset[n.Int64()])
		}
	}
	return string(buf), nil
}

// normalizeCode uppercases and strips whitespace from a user-provided code.
// Dashes are preserved so ABCD-EFGH stays comparable to the stored form.
func normalizeCode(raw string) string {
	var b strings.Builder
	for _, r := range raw {
		switch {
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			continue
		case r >= 'a' && r <= 'z':
			b.WriteRune(r - 32)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
