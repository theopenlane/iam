package tokens

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"
	"github.com/rs/zerolog/log"
	"github.com/theopenlane/utils/cache"
	"github.com/theopenlane/utils/ulids"
)

const DefaultRefreshAudience = "https://auth.theopenlane.io/v1/refresh"

var (
	nilID                = ulid.ULID{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ErrEmptySigningKeyID = errors.New("signing key identifier is empty")

	// Allowed signing algorithms for token verification
	allowedAlgorithms = []string{"EdDSA", "RS256", "RS384", "RS512"}
)

type loadedKey struct {
	kid     string
	ulid    ulid.ULID
	hasULID bool
}

// TokenManager handles the creation and verification of cryptographically signed JWT tokens.
// It wraps an Issuer for token creation and signing, and adds validation with blacklist
// and replay prevention capabilities.
//
// TokenManager provides backward compatibility while the Issuer interface provides a
// cleaner separation of concerns for new code.
type TokenManager struct {
	*Issuer
	validator
	blacklist       TokenBlacklist
	apiTokenKeyring *APITokenKeyring
	apiTokenEntropy io.Reader
}

// New creates a TokenManager with the specified keys which should be a mapping of key identifiers
// to filesystem paths containing PEM-encoded private keys. This input is specifically designed
// for the config environment variable so that keys can be loaded from k8s or vault secrets that
// are mounted as files on disk
func New(conf Config) (tm *TokenManager, err error) {
	issuer, err := NewIssuer(conf)
	if err != nil {
		return nil, err
	}

	tm = &TokenManager{
		Issuer: issuer,
		validator: validator{
			audience: conf.Audience,
			issuer:   conf.Issuer,
			keyFunc:  issuer.keyFunc,
		},
	}

	// default to in-memory no-op implementations
	tm.blacklist = NewNoOpTokenBlacklist()
	tm.validator.blacklist = tm.blacklist

	// Initialize Redis-backed features if enabled
	if conf.Redis.Enabled {
		redisClient := cache.New(conf.Redis.Config)

		// Initialize blacklist with Redis
		tm.blacklist = NewRedisTokenBlacklist(redisClient, conf.Redis.BlacklistPrefix)
		tm.validator.blacklist = tm.blacklist
	}

	if conf.APITokens.Enabled {
		keyring, err := loadAPITokenKeyringFromConfig(conf.APITokens)
		if err != nil {
			return nil, err
		}

		tm.WithAPITokenKeyring(keyring)
	}

	return tm, nil
}

// WithBlacklist sets the token blacklist for the TokenManager
func (tm *TokenManager) WithBlacklist(blacklist TokenBlacklist) *TokenManager {
	tm.blacklist = blacklist
	tm.validator.blacklist = blacklist

	return tm
}

// WithAPITokenKeyring configures the symmetric keyring used for opaque API tokens.
func (tm *TokenManager) WithAPITokenKeyring(keyring *APITokenKeyring) *TokenManager {
	tm.apiTokenKeyring = keyring

	return tm
}

func (tm *TokenManager) withAPITokenEntropySource(reader io.Reader) {
	tm.apiTokenEntropy = reader
}

// NewWithKey is a constructor function that creates a new instance of the TokenManager struct
// with a specified Ed25519 signing key. It takes in the signing key as a parameter and initializes the
// TokenManager with the provided key, along with other configuration settings from the TokenConfig
// struct. It returns the created TokenManager instance or an error if there was a problem
// initializing the TokenManager.
//
// [MKA] BREAKING CHANGE in the EdDSA migration requires callers to supply a crypto.Signer
func NewWithKey(key crypto.Signer, conf Config) (tm *TokenManager, err error) {
	issuer, err := NewIssuerWithKey(key, conf)
	if err != nil {
		return nil, err
	}

	tm = &TokenManager{
		Issuer: issuer,
		validator: validator{
			audience: conf.Audience,
			issuer:   conf.Issuer,
			keyFunc:  issuer.keyFunc,
		},
	}

	// default to in-memory no-op implementations
	tm.blacklist = NewNoOpTokenBlacklist()
	tm.validator.blacklist = tm.blacklist

	// Initialize Redis-backed features if enabled
	if conf.Redis.Enabled {
		redisClient := cache.New(conf.Redis.Config)

		// Initialize blacklist with Redis
		tm.blacklist = NewRedisTokenBlacklist(redisClient, conf.Redis.BlacklistPrefix)
		tm.validator.blacklist = tm.blacklist
	}

	if conf.APITokens.Enabled {
		keyring, err := loadAPITokenKeyringFromConfig(conf.APITokens)
		if err != nil {
			return nil, err
		}

		tm.WithAPITokenKeyring(keyring)
	}

	return tm, nil
}

const (
	// Default durations for different impersonation types - kept short for security
	supportImpersonationDuration = 30 * time.Minute // Support sessions should be very short-lived
	jobImpersonationDuration     = 2 * time.Hour    // Jobs get slightly longer but still limited
	adminImpersonationDuration   = 15 * time.Minute // Admin impersonation should be extremely short
	defaultImpersonationDuration = 15 * time.Minute // Conservative default for unknown types
)

// CreateImpersonationToken creates a JWT token for user impersonation
func (tm *TokenManager) CreateImpersonationToken(_ context.Context, opts CreateImpersonationTokenOptions) (string, error) {
	if opts.Duration == 0 {
		// Default duration based on impersonation type
		switch opts.Type {
		case "support":
			opts.Duration = supportImpersonationDuration
		case "job":
			opts.Duration = jobImpersonationDuration
		case "admin":
			opts.Duration = adminImpersonationDuration
		default:
			opts.Duration = defaultImpersonationDuration
		}
	}

	now := time.Now()
	sessionID := ulids.New().String()

	claims := &ImpersonationClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(opts.Duration)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    tm.conf.Issuer,
			Subject:   opts.TargetUserID,
			Audience:  jwt.ClaimStrings{tm.conf.Audience},
			ID:        sessionID,
		},
		UserID:            opts.TargetUserID,
		OrgID:             opts.OrganizationID,
		ImpersonatorID:    opts.ImpersonatorID,
		ImpersonatorEmail: opts.ImpersonatorEmail,
		Type:              opts.Type,
		Reason:            opts.Reason,
		SessionID:         sessionID,
		Scopes:            opts.Scopes,
		TargetUserEmail:   opts.TargetUserEmail,
		OriginalToken:     opts.OriginalToken,
	}

	token := jwt.NewWithClaims(tm.currentSigningMethod, claims)

	// Add key ID to header
	if tm.conf.KID != "" {
		token.Header["kid"] = tm.conf.KID
	}

	return tm.Sign(token)
}

// ValidateImpersonationToken validates and parses an impersonation token
func (tm *TokenManager) ValidateImpersonationToken(ctx context.Context, tokenString string) (*ImpersonationClaims, error) {
	var token *jwt.Token

	claims := &ImpersonationClaims{}

	// Parse with validation
	parser := jwt.NewParser(
		jwt.WithValidMethods(allowedAlgorithms),
		jwt.WithAudience(tm.conf.Audience),
		jwt.WithIssuer(tm.conf.Issuer),
	)

	token, err := parser.ParseWithClaims(tokenString, claims, tm.Issuer.keyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check if the token has been blacklisted
	if tm.blacklist != nil && claims.SessionID != "" {
		revoked, err := tm.blacklist.IsRevoked(ctx, claims.SessionID)

		if revoked {
			log.Warn().Str("session_id", claims.SessionID).Msg("impersonation token is revoked")
			return nil, ErrTokenInvalid
		}
		// swallow this error intentionally, we don't want to block validation if blacklist check fails - auth should still succeed
		if err != nil {
			log.Warn().Msgf("failed to check blacklist for session %s: %v", claims.SessionID, err)
		}
	}

	// Additional validation specific to impersonation
	if claims.Type == "" {
		return nil, ErrMissingImpersonationType
	}

	if claims.ImpersonatorID == "" {
		return nil, ErrMissingImpersonatorID
	}

	if claims.UserID == "" {
		return nil, ErrMissingTargetUserID
	}

	return claims, nil
}

// RevokeImpersonationToken revokes an impersonation token by adding it to the blacklist
func (tm *TokenManager) RevokeImpersonationToken(ctx context.Context, sessionID string, ttl time.Duration) error {
	if tm.blacklist == nil {
		// No blacklist configured, tokens cannot be revoked
		return nil
	}

	return tm.blacklist.Revoke(ctx, sessionID, ttl)
}

// RevokeToken revokes a JWT token by its ID
func (tm *TokenManager) RevokeToken(ctx context.Context, tokenID string, ttl time.Duration) error {
	if tm.blacklist == nil {
		// No blacklist configured, tokens cannot be revoked
		return nil
	}

	return tm.blacklist.Revoke(ctx, tokenID, ttl)
}

// SuspendUser suspends all tokens for a user
func (tm *TokenManager) SuspendUser(ctx context.Context, userID string, ttl time.Duration) error {
	if tm.blacklist == nil {
		// No blacklist configured, users cannot be suspended
		return nil
	}

	return tm.blacklist.RevokeAllForUser(ctx, userID, ttl)
}

// GetBlacklist returns the configured blacklist (for internal use)
func (tm *TokenManager) GetBlacklist() TokenBlacklist {
	return tm.blacklist
}

// IsUserSuspended checks if a user is currently suspended
func (tm *TokenManager) IsUserSuspended(ctx context.Context, userID string) (bool, error) {
	if tm.blacklist == nil {
		return false, nil
	}

	return tm.blacklist.IsUserRevoked(ctx, userID)
}

// GetUserSuspensionStatus returns detailed suspension information
type SuspensionStatus struct {
	UserID    string
	Suspended bool
	// Future: could add SuspendedAt, ExpiresAt, Reason if we store metadata
}

// GetUserSuspensionStatus gets detailed suspension information for a user
func (tm *TokenManager) GetUserSuspensionStatus(ctx context.Context, userID string) (*SuspensionStatus, error) {
	suspended, err := tm.IsUserSuspended(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &SuspensionStatus{
		UserID:    userID,
		Suspended: suspended,
	}, nil
}

// IsTokenRevoked checks if a specific token (by JWT ID) has been revoked
func (tm *TokenManager) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	if tm.blacklist == nil {
		return false, nil
	}

	return tm.blacklist.IsRevoked(ctx, tokenID)
}

// RevokeTokenWithTTL revokes a token with a specific TTL (alias for RevokeToken for clarity)
func (tm *TokenManager) RevokeTokenWithTTL(ctx context.Context, tokenID string, ttl time.Duration) error {
	return tm.RevokeToken(ctx, tokenID, ttl)
}

// SuspendUserWithDuration suspends a user for a specific duration (alias for SuspendUser for clarity)
func (tm *TokenManager) SuspendUserWithDuration(ctx context.Context, userID string, duration time.Duration) error {
	return tm.SuspendUser(ctx, userID, duration)
}

// CreateTokenPair returns signed access and refresh tokens for the specified claims in one step since usually you want both access and refresh tokens at the same time
func (tm *TokenManager) CreateTokenPair(claims *Claims) (accessToken, refreshToken string, err error) {
	var atk, rtk *jwt.Token

	if atk, err = tm.CreateAccessToken(claims); err != nil {
		return "", "", fmt.Errorf("could not create access token: %w", err)
	}

	if rtk, err = tm.CreateRefreshToken(atk); err != nil {
		return "", "", fmt.Errorf("could not create refresh token: %w", err)
	}

	if accessToken, err = tm.Sign(atk); err != nil {
		return "", "", fmt.Errorf("could not sign access token: %w", err)
	}

	if refreshToken, err = tm.Sign(rtk); err != nil {
		return "", "", fmt.Errorf("could not sign refresh token: %w", err)
	}

	return
}

// AddSigningKey registers a new signing key identified by the supplied ULID.
// [MKA] BREAKING CHANGE with edDSA – callers must now supply a crypto.Signer (ed25519)
func (tm *TokenManager) AddSigningKey(keyID ulid.ULID, key crypto.Signer) error {
	return tm.AddKey(keyID.String(), key)
}

// AddSigningKeyWithID registers a new signing key with an arbitrary string identifier.
func (tm *TokenManager) AddSigningKeyWithID(kid string, key crypto.Signer) error {
	return tm.AddKey(kid, key)
}

// Parse parses a token without validating claims (but does verify signature).
// This delegates to the Issuer's Parse method.
func (tm *TokenManager) Parse(tks string) (*Claims, error) {
	return tm.Issuer.Parse(tks)
}

// UseSigningKey sets the current signing key to the key specified by keyID.
// It returns ErrUnknownSigningKey if the key has not been registered.
func (tm *TokenManager) UseSigningKey(keyID ulid.ULID) error {
	return tm.UseSigningKeyID(keyID.String())
}

// RemoveSigningKey deletes the signing key identified by keyID. If the removed
// key is the currently active signing key the newest remaining key will become
// active. Removing a key ensures any tokens referencing it can no longer be
// validated.
func (tm *TokenManager) RemoveSigningKey(keyID ulid.ULID) {
	tm.RemoveSigningKeyByID(keyID.String())
}

// ParseUnverified parses a string of tokens and returns the claims and any error encountered
func ParseUnverified(tks string) (claims *jwt.RegisteredClaims, err error) {
	claims = &jwt.RegisteredClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	if _, _, err = parser.ParseUnverified(tks, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// ParseUnverifiedTokenClaims parses token claims from an access token
func ParseUnverifiedTokenClaims(tks string) (claims *Claims, err error) {
	claims = &Claims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	if _, _, err = parser.ParseUnverified(tks, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// ExpiresAt parses a JWT token and returns the expiration time if it exists
func ExpiresAt(tks string) (_ time.Time, err error) {
	var claims *jwt.RegisteredClaims

	if claims, err = ParseUnverified(tks); err != nil {
		return time.Time{}, err
	}

	return claims.ExpiresAt.Time, nil
}

// NotBefore parses a JWT token and returns the "NotBefore" time claim if it exists
func NotBefore(tks string) (_ time.Time, err error) {
	var claims *jwt.RegisteredClaims

	if claims, err = ParseUnverified(tks); err != nil {
		return time.Time{}, err
	}

	return claims.NotBefore.Time, nil
}

// IsExpired attempts to check if the provided token is expired
func IsExpired(tks string) (bool, error) {
	expiration, err := ExpiresAt(tks)
	if err != nil {
		return true, err
	}

	// check if token is expired
	if expiration.Before(time.Now()) {
		return true, nil
	}

	return false, nil
}

// ImpersonationClaims extends the standard JWT claims with impersonation-specific information
type ImpersonationClaims struct {
	jwt.RegisteredClaims
	// UserID is the user being impersonated
	UserID string `json:"user_id,omitempty"`
	// OrgID is the organization context
	OrgID string `json:"org,omitempty"`
	// ImpersonatorID is the user doing the impersonation
	ImpersonatorID string `json:"impersonator_id"`
	// ImpersonatorEmail is the email of the impersonator
	ImpersonatorEmail string `json:"impersonator_email"`
	// Type indicates the type of impersonation (support, job, admin)
	Type string `json:"type"`
	// Reason for the impersonation
	Reason string `json:"reason"`
	// SessionID uniquely identifies this impersonation session
	SessionID string `json:"session_id"`
	// Scopes defines what actions are allowed
	Scopes []string `json:"scopes"`
	// TargetUserEmail is the email of the user being impersonated
	TargetUserEmail string `json:"target_user_email"`
	// OriginalToken stores the original user's token for reference
	OriginalToken string `json:"original_token,omitempty"`
}

// CreateImpersonationTokenOptions contains options for creating impersonation tokens
type CreateImpersonationTokenOptions struct {
	ImpersonatorID    string
	ImpersonatorEmail string
	TargetUserID      string
	TargetUserEmail   string
	OrganizationID    string
	Type              string
	Reason            string
	Duration          time.Duration
	Scopes            []string
	OriginalToken     string
}

// ParseUserID returns the target user ID from impersonation claims
func (c ImpersonationClaims) ParseUserID() ulid.ULID {
	userID, err := ulid.Parse(c.UserID)
	if err != nil {
		return ulids.Null
	}

	return userID
}

// ParseOrgID returns the organization ID from impersonation claims
func (c ImpersonationClaims) ParseOrgID() ulid.ULID {
	orgID, err := ulid.Parse(c.OrgID)
	if err != nil {
		return ulids.Null
	}

	return orgID
}

// ParseImpersonatorID returns the impersonator user ID from claims
func (c ImpersonationClaims) ParseImpersonatorID() ulid.ULID {
	impersonatorID, err := ulid.Parse(c.ImpersonatorID)
	if err != nil {
		return ulids.Null
	}

	return impersonatorID
}

// HasScope checks if the impersonation token has a specific scope
func (c ImpersonationClaims) HasScope(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}

	return false
}

// GetSessionID returns the session ID for this impersonation
func (c ImpersonationClaims) GetSessionID() string {
	return c.SessionID
}

// IsJobImpersonation returns true if this is a job impersonation token
func (c ImpersonationClaims) IsJobImpersonation() bool {
	return c.Type == "job"
}

// IsSupportImpersonation returns true if this is a support impersonation token
func (c ImpersonationClaims) IsSupportImpersonation() bool {
	return c.Type == "support"
}

// IsAdminImpersonation returns true if this is an admin impersonation token
func (c ImpersonationClaims) IsAdminImpersonation() bool {
	return c.Type == "admin"
}
