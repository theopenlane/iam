package oauthserver

import (
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/theopenlane/iam/tokens"
)

// TokenKind identifies what an opaque OAuth token represents
type TokenKind string

const (
	// KindRequest is a pending authorization request awaiting the user's consent
	KindRequest TokenKind = "REQUEST"
	// KindCode is a single-use authorization code
	KindCode TokenKind = "CODE"
	// KindAccess is an access token presented as a bearer token
	KindAccess TokenKind = "ACCESS"
	// KindRefresh is a refresh token exchanged at the token endpoint
	KindRefresh TokenKind = "REFRESH"
)

const (
	// AccessTokenPrefix prefixes access tokens
	AccessTokenPrefix = "tolo_"
	// RefreshTokenPrefix prefixes refresh tokens
	RefreshTokenPrefix = "tolr_"
	// CodePrefix prefixes authorization codes
	CodePrefix = "tolc_"
	// RequestPrefix prefixes authorization requests
	RequestPrefix = "tolq_"
)

const (
	// AccessTokenTTL is how long an access token is valid
	AccessTokenTTL = time.Hour
	// RefreshTokenTTL is how long a refresh token is valid, refresh tokens rotate on use
	RefreshTokenTTL = 30 * 24 * time.Hour
	// CodeTTL is how long an authorization code is valid
	CodeTTL = 5 * time.Minute
	// RequestTTL is how long a user has to complete the consent screen
	RequestTTL = 15 * time.Minute
)

// prefixes maps each token kind to its prefix
var prefixes = map[TokenKind]string{
	KindRequest: RequestPrefix,
	KindCode:    CodePrefix,
	KindAccess:  AccessTokenPrefix,
	KindRefresh: RefreshTokenPrefix,
}

// Prefix returns the prefix of tokens of this kind
func (k TokenKind) Prefix() string {
	return prefixes[k]
}

// Valid reports whether the kind is known
func (k TokenKind) Valid() bool {
	_, ok := prefixes[k]

	return ok
}

// KindOf returns the kind of a raw token from its prefix, or "" if unrecognized
func KindOf(raw string) TokenKind {
	for kind, prefix := range prefixes {
		if strings.HasPrefix(raw, prefix) {
			return kind
		}
	}

	return ""
}

// IsAccessToken reports whether a bearer token is an OAuth access token
func IsAccessToken(raw string) bool {
	return KindOf(raw) == KindAccess
}

// Token is a newly issued token, Value goes to the client once and only Kind, ID, Hash and KeyVersion are stored
type Token struct {
	// Kind is what the token represents
	Kind TokenKind
	// ID identifies the token's stored record
	ID ulid.ULID
	// Value is the opaque token returned to the client
	Value string
	// Hash is the keyed digest to store
	Hash string
	// KeyVersion is the keyring version the hash was computed with, to store
	KeyVersion string
	// ExpiresAt is when the token stops being valid, from its kind's TTL
	ExpiresAt time.Time
}

// StoredToken is the record a service persisted for a token
type StoredToken struct {
	// ID is the stored token ID
	ID string
	// Kind is the stored token kind
	Kind TokenKind
	// Hash is the stored keyed digest
	Hash string
	// KeyVersion is the stored keyring version
	KeyVersion string
}

// TokenIssuer issues and verifies opaque OAuth tokens with an iam/tokens API token keyring
type TokenIssuer struct {
	// tm holds the API token keyring tokens are hashed with
	tm *tokens.TokenManager
}

// NewTokenIssuer returns an issuer backed by the token manager's API token keyring, failing if it has no active key
func NewTokenIssuer(tm *tokens.TokenManager) (*TokenIssuer, error) {
	if tm == nil {
		return nil, ErrKeyringRequired
	}

	if _, err := tm.GenerateAPIToken(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyringRequired, err)
	}

	return &TokenIssuer{tm: tm}, nil
}

// Issue returns a new token of the given kind
func (i *TokenIssuer) Issue(kind TokenKind) (*Token, error) {
	ttl, ok := ttls[kind]
	if !ok {
		return nil, fmt.Errorf("%w: unknown kind %q", ErrTokenInvalid, kind)
	}

	generated, err := i.tm.GenerateAPIToken(tokens.WithAPITokenPrefix(kind.Prefix()))
	if err != nil {
		return nil, err
	}

	return &Token{
		Kind:       kind,
		ID:         generated.TokenID,
		Value:      generated.Value,
		Hash:       generated.Hash,
		KeyVersion: generated.KeyVersion,
		ExpiresAt:  time.Now().Add(ttl),
	}, nil
}

// ttls maps each token kind to how long it is valid
var ttls = map[TokenKind]time.Duration{
	KindRequest: RequestTTL,
	KindCode:    CodeTTL,
	KindAccess:  AccessTokenTTL,
	KindRefresh: RefreshTokenTTL,
}

// Lookup returns the kind and ID to load a presented token's stored record by
func (i *TokenIssuer) Lookup(raw string) (TokenKind, ulid.ULID, error) {
	kind := KindOf(raw)
	if kind == "" {
		return "", ulid.ULID{}, ErrTokenInvalid
	}

	id, err := i.tm.ParseAPITokenID(raw, tokens.WithAPITokenPrefix(kind.Prefix()))
	if err != nil {
		return "", ulid.ULID{}, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	return kind, id, nil
}

// Verify checks a presented token against its stored record
func (i *TokenIssuer) Verify(raw string, stored StoredToken) error {
	kind := KindOf(raw)
	if kind == "" || kind != stored.Kind {
		return ErrTokenKindMismatch
	}

	storedID, err := ulid.ParseStrict(stored.ID)
	if err != nil {
		return fmt.Errorf("%w: stored id: %w", ErrTokenInvalid, err)
	}

	id, err := i.tm.VerifyAPIToken(raw, stored.Hash, stored.KeyVersion, tokens.WithAPITokenPrefix(kind.Prefix()))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}

	if id != storedID {
		return ErrTokenInvalid
	}

	return nil
}
