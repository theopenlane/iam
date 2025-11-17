package tokens

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/theopenlane/utils/cache"
)

const (
	// MinAccessDuration is the minimum allowed access token duration
	MinAccessDuration = 5 * time.Minute
	// MaxAccessDuration is the maximum allowed access token duration
	MaxAccessDuration = 24 * time.Hour
	// MinRefreshDuration is the minimum allowed refresh token duration
	MinRefreshDuration = 15 * time.Minute
	// MaxRefreshDuration is the maximum allowed refresh token duration
	MaxRefreshDuration = 30 * 24 * time.Hour // 30 days
	// MinRefreshOverlap is the minimum allowed refresh overlap (most negative)
	MinRefreshOverlap = -1 * time.Hour
	// DefaultAPITokenEnvPrefix is the default environment variable prefix for API token key material
	DefaultAPITokenEnvPrefix = "IAM_API_TOKEN_KEY_" // nolint:gosec
	// MinAPITokenSecretLength is the minimum length for API token secrets in bytes
	MinAPITokenSecretLength = 32
	// DefaultAPITokenSecretSize is the fallback number of bytes used for a generated opaque token secret.
	DefaultAPITokenSecretSize = 32
	// DefaultAPITokenDelimiter is the fallback delimiter used when formatting opaque token values.
	DefaultAPITokenDelimiter = "."
	// DefaultAPITokenPrefix is the fallback prefix applied to opaque token values.
	DefaultAPITokenPrefix = ""
)

// Config defines the configuration settings for authentication tokens used in the server
type Config struct {
	// KID represents the Key ID used in the configuration.
	KID string `json:"kid" koanf:"kid" jsonschema:"required"`
	// Audience represents the target audience for the tokens.
	Audience string `json:"audience" koanf:"audience" jsonschema:"required" domain:"inherit" domainPrefix:"https://api"`
	// RefreshAudience represents the audience for refreshing tokens.
	RefreshAudience string `json:"refreshaudience" koanf:"refreshaudience" domain:"inherit" domainPrefix:"https://api"`
	// Issuer represents the issuer of the tokens
	Issuer string `json:"issuer" koanf:"issuer" jsonschema:"required" domain:"inherit" domainPrefix:"https://api"`
	// AccessDuration represents the duration of the access token is valid for
	AccessDuration time.Duration `json:"accessduration" koanf:"accessduration" default:"1h"`
	// RefreshDuration represents the duration of the refresh token is valid for
	RefreshDuration time.Duration `json:"refreshduration" koanf:"refreshduration" default:"2h"`
	// RefreshOverlap represents the overlap time for a refresh and access token
	RefreshOverlap time.Duration `json:"refreshoverlap" koanf:"refreshoverlap" default:"-15m" `
	// JWKSEndpoint represents the endpoint for the JSON Web Key Set
	JWKSEndpoint string `json:"jwksendpoint" koanf:"jwksendpoint" domain:"inherit" domainPrefix:"https://api" domainSuffix:"/.well-known/jwks.json"`
	// Keys represents the key pairs used for signing the tokens
	Keys map[string]string `json:"keys" koanf:"keys" jsonschema:"required"`
	// GenerateKeys is a boolean to determine if the keys should be generated
	GenerateKeys bool `json:"generatekeys" koanf:"generatekeys" default:"true"`
	// JWKSCacheTTL is the duration to cache JWKS responses
	JWKSCacheTTL time.Duration `json:"jwkscachettl" koanf:"jwkscachettl" default:"5m"`
	// Redis contains Redis configuration for token blacklist and JWT ID tracking
	Redis RedisConfig `json:"redis" koanf:"redis"`
	// APITokens contains configuration for opaque API token key management
	APITokens APITokenConfig `json:"apitokens" koanf:"apitokens"`
}

// RedisConfig contains Redis configuration for token security features
type RedisConfig struct {
	// Enabled turns on Redis-based blacklist features
	Enabled bool `json:"enabled" koanf:"enabled" default:"false"`
	// Config contains the Redis connection settings
	Config cache.Config `json:"config" koanf:"config"`
	// BlacklistPrefix is the Redis key prefix for blacklisted tokens
	BlacklistPrefix string `json:"blacklistprefix" koanf:"blacklistprefix" default:"token:blacklist:"`
}

// APITokenConfig contains configuration for opaque API token key management
type APITokenConfig struct {
	// Enabled turns on opaque API token support
	Enabled bool `json:"enabled" koanf:"enabled" default:"false"`
	// EnvPrefix is the environment variable prefix used to load key material
	EnvPrefix string `json:"envprefix" koanf:"envprefix" default:"IAM_API_TOKEN_KEY_"`
	// Keys describes statically configured API token keys keyed by version
	Keys map[string]APITokenKeyConfig `json:"keys" koanf:"keys" example:"v1"`
	// SecretSize controls the number of random bytes embedded in a generated opaque token secret
	SecretSize int `json:"secretsize" koanf:"secretsize" default:"32"`
	// Delimiter separates the token identifier and secret when formatting the opaque value
	Delimiter string `json:"delimiter" koanf:"delimiter" default:"." `
	// Prefix is prepended to the opaque token value before the identifier segment
	Prefix string `json:"prefix" koanf:"prefix" default:""`
}

// APITokenKeyConfig defines the configuration attributes for an API token key
type APITokenKeyConfig struct {
	// Secret represents the symmetric key material used for hashing
	Secret string `json:"secret" koanf:"secret" sensitive:"true"`
	// Status indicates the lifecycle state of the key - active, deprecated, or revoked
	Status string `json:"status" koanf:"status" default:"active"`
}

// Validate checks that the Config has valid token duration settings
func (c *Config) Validate() error {
	// Validate required fields
	if c.Audience == "" {
		return ErrAudienceRequired
	}

	if c.Issuer == "" {
		return ErrIssuerRequired
	}

	// Validate access duration
	if c.AccessDuration <= 0 || c.AccessDuration < MinAccessDuration || c.AccessDuration > MaxAccessDuration {
		return fmt.Errorf("%w: got %v, must be between %v and %v",
			ErrAccessDurationInvalid, c.AccessDuration, MinAccessDuration, MaxAccessDuration)
	}

	// Validate refresh duration
	if c.RefreshDuration <= 0 || c.RefreshDuration < MinRefreshDuration || c.RefreshDuration > MaxRefreshDuration {
		return fmt.Errorf("%w: got %v, must be between %v and %v",
			ErrRefreshDurationInvalid, c.RefreshDuration, MinRefreshDuration, MaxRefreshDuration)
	}

	// Validate refresh overlap is negative
	if c.RefreshOverlap >= 0 {
		return fmt.Errorf("%w: got %v, must be negative", ErrRefreshOverlapInvalid, c.RefreshOverlap)
	}

	// Validate refresh overlap is not too large (more negative than access duration)
	if c.RefreshOverlap < MinRefreshOverlap {
		return fmt.Errorf("%w: got %v, must be greater than %v",
			ErrRefreshOverlapInvalid, c.RefreshOverlap, MinRefreshOverlap)
	}

	// Validate refresh duration is longer than access duration
	if c.RefreshDuration <= c.AccessDuration {
		return fmt.Errorf("%w: refresh duration %v must be greater than access duration %v",
			ErrRefreshDurationTooShort, c.RefreshDuration, c.AccessDuration)
	}

	// Validate refresh overlap makes sense with access duration
	if -c.RefreshOverlap >= c.AccessDuration {
		return fmt.Errorf("%w: overlap %v is too large for access duration %v",
			ErrRefreshOverlapInvalid, c.RefreshOverlap, c.AccessDuration)
	}

	// Validate API tokens configuration
	if c.APITokens.Enabled {
		if err := c.APITokens.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate checks that the APITokenConfig has valid settings
func (a *APITokenConfig) Validate() error {
	// Ensure either static keys or env prefix is configured
	if len(a.Keys) == 0 && a.EnvPrefix == "" {
		return ErrAPITokenEnvPrefixRequired
	}

	cfg := a.cloneWithDefaults()

	if cfg.SecretSize <= 0 {
		return ErrAPITokenSecretSizeInvalid
	}

	if cfg.Delimiter == "" {
		return ErrAPITokenDelimiterInvalid
	}

	// If we have static keys, validate them
	if len(a.Keys) > 0 {
		activeCount := 0

		for version, keyConfig := range a.Keys {
			if err := keyConfig.Validate(); err != nil {
				return fmt.Errorf("key %s: %w", version, err)
			}

			if keyConfig.Status == string(KeyStatusActive) {
				activeCount++
			}
		}

		// Ensure exactly one active key
		if activeCount == 0 {
			return ErrAPITokenNoActive
		}

		if activeCount > 1 {
			return fmt.Errorf("%w: found %d active keys", ErrAPITokenMultipleActive, activeCount)
		}
	}

	return nil
}

// Validate checks that the APITokenKeyConfig has valid settings
func (k *APITokenKeyConfig) Validate() error {
	// Validate status
	switch k.Status {
	case string(KeyStatusActive), string(KeyStatusDeprecated), string(KeyStatusRevoked):
		// valid status
	default:
		return fmt.Errorf("%w: got %q", ErrAPITokenStatusInvalid, k.Status)
	}

	// Only validate secret if it's provided (may be loaded from env)
	if k.Secret != "" {
		// Try to decode as base64 first
		decoded, err := base64.StdEncoding.DecodeString(k.Secret)
		if err != nil {
			// Not base64, treat as raw string
			decoded = []byte(k.Secret)
		}

		// Validate minimum length
		if len(decoded) < MinAPITokenSecretLength {
			return fmt.Errorf("%w: got %d bytes, need at least %d",
				ErrAPITokenSecretTooShort, len(decoded), MinAPITokenSecretLength)
		}
	}

	return nil
}

// cloneWithDefaults returns a copy of the APITokenConfig with default values applied
func (a APITokenConfig) cloneWithDefaults() APITokenConfig {
	cfg := a

	if cfg.SecretSize == 0 {
		cfg.SecretSize = DefaultAPITokenSecretSize
	}

	if cfg.Delimiter == "" {
		cfg.Delimiter = DefaultAPITokenDelimiter
	}

	if cfg.Prefix == "" {
		cfg.Prefix = DefaultAPITokenPrefix
	}

	return cfg
}
