package tokens

import (
	"errors"
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
)

var (
	// ErrAccessDurationInvalid is returned when the access duration is outside allowed bounds
	ErrAccessDurationInvalid = errors.New("access duration must be positive and between allowed bounds")
	// ErrRefreshDurationInvalid is returned when the refresh duration is outside allowed bounds
	ErrRefreshDurationInvalid = errors.New("refresh duration must be positive and between allowed bounds")
	// ErrRefreshOverlapInvalid is returned when the refresh overlap is not negative or too large
	ErrRefreshOverlapInvalid = errors.New("refresh overlap must be negative and less than access duration")
	// ErrRefreshDurationTooShort is returned when refresh duration is not longer than access duration
	ErrRefreshDurationTooShort = errors.New("refresh duration must be greater than access duration")
	// ErrAudienceRequired is returned when audience is not specified
	ErrAudienceRequired = errors.New("audience is required")
	// ErrIssuerRequired is returned when issuer is not specified
	ErrIssuerRequired = errors.New("issuer is required")
)

// Config defines the configuration settings for authentication tokens used in the server
type Config struct {
	// KID represents the Key ID used in the configuration.
	KID string `json:"kid" koanf:"kid" jsonschema:"required"`
	// Audience represents the target audience for the tokens.
	Audience string `json:"audience" koanf:"audience" jsonschema:"required" domain:"inherit" domainPrefix:"https://api"`
	// RefreshAudience represents the audience for refreshing tokens.
	RefreshAudience string `json:"refreshAudience" koanf:"refreshAudience" domain:"inherit" domainPrefix:"https://api"`
	// Issuer represents the issuer of the tokens
	Issuer string `json:"issuer" koanf:"issuer" jsonschema:"required" domain:"inherit" domainPrefix:"https://api"`
	// AccessDuration represents the duration of the access token is valid for
	AccessDuration time.Duration `json:"accessDuration" koanf:"accessDuration" default:"1h"`
	// RefreshDuration represents the duration of the refresh token is valid for
	RefreshDuration time.Duration `json:"refreshDuration" koanf:"refreshDuration" default:"2h"`
	// RefreshOverlap represents the overlap time for a refresh and access token
	RefreshOverlap time.Duration `json:"refreshOverlap" koanf:"refreshOverlap" default:"-15m" `
	// JWKSEndpoint represents the endpoint for the JSON Web Key Set
	JWKSEndpoint string `json:"jwksEndpoint" koanf:"jwksEndpoint" domain:"inherit" domainPrefix:"https://api" domainSuffix:"/.well-known/jwks.json"`
	// Keys represents the key pairs used for signing the tokens
	Keys map[string]string `json:"keys" koanf:"keys" jsonschema:"required"`
	// GenerateKeys is a boolean to determine if the keys should be generated
	GenerateKeys bool `json:"generateKeys" koanf:"generateKeys" default:"true"`
	// JWKSCacheTTL is the duration to cache JWKS responses
	JWKSCacheTTL time.Duration `json:"jwksCacheTTL" koanf:"jwksCacheTTL" default:"5m"`
	// Redis contains Redis configuration for token blacklist and JWT ID tracking
	Redis RedisConfig `json:"redis" koanf:"redis"`
}

// RedisConfig contains Redis configuration for token security features
type RedisConfig struct {
	// Enabled turns on Redis-based blacklist features
	Enabled bool `json:"enabled" koanf:"enabled" default:"false"`
	// Config contains the Redis connection settings
	Config cache.Config `json:"config" koanf:"config"`
	// BlacklistPrefix is the Redis key prefix for blacklisted tokens
	BlacklistPrefix string `json:"blacklistPrefix" koanf:"blacklistPrefix" default:"token:blacklist:"`
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

	return nil
}
