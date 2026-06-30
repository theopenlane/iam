package tokens_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/tokens"
)

// revocationTestConfig returns a token manager config suitable for the revocation tests
func revocationTestConfig() tokens.Config {
	return tokens.Config{
		Audience:        "test-audience",
		Issuer:          "test-issuer",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}
}

func TestRevocationEnabled(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	conf := revocationTestConfig()

	t.Run("false with default no-op blacklist", func(t *testing.T) {
		tm, err := tokens.NewWithKey(key, conf)
		require.NoError(t, err)

		assert.False(t, tm.RevocationEnabled())
	})

	t.Run("true with a redis blacklist", func(t *testing.T) {
		mr, err := miniredis.Run()
		require.NoError(t, err)

		defer mr.Close()

		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		defer client.Close()

		tm, err := tokens.NewWithKey(key, conf)
		require.NoError(t, err)

		tm.WithBlacklist(tokens.NewRedisTokenBlacklist(client, "test:revocation"))

		assert.True(t, tm.RevocationEnabled())
	})
}

func TestRevocationMethodsAreNoisyWithoutBlacklist(t *testing.T) {
	ctx := context.Background()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tm, err := tokens.NewWithKey(key, revocationTestConfig())
	require.NoError(t, err)

	// mutations surface ErrRevocationNotConfigured rather than silently succeeding
	assert.ErrorIs(t, tm.RevokeToken(ctx, "jti-1", time.Hour), tokens.ErrRevocationNotConfigured)
	assert.ErrorIs(t, tm.RevokeTokenWithTTL(ctx, "jti-1", time.Hour), tokens.ErrRevocationNotConfigured)
	assert.ErrorIs(t, tm.RevokeImpersonationToken(ctx, "session-1", time.Hour), tokens.ErrRevocationNotConfigured)
	assert.ErrorIs(t, tm.SuspendUser(ctx, "user-1", time.Hour), tokens.ErrRevocationNotConfigured)
	assert.ErrorIs(t, tm.SuspendUserWithDuration(ctx, "user-1", time.Hour), tokens.ErrRevocationNotConfigured)

	// reads surface the error and report not-revoked so callers can tell the check was inoperative
	revoked, err := tm.IsTokenRevoked(ctx, "jti-1")
	assert.False(t, revoked)
	assert.ErrorIs(t, err, tokens.ErrRevocationNotConfigured)

	suspended, err := tm.IsUserSuspended(ctx, "user-1")
	assert.False(t, suspended)
	assert.ErrorIs(t, err, tokens.ErrRevocationNotConfigured)
}

// TestJWKSValidatorBlacklist proves the request-path JWKS validator honors revocation only when a
// blacklist is wired into it, which is the gap the WithBlacklist option closes
func TestJWKSValidatorBlacklist(t *testing.T) {
	ctx := context.Background()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	conf := revocationTestConfig()

	tm, err := tokens.NewWithKey(key, conf)
	require.NoError(t, err)

	blacklist := tokens.NewRedisTokenBlacklist(client, "test:jwks")
	tm.WithBlacklist(blacklist)

	keys, err := tm.Keys()
	require.NoError(t, err)

	// signTokenWithID signs a fresh access token and returns the signed string and its jwt id
	signToken := func() (string, string) {
		jwtToken, err := tm.CreateAccessToken(&tokens.Claims{UserID: "user-123", OrgID: "org-456"})
		require.NoError(t, err)

		signed, err := tm.Sign(jwtToken)
		require.NoError(t, err)

		claims, err := tokens.ParseUnverifiedTokenClaims(signed)
		require.NoError(t, err)

		return signed, claims.ID
	}

	t.Run("validator without a blacklist cannot honor revocation", func(t *testing.T) {
		validator := tokens.NewJWKSValidator(keys, conf.Audience, conf.Issuer)

		signed, jti := signToken()

		_, err := validator.VerifyWithContext(ctx, signed)
		require.NoError(t, err)

		// revoke the token directly on the shared store
		require.NoError(t, blacklist.Revoke(ctx, jti, 30*time.Minute))

		// without WithBlacklist the validator still accepts the revoked token
		_, err = validator.VerifyWithContext(ctx, signed)
		assert.NoError(t, err)
	})

	t.Run("validator with a blacklist rejects revoked tokens", func(t *testing.T) {
		validator := tokens.NewJWKSValidator(keys, conf.Audience, conf.Issuer).WithBlacklist(blacklist)

		signed, jti := signToken()

		_, err := validator.VerifyWithContext(ctx, signed)
		require.NoError(t, err)

		require.NoError(t, blacklist.Revoke(ctx, jti, 30*time.Minute))

		_, err = validator.VerifyWithContext(ctx, signed)
		assert.ErrorIs(t, err, tokens.ErrTokenInvalid)
	})
}
