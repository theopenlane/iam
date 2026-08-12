package tokens_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/tokens"
)

const (
	// mintIssuer is the issuer bound into minted tokens
	mintIssuer = "https://auth.example.com"
	// mintAudience is the platform audience configured on the manager
	mintAudience = "https://api.example.com"
	// mintFederationAudience is a per-operation audience override for federation exchanges
	mintFederationAudience = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider"
	// mintSubject is the subject bound into minted tokens
	mintSubject = "01JQZX9K8N7M6P5R4T3V2W1Y0Z"
	// mintRSAKeySize is the smallest RSA key size the signing key loader accepts
	mintRSAKeySize = 2048
)

// signedTokenManager builds a token manager signing with the supplied key
func signedTokenManager(t *testing.T, key crypto.Signer) *tokens.TokenManager {
	t.Helper()

	manager, err := tokens.NewWithKey(key, tokens.NewConfig(
		tokens.WithIssuer(mintIssuer),
		tokens.WithAudience(mintAudience),
	))
	require.NoError(t, err)

	return manager
}

// parseSignedToken verifies the token signature and returns its claims and parsed token
func parseSignedToken(t *testing.T, signed string, key crypto.Signer) (jwt.MapClaims, *jwt.Token) {
	t.Helper()

	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(signed, claims, func(*jwt.Token) (any, error) {
		return key.Public(), nil
	})
	require.NoError(t, err)
	require.True(t, token.Valid)

	return claims, token
}

// TestNewConfig verifies default stamping and option layering
func TestNewConfig(t *testing.T) {
	conf := tokens.NewConfig(
		tokens.WithIssuer(mintIssuer),
		tokens.WithAudience(mintAudience),
	)

	assert.Equal(t, mintIssuer, conf.Issuer)
	assert.Equal(t, mintAudience, conf.Audience)
	assert.Equal(t, tokens.DefaultAccessDuration, conf.AccessDuration)
	assert.Equal(t, tokens.DefaultRefreshDuration, conf.RefreshDuration)
	assert.Equal(t, tokens.DefaultRefreshOverlap, conf.RefreshOverlap)
	assert.Equal(t, tokens.DefaultJWKSCacheTTL, conf.JWKSCacheTTL)
	assert.True(t, conf.GenerateKeys)

	require.NoError(t, conf.Validate())
}

// TestCreateSignedToken verifies config-derived minting on the token manager
func TestCreateSignedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, mintRSAKeySize)
	require.NoError(t, err)

	manager := signedTokenManager(t, key)

	t.Run("mints a verifiable token from the derived config", func(t *testing.T) {
		signed, err := manager.CreateSignedToken(
			tokens.WithSubject(mintSubject),
			tokens.WithAudience(mintFederationAudience),
			tokens.WithAccessDuration(10*time.Minute),
			tokens.WithClaim("organization_id", mintSubject),
			tokens.WithRequiredAlgorithm(jwt.SigningMethodRS256.Alg()),
		)
		require.NoError(t, err)

		claims, token := parseSignedToken(t, signed, key)

		assert.Equal(t, jwt.SigningMethodRS256.Alg(), token.Method.Alg())
		assert.Equal(t, manager.CurrentKeyID(), token.Header["kid"])

		assert.Equal(t, mintIssuer, claims["iss"])
		assert.Equal(t, mintFederationAudience, claims["aud"])
		assert.Equal(t, mintSubject, claims["sub"])
		assert.Equal(t, mintSubject, claims["organization_id"])
		assert.NotEmpty(t, claims["jti"])

		expiry, err := claims.GetExpirationTime()
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(10*time.Minute), expiry.Time, time.Minute)

		issued, err := claims.GetIssuedAt()
		require.NoError(t, err)
		assert.False(t, issued.IsZero())

		notBefore, err := claims.GetNotBefore()
		require.NoError(t, err)
		assert.False(t, notBefore.IsZero())
	})

	t.Run("defaults to the configured audience and access duration", func(t *testing.T) {
		signed, err := manager.CreateSignedToken()
		require.NoError(t, err)

		claims, _ := parseSignedToken(t, signed, key)

		assert.Equal(t, mintAudience, claims["aud"])
		assert.NotContains(t, claims, "sub")

		expiry, err := claims.GetExpirationTime()
		require.NoError(t, err)
		assert.WithinDuration(t, time.Now().Add(tokens.DefaultAccessDuration), expiry.Time, time.Minute)
	})

	t.Run("registered claims always win over extra claims", func(t *testing.T) {
		signed, err := manager.CreateSignedToken(
			tokens.WithSubject(mintSubject),
			tokens.WithClaim("iss", "https://evil.example.com"),
			tokens.WithClaim("sub", "01EVIL0000000000000000000"),
			tokens.WithClaim("exp", 0),
		)
		require.NoError(t, err)

		claims, _ := parseSignedToken(t, signed, key)

		assert.Equal(t, mintIssuer, claims["iss"])
		assert.Equal(t, mintSubject, claims["sub"])
	})

	t.Run("per-operation claims never leak into later mints", func(t *testing.T) {
		_, err := manager.CreateSignedToken(tokens.WithClaim("organization_id", mintSubject))
		require.NoError(t, err)

		signed, err := manager.CreateSignedToken()
		require.NoError(t, err)

		claims, _ := parseSignedToken(t, signed, key)
		assert.NotContains(t, claims, "organization_id")
	})

	t.Run("refuses to sign when the required algorithm does not match", func(t *testing.T) {
		_, edKey, keyErr := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, keyErr)

		_, err := signedTokenManager(t, edKey).CreateSignedToken(
			tokens.WithRequiredAlgorithm(jwt.SigningMethodRS256.Alg()),
		)
		require.ErrorIs(t, err, tokens.ErrSigningAlgorithmMismatch)
	})
}
