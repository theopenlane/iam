package tokens_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/tokens"
)

const (
	accessToken  = "eyJhbGciOiJFZERTQSIsImtpZCI6IjAxR1g2NDdTOFBDVkJDUEpIWEdKUjI2UE42IiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cDovLzEyNy4wLjAuMSJdLCJlbWFpbCI6Impkb2VAZXhhbXBsZS5jb20iLCJleHAiOjE2ODA2MTUzMzAsImlhdCI6MTY4MDYxMTczMCwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMSIsImp0aSI6IjAxZ3g2NDdzOHBjdmJjcGpoeGdqc3BtODdwIiwibmFtZSI6IkpvaG4gRG9lIiwibmJmIjoxNjgwNjExNzMwLCJvcmciOiIxMjMiLCJwZXJtaXNzaW9ucyI6WyJyZWFkOmRhdGEiLCJ3cml0ZTpkYXRhIl0sInByb2plY3QiOiJhYmMifQ.L11co-vnWfdmabTYpw8JLPKkAmho7cqbEnd9KqO6xlaoHolVSZ0PiWo_vd4909GScaWxG5wma5tlqTkIpe_PAw" // nolint: gosec
	refreshToken = "eyJhbGciOiJFZERTQSIsImtpZCI6IjAxR1g2NDdTOFBDVkJDUEpIWEdKUjI2UE42IiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cDovLzEyNy4wLjAuMSIsImh0dHA6Ly8xMjcuMC4wLjEvdjEvcmVmcmVzaCJdLCJleHAiOjE2ODA2MTg5MzAsImlhdCI6MTY4MDYxMTczMCwiaXNzIjoiaHR0cDovLzEyNy4wLjAuMSIsImp0aSI6IjAxZ3g2NDdzOHBjdmJjcGpoeGdqc3BtODdwIiwibmJmIjoxNjgwNjE0NDMwfQ.tMM6A_xlWwULGTvXN8YUUJ8BcJ5OsPC3L-u0I0u8I-3emckidiXm9OfZ0bHwIO0xgp_r6-ICnfyttu5FgmZrCw"                                                                                                                 // nolint: gosec
)

func TestParse(t *testing.T) {
	accessClaims, err := tokens.ParseUnverified(accessToken)
	assert.NoError(t, err, "could not parse access token")

	refreshClaims, err := tokens.ParseUnverified(refreshToken)
	assert.NoError(t, err, "could not parse refresh token")

	// We expect the claims and refresh tokens to have the same ID
	assert.Equal(t, accessClaims.ID, refreshClaims.ID, "access and refresh token had different IDs or the parse was unsuccessful")

	// Check that an error is returned when parsing a bad token
	_, err = tokens.ParseUnverified("notarealtoken")
	assert.Error(t, err, "should not be able to parse a bad token")
}

func TestExpiresAt(t *testing.T) {
	expiration, err := tokens.ExpiresAt(accessToken)
	assert.NoError(t, err, "could not parse access token")

	// Expect the time to be fetched correctly from the token
	expected := time.Date(2023, 4, 4, 13, 35, 30, 0, time.UTC)
	assert.True(t, expected.Equal(expiration))

	// Check that an error is returned when parsing a bad token
	_, err = tokens.ExpiresAt("notarealtoken")
	assert.Error(t, err, "should not be able to parse a bad token")
}

func TestNotBefore(t *testing.T) {
	expiration, err := tokens.NotBefore(refreshToken)
	assert.NoError(t, err, "could not parse access token")

	// Expect the time to be fetched correctly from the token
	expected := time.Date(2023, 4, 4, 13, 20, 30, 0, time.UTC)
	assert.True(t, expected.Equal(expiration))

	// Check that an error is returned when parsing a bad token
	_, err = tokens.NotBefore("notarealtoken")
	assert.Error(t, err, "should not be able to parse a bad token")
}

func TestIsExpired(t *testing.T) {
	t.Run("Expired Token", func(t *testing.T) {
		expired, err := tokens.IsExpired(accessToken)
		assert.NoError(t, err)
		assert.True(t, expired)
	})

	t.Run("Valid Token", func(t *testing.T) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)

		conf := tokens.Config{
			Audience:        "http://localhost:3000",
			Issuer:          "http://localhost:3001",
			AccessDuration:  time.Hour,
			RefreshDuration: 2 * time.Hour,
			RefreshOverlap:  -15 * time.Minute,
		}
		tm, err := tokens.NewWithKey(key, conf)
		assert.NoError(t, err)

		token, err := tm.CreateAccessToken(&tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}})
		assert.NoError(t, err)
		signed, err := tm.Sign(token)
		assert.NoError(t, err)

		isExpired, err := tokens.IsExpired(signed)
		assert.NoError(t, err)
		assert.False(t, isExpired)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		isExpired, err := tokens.IsExpired("notatoken")
		assert.Error(t, err)
		assert.True(t, isExpired)
	})
}
