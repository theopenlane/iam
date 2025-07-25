package tokens_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/tokens"
)

const (
	accessToken  = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxR1g2NDdTOFBDVkJDUEpIWEdKUjI2UE42IiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xIiwiYXVkIjpbImh0dHA6Ly8xMjcuMC4wLjEiXSwiZXhwIjoxNjgwNjE1MzMwLCJuYmYiOjE2ODA2MTE3MzAsImlhdCI6MTY4MDYxMTczMCwianRpIjoiMDFneDY0N3M4cGN2YmNwamh4Z2pzcG04N3AiLCJuYW1lIjoiSm9obiBEb2UiLCJlbWFpbCI6Impkb2VAZXhhbXBsZS5jb20iLCJvcmciOiIxMjMiLCJwcm9qZWN0IjoiYWJjIiwicGVybWlzc2lvbnMiOlsicmVhZDpkYXRhIiwid3JpdGU6ZGF0YSJdfQ.LLb6c2RdACJmoT3IFgJEwfu2_YJMcKgM2bF3ISF41A37gKTOkBaOe-UuTmjgZ7WEcuQ-cVkht0KI_4zqYYctB_WB9481XoNwff5VgFf3xrPdOYxS00YXQnl09RRqt6Fmca8nvd4mXfdO7uvpyNVuCIqNxBPXdSnRhreSoFB1GtFm42sBPAD7vF-MQUmU0c4PTsbiCfhR1_buH0NYEE1QFp3vYcgoiXOJHh9VStmRscqvLB12AQrcs26G9opdTCCORmvR2W3JLJ_hliHyp-d9lhXmCDFyiGkDEhTAUglqwBjqz5SO1UfAThWJO18PvZl4QPhb724oNT82VPh0DMDwfw" // nolint: gosec
	refreshToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjAxR1g2NDdTOFBDVkJDUEpIWEdKUjI2UE42IiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwOi8vMTI3LjAuMC4xIiwiYXVkIjpbImh0dHA6Ly8xMjcuMC4wLjEiLCJodHRwOi8vMTI3LjAuMC4xL3YxL3JlZnJlc2giXSwiZXhwIjoxNjgwNjE4OTMwLCJuYmYiOjE2ODA2MTQ0MzAsImlhdCI6MTY4MDYxMTczMCwianRpIjoiMDFneDY0N3M4cGN2YmNwamh4Z2pzcG04N3AifQ.CLHmtZwSPFCPoMBX06D_C3h3WuEonUbvbfWLvtmrMmIwnTwQ4hxsaRJo_a4qI-emp1HNg-yu_7c3VNwjkti-d0c7CAGApTaf5eRdGJ5HGUkI8RDHbbMFaOK86nAFnzdPJ2JLmGtLzvpF9eFXFllDhRiAB-2t0uKcOdN7cFghdwyWXIVJIJNjngF_WUFklmLKnqORtj_tA6UJ6NJnZln34eMGftAHbuH8x-xUiRePHnro4ydS43CKNOgRP8biMHiRR2broBz0apIt30TeQShaBSbmGx__LYdm7RKPJNVHAn_3h_PwwKQG567-Aqabg6TSmpwhXCk_RfUyQVGv2b997w"                                                                                                                 // nolint: gosec
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
		key, err := rsa.GenerateKey(rand.Reader, 2048)
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
