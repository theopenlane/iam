package tokens_test

import (
	"os"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwk"

	"github.com/theopenlane/iam/tokens"
)

func (s *TokenTestSuite) TestJWKSValidator() {
	// This is a long running test, skip if in short mode
	if testing.Short() {
		s.T().Skip("skipping long running test in short mode")
	}

	// NOTE: this test requires the jwks.json fixture to use the same keys as the
	// testdata keys loaded from the PEM file fixtures.
	// Create access and refresh tokens to validate.
	require := s.Require()
	tm, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize token manager")

	claims := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "01H6PGFB4T34D4WWEXQMAGJNMK",
		},
		UserID: "Rusty Shackleford",
		OrgID:  "01H6PGFG71N0AFEVTK3NJB71T9",
	}

	atks, rtks, err := tm.CreateTokenPair(claims)
	require.NoError(err, "could not create token pair")
	time.Sleep(500 * time.Millisecond)

	jwksData, err := os.ReadFile("testdata/jwks.json")
	require.NoError(err, "could not read jwks file")

	jwks, err := jwk.Parse(jwksData)
	require.NoError(err, "could not parse jwks")

	validator := tokens.NewJWKSValidator(jwks, "http://localhost:3000", "http://localhost:3001")

	parsedClaims, err := validator.Verify(atks)
	require.NoError(err, "could not validate access token")
	require.Equal(claims, parsedClaims, "parsed claims not returned correctly")

	_, err = validator.Parse(rtks)
	require.NoError(err, "could not parse refresh token")
}
