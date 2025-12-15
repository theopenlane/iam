package tokens_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/tokens"
)

const (
	audience = "http://localhost:3000"
	issuer   = "http://localhost:3001"
)

type TokenTestSuite struct {
	suite.Suite
	testdata    map[string]string
	conf        tokens.Config
	expiredConf tokens.Config
}

func (s *TokenTestSuite) SetupSuite() {
	// Create the keys map from the testdata directory to create new token managers.
	s.testdata = make(map[string]string)
	s.testdata["01GE6191AQTGMCJ9BN0QC3CCVG"] = "testdata/01GE6191AQTGMCJ9BN0QC3CCVG.pem"
	s.testdata["01GE62EXXR0X0561XD53RDFBQJ"] = "testdata/01GE62EXXR0X0561XD53RDFBQJ.pem"

	s.conf = tokens.Config{
		Keys:            s.testdata,
		Audience:        audience,
		Issuer:          issuer,
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	// Some tests require expired tokens to test expiration checking logic.
	s.expiredConf = tokens.Config{
		Keys:            s.testdata,
		Audience:        audience,
		Issuer:          issuer,
		AccessDuration:  -1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}
}

func (s *TokenTestSuite) TestCreateTokenPair() {
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
	require.NotEmpty(atks, "no access token returned")
	require.NotEmpty(rtks, "no refresh token returned")

	_, err = tm.Verify(atks)
	require.NoError(err, "could not parse or verify claims from *tokens.Claims")
	_, err = tm.Parse(rtks)
	require.NoError(err, "could not parse refresh token")
}

func (s *TokenTestSuite) TestTokenManager() {
	// This is a long running test, skip if in short mode
	if testing.Short() {
		s.T().Skip("skipping long running test in short mode")
	}

	require := s.Require()
	tm, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize token manager")

	keys, err := tm.Keys()
	require.NoError(err, "could not get jwks keys")
	require.Equal(2, keys.Len())
	require.Equal("01GE62EXXR0X0561XD53RDFBQJ", tm.CurrentKey().String())

	// Create an access token from simple claims
	creds := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "01H6PGFB4T34D4WWEXQMAGJNMK",
		},
		UserID: "Rusty Shackleford",
		OrgID:  "01H6PGFG71N0AFEVTK3NJB71T9",
	}

	accessToken, err := tm.CreateAccessToken(creds)
	require.NoError(err, "could not create access token from claims")
	require.IsType(&tokens.Claims{}, accessToken.Claims)

	time.Sleep(500 * time.Millisecond)

	now := time.Now()

	// Check access token claims
	ac := accessToken.Claims.(*tokens.Claims)
	require.NotZero(ac.ID)
	require.Equal(jwt.ClaimStrings{"http://localhost:3000"}, ac.Audience)
	require.Equal("http://localhost:3001", ac.Issuer)
	require.True(ac.IssuedAt.Before(now))
	require.True(ac.NotBefore.Before(now))
	require.True(ac.ExpiresAt.After(now))
	require.Equal(creds.Subject, ac.Subject)
	require.Equal(creds.UserID, ac.UserID)
	require.Equal(creds.OrgID, ac.OrgID)

	// Create a refresh token from the access token
	refreshToken, err := tm.CreateRefreshToken(accessToken)
	require.NoError(err, "could not create refresh token from access token")
	require.IsType(&tokens.Claims{}, refreshToken.Claims)

	// Check refresh token claims
	rc := refreshToken.Claims.(*tokens.Claims)
	require.Equal(ac.ID, rc.ID, "access and refresh tokens must have same jid")
	require.Equal(jwt.ClaimStrings{"http://localhost:3000", "http://localhost:3001/v1/refresh"}, rc.Audience)
	require.NotEqual(ac.Audience, rc.Audience, "identical access token and refresh token audience")
	require.Equal(ac.Issuer, rc.Issuer)
	require.True(rc.IssuedAt.Equal(ac.IssuedAt.Time))
	require.True(rc.NotBefore.After(now))
	require.True(rc.ExpiresAt.After(rc.NotBefore.Time))
	require.Equal(ac.Subject, rc.Subject)
	require.Empty(rc.UserID)
	require.Equal(ac.OrgID, rc.OrgID)

	// Verify relative nbf and exp claims of access and refresh tokens
	require.True(ac.IssuedAt.Equal(rc.IssuedAt.Time), "access and refresh tokens do not have same iss timestamp")
	require.Equal(45*time.Minute, rc.NotBefore.Sub(ac.IssuedAt.Time), "refresh token nbf is not 45 minutes after access token iss")
	require.Equal(15*time.Minute, ac.ExpiresAt.Sub(rc.NotBefore.Time), "refresh token active does not overlap active token active by 15 minutes")
	require.Equal(60*time.Minute, rc.ExpiresAt.Sub(ac.ExpiresAt.Time), "refresh token does not expire 1 hour after access token")

	// Sign the access token
	atks, err := tm.Sign(accessToken)
	require.NoError(err, "could not sign access token")

	// Sign the refresh token
	rtks, err := tm.Sign(refreshToken)
	require.NoError(err, "could not sign refresh token")
	require.NotEqual(atks, rtks, "identical access and refresh tokens")

	// Validate the access token
	_, err = tm.Verify(atks)
	require.NoError(err, "could not validate access token")

	// Validate the refresh token (should be invalid because of not before in the future)
	_, err = tm.Verify(rtks)
	require.Error(err, "refresh token is valid?")
}

func (s *TokenTestSuite) TestValidTokens() {
	require := s.Require()
	tm, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize token manager")

	// Default creds
	creds := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "01H6PGFB4T34D4WWEXQMAGJNMK",
		},
		UserID: "Rusty Shackleford",
		OrgID:  "01H6PGFG71N0AFEVTK3NJB71T9",
	}

	// TODO: add validation steps and test
	_, err = tm.CreateAccessToken(creds)
	require.NoError(err)
}

func (s *TokenTestSuite) TestCreateAccessTokenUsesCorrectDuration() {
	require := s.Require()

	conf := tokens.Config{
		Keys:                     s.testdata,
		Audience:                 audience,
		Issuer:                   issuer,
		AccessDuration:           1 * time.Hour,
		AssessmentAccessDuration: 2 * time.Hour,
		RefreshDuration:          3 * time.Hour,
		RefreshOverlap:           -15 * time.Minute,
	}

	tm, err := tokens.New(conf)
	require.NoError(err, "could not initialize token manager")

	regularSubject := "01H6PGFB4T34D4WWEXQMAGJNMK"
	regularCreds := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: regularSubject,
		},
	}

	regularToken, err := tm.CreateAccessToken(regularCreds)
	require.NoError(err, "could not create access token with regular subject")

	regularClaims := regularToken.Claims.(*tokens.Claims)
	regularDuration := regularClaims.ExpiresAt.Time.Sub(regularClaims.IssuedAt.Time)
	require.Equal(conf.AccessDuration, regularDuration,
		"regular subject token should use AccessDuration")

	anonSubject := "anon_questionnaire_01H6PGFB4T34D4WWEXQMAGJNMK"
	anonCreds := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: anonSubject,
		},
	}

	anonToken, err := tm.CreateAccessToken(anonCreds)
	require.NoError(err, "could not create access token with anonymous assessment subject")

	anonClaims := anonToken.Claims.(*tokens.Claims)
	anonDuration := anonClaims.ExpiresAt.Time.Sub(anonClaims.IssuedAt.Time)
	require.Equal(conf.AssessmentAccessDuration, anonDuration,
		"anonymous assessment subject token should use AssessmentAccessDuration")

	require.NotEqual(regularDuration, anonDuration,
		"tokens with different subjects should have different durations")
	require.NotEqual(regularClaims.ExpiresAt.Time, anonClaims.ExpiresAt.Time,
		"tokens with different subjects should have different expiration times")
}

func (s *TokenTestSuite) TestInvalidTokens() {
	// Create the token manager
	require := s.Require()
	tm, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize token manager")

	// Manually create a token to validate with the token manager
	now := time.Now()
	claims := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        ulids.New().String(),                           // id not validated
			Subject:   "01H6PGFB4T34D4WWEXQMAGJNMK",                   // correct subject
			Audience:  jwt.ClaimStrings{"http://foo.example.com"},     // wrong audience
			IssuedAt:  jwt.NewNumericDate(now.Add(-1 * time.Hour)),    // iat not validated
			NotBefore: jwt.NewNumericDate(now.Add(15 * time.Minute)),  // nbf is validated and is after now
			ExpiresAt: jwt.NewNumericDate(now.Add(-30 * time.Minute)), // exp is validated and is before now
		},
		UserID: "Rusty Shackleford",
		OrgID:  "01H6PGFG71N0AFEVTK3NJB71T9",
	}

	// Test validation signed with wrong kid
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = "01GE63H600NKHE7B8Y7MHW1VGV"
	_, badKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err, "could not generate bad ed25519 keys")
	tks, err := token.SignedString(badKey)
	require.NoError(err, "could not sign token with bad kid")

	_, err = tm.Verify(tks)
	require.EqualError(err, "token is unverifiable: error while executing keyfunc: unknown signing key")

	// Test validation signed with good kid but wrong key
	token.Header["kid"] = "01GE62EXXR0X0561XD53RDFBQJ"
	tks, err = token.SignedString(badKey)
	require.NoError(err, "could not sign token with bad keys and good kid")

	_, err = tm.Verify(tks)
	require.EqualError(err, "token signature is invalid: ed25519: verification error")

	// Test time-based validation: nbf
	tks, err = tm.Sign(token)
	require.NoError(err, "could not sign token with good keys")

	_, err = tm.Verify(tks)
	require.EqualError(err, "token has invalid claims: token is expired, token is not valid yet")

	// Test time-based validation: exp
	claims.NotBefore = jwt.NewNumericDate(now.Add(-1 * time.Hour))
	tks, err = tm.Sign(jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)) // nolint
	require.NoError(err, "could not sign token with good keys")

	// Test audience verification
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(1 * time.Hour))
	tks, err = tm.Sign(jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims))
	require.NoError(err, "could not sign token with good keys")

	_, err = tm.Verify(tks)
	require.EqualError(err, "token has invalid audience")

	// Token is finally valid
	claims.Audience = jwt.ClaimStrings{"http://localhost:3000"}
	claims.Issuer = "http://localhost:3001"
	tks, err = tm.Sign(jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims))
	require.NoError(err, "could not sign token with good keys")
	_, err = tm.Verify(tks)
	require.NoError(err, "claims are still not valid")
}

// Test that a token signed with an old cert can still be verified - this also tests that the correct signing key is required.
func (s *TokenTestSuite) TestKeyRotation() {
	require := s.Require()

	// Create the "old token manager"
	conf := tokens.Config{
		Keys: map[string]string{
			"01GE6191AQTGMCJ9BN0QC3CCVG": "testdata/01GE6191AQTGMCJ9BN0QC3CCVG.pem",
		},
		Audience:        audience,
		Issuer:          issuer,
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	oldTM, err := tokens.New(conf)
	require.NoError(err, "could not initialize old token manager")

	// Create the "new" token manager with the new key
	newTM, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize new token manager")

	// Create a valid token with the "old token manager"
	token, err := oldTM.CreateAccessToken(&tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "01H6PGFB4T34D4WWEXQMAGJNMK",
		},
		UserID: "Rusty Shackleford",
		OrgID:  "01H6PGFG71N0AFEVTK3NJB71T9",
	})
	require.NoError(err)

	tks, err := oldTM.Sign(token)
	require.NoError(err)

	// Validate token with "new token manager"
	_, err = newTM.Verify(tks)
	require.NoError(err)

	// A token created by the "new token manager" should not be verified by the old one
	tks, err = newTM.Sign(token)
	require.NoError(err)

	_, err = oldTM.Verify(tks)
	require.Error(err)
}

// Test signing tokens with multiple keys and rotating the active signing key.
// Tokens created with previous keys should continue to verify successfully.
func (s *TokenTestSuite) TestSigningKeyManagement() {
	require := s.Require()

	// start token manager that has a single key
	_, key1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err, "could not generate ed25519 key")

	conf := tokens.Config{
		Audience:        audience,
		Issuer:          issuer,
		AccessDuration:  time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key1, conf)
	require.NoError(err, "could not initialize token manager with key1")

	kid1 := tm.CurrentKey()

	// Sign a token with the first key
	tok1, err := tm.CreateAccessToken(&tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}})
	require.NoError(err, "could not create access token with key1")
	sig1, err := tm.Sign(tok1)
	require.NoError(err, "could not sign token with key1")

	// Generate a second key with a ULID that is newer so AddSigningKey rotates to it
	_, key2, err := ed25519.GenerateKey(rand.Reader) //nolint:gosec
	require.NoError(err, "could not generate ed25519 key")

	kid2 := ulids.FromTime(time.Now().Add(time.Second))
	require.NoError(tm.AddSigningKey(kid2, key2))

	require.Equal(kid2, tm.CurrentKey(), "latest key should be active")
	require.Equal(kid2.String(), tm.CurrentKeyID())

	// JWKS should include both keys.
	jwks, err := tm.Keys()
	require.NoError(err)
	require.Equal(2, jwks.Len())

	// Sign another token with the new key.
	tok2, err := tm.CreateAccessToken(&tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}})
	require.NoError(err)
	sig2, err := tm.Sign(tok2)
	require.NoError(err)

	// Verify both tokens.
	_, err = tm.Verify(sig1)
	require.NoError(err, "token signed with first key should still verify")

	_, err = tm.Verify(sig2)
	require.NoError(err, "token signed with second key should verify")

	// Rotate back to the first key
	err = tm.UseSigningKey(kid1)
	require.NoError(err)
	require.Equal(kid1, tm.CurrentKey())
	require.Equal(kid1.String(), tm.CurrentKeyID())

	tok3, err := tm.CreateAccessToken(&tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}})
	require.NoError(err)
	sig3, err := tm.Sign(tok3)
	require.NoError(err)

	_, err = tm.Verify(sig3)
	require.NoError(err, "token signed after rotating back should verify")

	// Attempt to use an unknown key id
	err = tm.UseSigningKey(ulids.New())
	require.ErrorIs(err, tokens.ErrUnknownSigningKey)
}

// Test that removing a signing key invalidates tokens signed with it
func (s *TokenTestSuite) TestSigningKeyRemovalInvalidatesTokens() {
	require := s.Require()

	tm, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize token manager")

	// Create and sign a token with the current key
	tok, err := tm.CreateAccessToken(&tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}})
	require.NoError(err)
	signed, err := tm.Sign(tok)
	require.NoError(err)

	// Ensure it verifies prior to key removal
	_, err = tm.Verify(signed)
	require.NoError(err)

	kid := tm.CurrentKey()

	// Remove the signing key that was used to sign the token
	tm.RemoveSigningKey(kid)

	// Verification should now fail because the key no longer exists
	_, err = tm.Verify(signed)
	require.EqualError(err, "token is unverifiable: error while executing keyfunc: unknown signing key")

	// Tokens signed with the remaining key should still verify.
	tok2, err := tm.CreateAccessToken(&tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}})
	require.NoError(err)
	sig2, err := tm.Sign(tok2)
	require.NoError(err)
	_, err = tm.Verify(sig2)
	require.NoError(err)
}

// Test that a token can be parsed even if it is expired. This is necessary to parse
// access tokens in order to use a refresh token to extract the claims
func (s *TokenTestSuite) TestParseExpiredToken() {
	require := s.Require()
	tm, err := tokens.New(s.conf)
	require.NoError(err, "could not initialize token manager")

	// Default creds
	creds := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "01H6PGFB4T34D4WWEXQMAGJNMK",
		},
		UserID: "Rusty Shackleford",
		OrgID:  "01H6PGFG71N0AFEVTK3NJB71T9",
	}

	accessToken, err := tm.CreateAccessToken(creds)
	require.NoError(err, "could not create access token from claims")
	require.IsType(&tokens.Claims{}, accessToken.Claims)

	// Modify claims to be expired
	claims := accessToken.Claims.(*tokens.Claims)
	claims.IssuedAt = jwt.NewNumericDate(claims.IssuedAt.Add(-24 * time.Hour))
	claims.ExpiresAt = jwt.NewNumericDate(claims.ExpiresAt.Add(-24 * time.Hour))
	claims.NotBefore = jwt.NewNumericDate(claims.NotBefore.Add(-24 * time.Hour))
	accessToken.Claims = claims

	// Create signed token
	tks, err := tm.Sign(accessToken)
	require.NoError(err, "could not create expired access token from claims")

	// Ensure that verification fails; claims are invalid
	pclaims, err := tm.Verify(tks)
	require.Error(err, "expired token was somehow validated?")
	require.Empty(pclaims, "verify returned claims even after error")

	// Parse token without verifying claims but verifying the signature
	pclaims, err = tm.Parse(tks)
	require.NoError(err, "claims were validated in parse")
	require.NotEmpty(pclaims, "parsing returned empty claims without error")

	// Check claims
	require.Equal(claims.ID, pclaims.ID)
	require.Equal(claims.ExpiresAt, pclaims.ExpiresAt)
	require.Equal(creds.UserID, claims.UserID)

	// Ensure signature is still validated on parse
	tks += "abcdefg"
	claims, err = tm.Parse(tks)
	require.Error(err, "claims were parsed with bad signature")
	require.Empty(claims, "bad signature token returned non-empty claims")
}

// Execute suite as a go test
func TestTokenTestSuite(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}

func TestParseUnverifiedTokenClaims(t *testing.T) {
	claims, err := tokens.ParseUnverifiedTokenClaims(accessToken)
	require.NoError(t, err, "should not be able to parse a bad token")
	require.NotEmpty(t, claims, "should not return empty claims")

	// Should return an error when a bad token is parsed.
	_, err = tokens.ParseUnverifiedTokenClaims("notarealtoken")
	require.Error(t, err, "should not be able to parse a bad token")
}

func TestRefreshAudience(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	conf := tokens.Config{
		Audience:        "http://localhost:3000",
		Issuer:          "https://example.com",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key, conf)
	require.NoError(t, err)

	// Should default to issuer + /v1/refresh
	require.Equal(t, "https://example.com/v1/refresh", tm.RefreshAudience())

	// If issuer is invalid, fallback to DefaultRefreshAudience
	_, badKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	badConf := tokens.Config{
		Audience:        "http://localhost:3000",
		Issuer:          "%gh$?",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tmBad, err := tokens.NewWithKey(badKey, badConf)
	require.NoError(t, err)
	require.Equal(t, tokens.DefaultRefreshAudience, tmBad.RefreshAudience())

	// RefreshAudience from config should be respected
	confOverride := tokens.Config{
		Audience:        "http://localhost:3000",
		Issuer:          "https://example.com",
		RefreshAudience: "https://override.example.com/refresh",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	_, key2, err := ed25519.GenerateKey(rand.Reader) //nolint:gosec
	require.NoError(t, err)
	tmOverride, err := tokens.NewWithKey(key2, confOverride)
	require.NoError(t, err)
	require.Equal(t, "https://override.example.com/refresh", tmOverride.RefreshAudience())
}

func TestTokenManagerAllowsNonULIDKeyID(t *testing.T) {
	conf := tokens.Config{
		Keys: map[string]string{
			"primary": "testdata/01GE62EXXR0X0561XD53RDFBQJ.pem",
		},
		Audience:        audience,
		Issuer:          issuer,
		AccessDuration:  time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.New(conf)
	require.NoError(t, err)
	require.Equal(t, "primary", tm.CurrentKeyID())
	require.Equal(t, ulids.Null, tm.CurrentKey())

	claims := &tokens.Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: "user"}}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := tm.Sign(token)
	require.NoError(t, err)
	require.NotEmpty(t, signed)
}
