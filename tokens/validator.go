package tokens

import (
	"context"
	"crypto/subtle"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// Validator are able to verify that access and refresh tokens were issued by
// Openlane and that their claims are valid (e.g. not expired).
type Validator interface {
	// Verify an access or a refresh token after parsing and return its claims
	Verify(tks string) (claims *Claims, err error)
	// VerifyWithContext verifies a token with blacklist checking
	VerifyWithContext(ctx context.Context, tks string) (claims *Claims, err error)
	// Parse an access or refresh token without verifying claims (e.g. to check an expired token)
	Parse(tks string) (claims *Claims, err error)
}

// validator implements the Validator interface, allowing structs in this package to
// embed the validation code base and supply their own keyFunc; unifying functionality
type validator struct {
	audience  string
	issuer    string
	keyFunc   jwt.Keyfunc
	blacklist TokenBlacklist
}

// Verify an access or a refresh token after parsing and return its claims.
func (v *validator) Verify(tks string) (claims *Claims, err error) {
	return v.VerifyWithContext(context.Background(), tks)
}

// VerifyWithContext verifies a token with blacklist checking
func (v *validator) VerifyWithContext(ctx context.Context, tks string) (claims *Claims, err error) {
	var token *jwt.Token

	if token, err = jwt.ParseWithClaims(tks, &Claims{}, v.keyFunc, jwt.WithValidMethods(allowedAlgorithms)); err != nil {
		return nil, err
	}

	var ok bool
	if claims, ok = token.Claims.(*Claims); !ok || !token.Valid {
		return nil, ErrTokenInvalidClaims
	}

	if !claims.VerifyAudience(v.audience, true) {
		return nil, ErrTokenInvalidAudience
	}

	if !claims.VerifyIssuer(v.issuer, true) {
		return nil, ErrTokenInvalidIssuer
	}

	// Check blacklist if configured
	if err := v.checkBlacklist(ctx, claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// checkBlacklist performs blacklist validation for tokens
func (v *validator) checkBlacklist(ctx context.Context, claims *Claims) error {
	if v.blacklist == nil {
		return nil
	}

	// Check if specific token is revoked
	if claims.ID != "" {
		revoked, err := v.blacklist.IsRevoked(ctx, claims.ID)
		if revoked {
			return ErrTokenInvalid
		}

		if err != nil {
			// Log the error but continue with fail-open behavior for availability
			// This matches the design decision in the blacklist implementation
			log.Debug().Err(err).Str("token_id", claims.ID).Msg("failed to check token blacklist status")
		}
	}

	// Check if user is suspended - prefer UserID, fallback to Subject
	if userID := v.getUserID(claims); userID != "" {
		suspended, err := v.blacklist.IsUserRevoked(ctx, userID)
		if suspended {
			return ErrTokenInvalid
		}

		if err != nil {
			// Log the error but continue with fail-open behavior for availability
			log.Debug().Err(err).Str("user_id", userID).Msg("failed to check user suspension status")
		}
	}

	return nil
}

// getUserID extracts the user identifier from claims
func (v *validator) getUserID(claims *Claims) string {
	if claims.UserID != "" {
		return claims.UserID
	}

	return claims.Subject
}

// Parse an access or refresh token verifying its signature but without verifying its
// claims. This ensures that valid JWT tokens are still accepted but claims can be
// handled on a case-by-case basis; for example by validating an expired access token
// during reauthentication
func (v *validator) Parse(tks string) (claims *Claims, err error) {
	parser := jwt.NewParser(jwt.WithValidMethods(allowedAlgorithms), jwt.WithoutClaimsValidation())
	claims = &Claims{}

	if _, err = parser.ParseWithClaims(tks, claims, v.keyFunc); err != nil {
		return nil, err
	}

	return claims, nil
}

func (c *Claims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

func (c *Claims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}

	return subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0
}

func verifyAud(aud []string, cmp string, required bool) bool {
	if len(aud) == 0 {
		return !required
	}
	// use a var here to keep constant time compare when looping over a number of claims
	result := false

	var stringClaims string

	for _, a := range aud {
		if subtle.ConstantTimeCompare([]byte(a), []byte(cmp)) != 0 {
			result = true
		}

		stringClaims += a
	}

	// case where "" is sent in one or many aud claims
	if len(stringClaims) == 0 {
		return !required
	}

	return result
}
