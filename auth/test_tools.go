package auth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/theopenlane/echox/middleware/echocontext"
	"github.com/theopenlane/utils/contextx"
	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/tokens"
)

// newValidClaims returns claims with a fake subject for testing purposes ONLY
func newValidClaims(subject string) *tokens.Claims {
	iat := time.Now()
	nbf := iat
	exp := time.Now().Add(time.Hour)

	claims := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    "test suite",
			IssuedAt:  jwt.NewNumericDate(iat),
			NotBefore: jwt.NewNumericDate(nbf),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		UserID: subject,
		OrgID:  "ulid_id_of_org",
	}

	return claims
}

func NewTestContextWithValidUser(subject string) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaims(subject)

	SetAuthenticatedUserContext(ec, &AuthenticatedUser{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
	})

	reqCtx := contextx.With(ec.Request().Context(), ec)

	ec.SetRequest(ec.Request().WithContext(reqCtx))

	return reqCtx
}

// newValidClaims returns claims with a fake orgID for testing purposes ONLY
func newValidClaimsOrgID(sub, orgID string) *tokens.Claims {
	iat := time.Now()
	nbf := iat
	exp := time.Now().Add(time.Hour)

	claims := &tokens.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			Issuer:    "test suite",
			IssuedAt:  jwt.NewNumericDate(iat),
			NotBefore: jwt.NewNumericDate(nbf),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		UserID: sub,
		OrgID:  orgID,
	}

	return claims
}

// NewTestContextWithOrgID creates a context with a fake orgID for testing purposes only (why all caps jeez keep it down)
func NewTestContextWithOrgID(sub, orgID string) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(sub, orgID)

	SetAuthenticatedUserContext(ec, &AuthenticatedUser{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
	})

	reqCtx := contextx.With(ec.Request().Context(), ec)

	ec.SetRequest(ec.Request().WithContext(reqCtx))

	return reqCtx
}

// NewTestContextWithSubscription creates a context with an active subscription for testing purposes only
func NewTestContextWithSubscription(subscription bool) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(ulids.New().String(), ulids.New().String())

	SetAuthenticatedUserContext(ec, &AuthenticatedUser{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
		ActiveSubscription: subscription,
	})

	reqCtx := contextx.With(ec.Request().Context(), ec)

	return reqCtx
}
