package auth

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echo "github.com/theopenlane/echox"
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

// NewTestEchoContextWithValidUser creates an echo context with a fake subject for testing purposes ONLY
func NewTestEchoContextWithValidUser(subject string) (echo.Context, error) {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaims(subject)

	SetAuthenticatedUserContext(ec, &AuthenticatedUser{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: "jwt",
	})

	return ec, nil
}

func NewTestContextWithValidUser(subject string) (context.Context, error) {
	ec, err := NewTestEchoContextWithValidUser(subject)
	if err != nil {
		return nil, err
	}

	reqCtx := contextx.With(ec.Request().Context(), ec)

	ec.SetRequest(ec.Request().WithContext(reqCtx))

	return reqCtx, nil
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

// NewTestEchoContextWithOrgID creates an echo context with a fake orgID for testing purposes ONLY
func NewTestEchoContextWithOrgID(sub, orgID string) (echo.Context, error) {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(sub, orgID)

	SetAuthenticatedUserContext(ec, &AuthenticatedUser{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: "jwt",
	})

	return ec, nil
}

// NewTestContextWithOrgID creates a context with a fake orgID for testing purposes only (why all caps jeez keep it down)
func NewTestContextWithOrgID(sub, orgID string) (context.Context, error) {
	ec, err := NewTestEchoContextWithOrgID(sub, orgID)
	if err != nil {
		return nil, err
	}

	reqCtx := contextx.With(ec.Request().Context(), ec)

	ec.SetRequest(ec.Request().WithContext(reqCtx))

	return reqCtx, nil
}

// NewTestEchoContextWithOrgID creates an echo context with a fake orgID for testing purposes ONLY
func NewTestEchoContextWithSubscription(subscription bool) (echo.Context, error) {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(ulids.New().String(), ulids.New().String())

	SetAuthenticatedUserContext(ec, &AuthenticatedUser{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: "jwt",
		ActiveSubscription: subscription,
	})

	return ec, nil
}

// NewTestContextWithOrgID creates a context with a fake orgID for testing purposes only (why all caps jeez keep it down)
func NewTestContextWithSubscription(subscription bool) (context.Context, error) {
	ec, err := NewTestEchoContextWithSubscription(subscription)
	if err != nil {
		return nil, err
	}

	reqCtx := contextx.With(ec.Request().Context(), ec)

	ec.SetRequest(ec.Request().WithContext(reqCtx))

	return reqCtx, nil
}
