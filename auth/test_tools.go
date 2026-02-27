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

// newValidClaimsOrgID returns claims with a fake orgID for testing purposes ONLY
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

// NewTestContextWithValidUser creates a context with a valid user for testing purposes only
func NewTestContextWithValidUser(subject string) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaims(subject)

	ctx := WithCaller(ec.Request().Context(), &Caller{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
	})

	ctx = contextx.With(ctx, ec)

	ec.SetRequest(ec.Request().WithContext(ctx))

	return ctx
}

// NewTestContextWithOrgID creates a context with a fake orgID for testing purposes only
func NewTestContextWithOrgID(sub, orgID string) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(sub, orgID)

	ctx := WithCaller(ec.Request().Context(), &Caller{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
	})

	ctx = contextx.With(ctx, ec)

	ec.SetRequest(ec.Request().WithContext(ctx))

	return ctx
}

// NewTestContextForSystemAdmin creates a context with a fake system admin user
func NewTestContextForSystemAdmin(sub, orgID string) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(sub, orgID)

	ctx := WithCaller(ec.Request().Context(), &Caller{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
		Capabilities:       CapSystemAdmin,
	})

	ctx = contextx.With(ctx, ec)

	ec.SetRequest(ec.Request().WithContext(ctx))

	return ctx
}

// NewTestContextWithSubscription creates a context with an active subscription for testing purposes only
func NewTestContextWithSubscription(subscription bool) context.Context {
	ec := echocontext.NewTestEchoContext()

	claims := newValidClaimsOrgID(ulids.New().String(), ulids.New().String())

	ctx := WithCaller(ec.Request().Context(), &Caller{
		SubjectID:          claims.UserID,
		OrganizationID:     claims.OrgID,
		OrganizationIDs:    []string{claims.OrgID},
		AuthenticationType: JWTAuthentication,
		ActiveSubscription: subscription,
	})

	ctx = contextx.With(ctx, ec)

	ec.SetRequest(ec.Request().WithContext(ctx))

	return ctx
}
