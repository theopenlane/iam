package auth

import (
	"context"

	"github.com/theopenlane/utils/contextx"
)

// CallerKey is the context key for storing and retrieving a *Caller
var CallerKey = contextx.NewKey[*Caller]()

// OriginalSystemAdminCallerKey stores the original system-admin caller when a
// request is temporarily switched to run as another user.
var OriginalSystemAdminCallerKey = contextx.NewKey[*Caller]()

// AnonymousQuestionnaireUserKey stores and retrieves the anonymous questionnaire caller details.
var AnonymousQuestionnaireUserKey = contextx.NewKey[*AnonymousQuestionnaireUser]()

// AnonymousTrustCenterUserKey stores and retrieves the anonymous trust center caller details.
var AnonymousTrustCenterUserKey = contextx.NewKey[*AnonymousTrustCenterUser]()

// AccessTokenKey stores and retrieves the request access token.
var AccessTokenKey = contextx.NewKey[string]()

// RefreshTokenKey stores and retrieves the request refresh token.
var RefreshTokenKey = contextx.NewKey[string]()

// RequestIDKey stores and retrieves the request ID.
var RequestIDKey = contextx.NewKey[string]()

// ImpersonatedUserKey stores and retrieves impersonated user context.
var ImpersonatedUserKey = contextx.NewKey[*ImpersonatedUser]()

// WithCaller stores c in ctx and returns the updated context
func WithCaller(ctx context.Context, c *Caller) context.Context {
	return CallerKey.Set(ctx, c)
}

// CallerFromContext returns the Caller stored in ctx and true, or nil and false if not set
func CallerFromContext(ctx context.Context) (*Caller, bool) {
	return CallerKey.Get(ctx)
}

// MustCallerFromContext returns the Caller stored in ctx, panicking if not set
func MustCallerFromContext(ctx context.Context) *Caller {
	return CallerKey.MustGet(ctx)
}

// WithOriginalSystemAdminCaller stores the original admin caller in ctx.
func WithOriginalSystemAdminCaller(ctx context.Context, c *Caller) context.Context {
	return OriginalSystemAdminCallerKey.Set(ctx, c)
}

// OriginalSystemAdminCallerFromContext returns the original admin caller from
// ctx when present.
func OriginalSystemAdminCallerFromContext(ctx context.Context) (*Caller, bool) {
	return OriginalSystemAdminCallerKey.Get(ctx)
}
