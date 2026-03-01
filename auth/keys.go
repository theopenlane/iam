package auth

import (
	"context"

	"github.com/theopenlane/utils/contextx"
)

// CallerKey is the context key for storing and retrieving a *Caller
var CallerKey = contextx.NewKey[*Caller]()

// ActiveTrustCenterIDKey stores the trust center ID for the current anonymous trust center request.
var ActiveTrustCenterIDKey = contextx.NewKey[string]()

// ActiveAssessmentIDKey stores the assessment ID for the current anonymous questionnaire request.
var ActiveAssessmentIDKey = contextx.NewKey[string]()

// AccessTokenKey stores and retrieves the request access token.
var AccessTokenKey = contextx.NewKey[string]()

// RefreshTokenKey stores and retrieves the request refresh token.
var RefreshTokenKey = contextx.NewKey[string]()

// RequestIDKey stores and retrieves the request ID.
var RequestIDKey = contextx.NewKey[string]()

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
	if c == nil {
		return ctx
	}

	current, ok := CallerFromContext(ctx)
	if !ok || current == nil {
		return WithCaller(ctx, &Caller{
			OriginalSystemAdmin: c,
		})
	}

	updated := *current
	updated.OriginalSystemAdmin = c

	return WithCaller(ctx, &updated)
}

// OriginalSystemAdminCallerFromContext returns the original admin caller from
// ctx when present.
func OriginalSystemAdminCallerFromContext(ctx context.Context) (*Caller, bool) {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil || caller.OriginalSystemAdmin == nil {
		return nil, false
	}

	return caller.OriginalSystemAdmin, true
}

// WithAccessToken stores the request access token in ctx.
func WithAccessToken(ctx context.Context, token string) context.Context {
	return AccessTokenKey.Set(ctx, token)
}

// AccessTokenFromContext returns the request access token from ctx when present.
func AccessTokenFromContext(ctx context.Context) (string, bool) {
	return AccessTokenKey.Get(ctx)
}

// WithRefreshToken stores the request refresh token in ctx.
func WithRefreshToken(ctx context.Context, token string) context.Context {
	return RefreshTokenKey.Set(ctx, token)
}

// RefreshTokenFromContext returns the request refresh token from ctx when present.
func RefreshTokenFromContext(ctx context.Context) (string, bool) {
	return RefreshTokenKey.Get(ctx)
}

// WithRequestID stores the request ID in ctx.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return RequestIDKey.Set(ctx, requestID)
}

// RequestIDFromContext returns the request ID from ctx when present.
func RequestIDFromContext(ctx context.Context) (string, bool) {
	return RequestIDKey.Get(ctx)
}
