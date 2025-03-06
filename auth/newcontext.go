package auth

import (
	"context"

	echo "github.com/theopenlane/echox"
	"github.com/theopenlane/utils/contextx"
)

// WithAuthenticatedUser sets the authenticated user in the context
func WithAuthenticatedUser(ctx context.Context, user *AuthenticatedUser) context.Context {
	return contextx.With(ctx, user)
}

// AuthenticatedUserFromContext retrieves the authenticated user from the context
func AuthenticatedUserFromContext(ctx context.Context) (*AuthenticatedUser, bool) {
	return contextx.From[*AuthenticatedUser](ctx)
}

// MustAuthenticatedUserFromContext retrieves the authenticated user from the context or panics if not found
func MustAuthenticatedUserFromContext(ctx context.Context) *AuthenticatedUser {
	return contextx.MustFrom[*AuthenticatedUser](ctx)
}

// AuthenticatedUserFromContextOr retrieves the authenticated user from the context or returns the provided default value if not found
func AuthenticatedUserFromContextOr(ctx context.Context, def *AuthenticatedUser) *AuthenticatedUser {
	return contextx.FromOr(ctx, def)
}

// AuthenticatedUserFromContextOrFunc retrieves the authenticated user from the context or returns the result of the provided function if not found
func AuthenticatedUserFromContextOrFunc(ctx context.Context, f func() *AuthenticatedUser) *AuthenticatedUser {
	return contextx.FromOrFunc(ctx, f)
}

// WithAccessToken sets the access token in the context
func WithAccessToken(ctx context.Context, token string) context.Context {
	return contextx.With(ctx, token)
}

// AccessTokenFromContext retrieves the access token from the context
func AccessTokenFromContext(ctx context.Context) (string, bool) {
	return contextx.From[string](ctx)
}

// MustAccessTokenFromContext retrieves the access token from the context or panics if not found
func MustAccessTokenFromContext(ctx context.Context) string {
	return contextx.MustFrom[string](ctx)
}

// AccessTokenFromContextOr retrieves the access token from the context or returns the provided default value if not found
func AccessTokenFromContextOr(ctx context.Context, def string) string {
	return contextx.FromOr(ctx, def)
}

// AccessTokenFromContextOrFunc retrieves the access token from the context or returns the result of the provided function if not found
func AccessTokenFromContextOrFunc(ctx context.Context, f func() string) string {
	return contextx.FromOrFunc(ctx, f)
}

// WithRequestID sets the request ID in the context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return contextx.With(ctx, requestID)
}

// RequestIDFromContext retrieves the request ID from the context
func RequestIDFromContext(ctx context.Context) (string, bool) {
	return contextx.From[string](ctx)
}

// MustRequestIDFromContext retrieves the request ID from the context or panics if not found
func MustRequestIDFromContext(ctx context.Context) string {
	return contextx.MustFrom[string](ctx)
}

// RequestIDFromContextOr retrieves the request ID from the context or returns the provided default value if not found
func RequestIDFromContextOr(ctx context.Context, def string) string {
	return contextx.FromOr(ctx, def)
}

// RequestIDFromContextOrFunc retrieves the request ID from the context or returns the result of the provided function if not found
func RequestIDFromContextOrFunc(ctx context.Context, f func() string) string {
	return contextx.FromOrFunc(ctx, f)
}

// NewSetAuthenticatedUserContext sets the authenticated user context in the echo context
func NewSetAuthenticatedUserContext(c echo.Context, user *AuthenticatedUser) {
	ctx := c.Request().Context()
	ctx = WithAuthenticatedUser(ctx, user)
	c.SetRequest(c.Request().WithContext(ctx))
}

// NewGetAuthenticatedUserContext retrieves the authenticated user from the echo context
func NewGetAuthenticatedUserContext(c echo.Context) (*AuthenticatedUser, bool) {
	return AuthenticatedUserFromContext(c.Request().Context())
}

// MustGetAuthenticatedUserContext retrieves the authenticated user from the echo context or panics if not found
func MustGetAuthenticatedUserContext(c echo.Context) *AuthenticatedUser {
	return MustAuthenticatedUserFromContext(c.Request().Context())
}

// GetAuthenticatedUserContextOr retrieves the authenticated user from the echo context or returns the provided default value if not found
func GetAuthenticatedUserContextOr(c echo.Context, def *AuthenticatedUser) *AuthenticatedUser {
	return AuthenticatedUserFromContextOr(c.Request().Context(), def)
}

// GetAuthenticatedUserContextOrFunc retrieves the authenticated user from the echo context or returns the result of the provided function if not found
func GetAuthenticatedUserContextOrFunc(c echo.Context, f func() *AuthenticatedUser) *AuthenticatedUser {
	return AuthenticatedUserFromContextOrFunc(c.Request().Context(), f)
}
