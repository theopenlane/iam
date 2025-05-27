package auth

import (
	"context"

	echo "github.com/theopenlane/echox"
	"github.com/theopenlane/utils/contextx"
)

// AuthenticationType represents the type of authentication used
// It can be JWT, PAT (Personal Access Token), or API Token
type AuthenticationType string

const (
	// JWTAuthentication is the authentication type for JWT tokens
	JWTAuthentication AuthenticationType = "jwt"
	// PATAuthentication is the authentication type for personal access tokens
	PATAuthentication AuthenticationType = "pat"
	// APITokenAuthentication is the authentication type for API tokens, commonly used for service authentication for machine-to-machine communication
	APITokenAuthentication AuthenticationType = "api_token"
)

// ContextRefreshToken is the context key for the refresh token
type ContextRefreshToken struct {
	token string
}

// ContextAccessToken is the context key for the access token
type ContextAccessToken struct {
	token string
}

// ContextRequestID is the context key for the request ID
type ContextRequestID struct {
	requestID string
}

// OrganizationCreationContextKey is the context key name for the organization creation context
type OrganizationCreationContextKey struct{}

// ManagedGroupContextKey is the context key name for the managed group context
type ManagedGroupContextKey struct{}

// OrgSubscriptionContextKey is the context key name for the organization subscription context
type OrgSubscriptionContextKey struct{}

// AcmeSolverContextKey is the context key name for the acme solver context
type AcmeSolverContextKey struct{}

// AuthenticatedUser contains the user and organization ID for the authenticated user
type AuthenticatedUser struct {
	// SubjectID is the user ID of the authenticated user or the api token ID if the user is an API token
	SubjectID string
	// SubjectName is the name of the authenticated user
	SubjectName string
	// SubjectEmail is the email of the authenticated user
	SubjectEmail string
	// OrganizationID is the organization ID of the authenticated user
	OrganizationID string
	// OrganizationName is the name of the organization the user is authenticated to
	OrganizationName string
	// OrganizationIDs is the list of organization IDs the user is authorized to access
	OrganizationIDs []string
	// AuthenticationType is the type of authentication used to authenticate the user (JWT, PAT, API Token)
	AuthenticationType AuthenticationType
	// ActiveSubscription is the active subscription for the user
	ActiveSubscription bool
}

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
	return contextx.With(ctx, &ContextAccessToken{token})
}

// SetAccessToken sets the access token context in the echo context
func SetAccessToken(c echo.Context, token string) {
	ctx := c.Request().Context()
	ctx = WithAccessToken(ctx, token)
	c.SetRequest(c.Request().WithContext(ctx))
}

// AccessTokenFromContext retrieves the access token from the context
func AccessTokenFromContext(ctx context.Context) (string, bool) {
	v, ok := contextx.From[*ContextAccessToken](ctx)
	if !ok {
		return "", ok
	}

	return v.token, ok
}

// MustAccessTokenFromContext retrieves the access token from the context or panics if not found
func MustAccessTokenFromContext(ctx context.Context) string {
	return contextx.MustFrom[*ContextAccessToken](ctx).token
}

// AccessTokenFromContextOr retrieves the access token from the context or returns the provided default value if not found
func AccessTokenFromContextOr(ctx context.Context, def string) string {
	return contextx.FromOr(ctx, def)
}

// WithRefreshToken sets the refresh token in the context
func WithRefreshToken(ctx context.Context, token string) context.Context {
	return contextx.With(ctx, &ContextRefreshToken{token})
}

// SetRefreshToken sets the refresh token context in the echo context
func SetRefreshToken(c echo.Context, token string) {
	ctx := c.Request().Context()
	ctx = WithRefreshToken(ctx, token)
	c.SetRequest(c.Request().WithContext(ctx))
}

// WithAccessAndRefreshToken sets the access and refresh tokens in the context
func WithAccessAndRefreshToken(ctx context.Context, accessToken, refreshToken string) context.Context {
	ctx = WithAccessToken(ctx, accessToken)
	ctx = WithRefreshToken(ctx, refreshToken)

	return ctx
}

// RefreshTokenFromContext retrieves the refresh token from the context
func RefreshTokenFromContext(ctx context.Context) (string, bool) {
	v, ok := contextx.From[*ContextRefreshToken](ctx)
	if !ok {
		return "", ok
	}

	return v.token, ok
}

// MustRefreshTokenFromContext retrieves the access token from the context or panics if not found
func MustRefreshTokenFromContext(ctx context.Context) string {
	return contextx.MustFrom[*ContextAccessToken](ctx).token
}

// WithRequestID sets the request ID in the context
// This is used to track requests across services
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return contextx.With(ctx, &ContextRequestID{requestID})
}

// SetRequestID sets the request id in the echo context
func SetRequestID(c echo.Context, token string) {
	ctx := c.Request().Context()
	ctx = WithRequestID(ctx, token)
	c.SetRequest(c.Request().WithContext(ctx))
}

// RequestIDFromContext retrieves the request ID from the context
func RequestIDFromContext(ctx context.Context) (string, bool) {
	v, ok := contextx.From[*ContextRequestID](ctx)
	if !ok {
		return "", ok
	}

	return v.requestID, ok
}

// MustRequestIDFromContext retrieves the request ID from the context or panics if not found
func MustRequestIDFromContext(ctx context.Context) string {
	return contextx.MustFrom[*ContextRequestID](ctx).requestID
}

// SetAuthenticatedUserContext sets the authenticated user context in the echo context
func SetAuthenticatedUserContext(c echo.Context, user *AuthenticatedUser) {
	ctx := c.Request().Context()
	ctx = WithAuthenticatedUser(ctx, user)
	c.SetRequest(c.Request().WithContext(ctx))
}

// GetAuthenticatedUserContext retrieves the authenticated user from the echo context
func GetAuthenticatedUserContext(c echo.Context) (*AuthenticatedUser, bool) {
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
