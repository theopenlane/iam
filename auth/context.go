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

// AnonymousQuestionnaireUser contains user information for anonymously accessing and filling
// a questionnaire
type AnonymousQuestionnaireUser struct {
	// SubjectID is the user ID of the authenticated user or the api token ID if the user is an API token
	SubjectID string
	// SubjectName is the name of the authenticated user
	SubjectName string
	// SubjectEmail is the email of the authenticated user
	SubjectEmail string
	// OrganizationID is the organization ID of the authenticated user
	OrganizationID string
	// AuthenticationType is the type of authentication used to authenticate the user (JWT, PAT, API Token)
	AuthenticationType AuthenticationType
	// AssessmentID is the ID of the assessment the user is accessing
	AssessmentID string
}

// AnonymousTrustCenterUser contains user information for anonymous trust center access
// This allows unauthenticated users to access specific trust center resources
type AnonymousTrustCenterUser struct {
	// SubjectID is the user ID of the authenticated user or the api token ID if the user is an API token
	SubjectID string
	// SubjectName is the name of the authenticated user
	SubjectName string
	// SubjectEmail is the email of the authenticated user
	SubjectEmail string
	// OrganizationID is the organization ID of the authenticated user
	OrganizationID string
	// AuthenticationType is the type of authentication used to authenticate the user (JWT, PAT, API Token)
	AuthenticationType AuthenticationType
	// TrustCenterID is the ID of the trust center the user has access to
	TrustCenterID string
	// OrganizationRole is the role of the user in the organization (e.g., anonymous) that can be used to skip certain authorization checks
	// that are only organization role dependent
	OrganizationRole OrganizationRoleType
}

// WithContextValue stores a typed value in ctx using key.
func WithContextValue[T any](ctx context.Context, key contextx.Key[T], value T) context.Context {
	return key.Set(ctx, value)
}

// ContextValue retrieves a typed value from ctx.
func ContextValue[T any](ctx context.Context, key contextx.Key[T]) (T, bool) {
	return key.Get(ctx)
}

// MustContextValue retrieves a typed value from ctx and panics if it's missing.
func MustContextValue[T any](ctx context.Context, key contextx.Key[T]) T {
	return key.MustGet(ctx)
}

// ContextValueOr returns the stored value or def when absent.
func ContextValueOr[T any](ctx context.Context, key contextx.Key[T], def T) T {
	return key.GetOr(ctx, def)
}

// ContextValueOrFunc returns the stored value or calls fn when absent.
func ContextValueOrFunc[T any](ctx context.Context, key contextx.Key[T], fn func() T) T {
	return key.GetOrFunc(ctx, fn)
}

// SetEchoContextValue stores a typed value inside the echo context.
func SetEchoContextValue[T any](c echo.Context, key contextx.Key[T], value T) {
	ctx := key.Set(c.Request().Context(), value)
	c.SetRequest(c.Request().WithContext(ctx))
}

// EchoContextValue retrieves a typed value from the echo context.
func EchoContextValue[T any](c echo.Context, key contextx.Key[T]) (T, bool) {
	return key.Get(c.Request().Context())
}

// MustEchoContextValue retrieves a typed value from the echo context and panics if missing.
func MustEchoContextValue[T any](c echo.Context, key contextx.Key[T]) T {
	return key.MustGet(c.Request().Context())
}
