package auth

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
