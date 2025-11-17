package google

// ProviderConfig represents the configuration settings for a Google Oauth Provider
type ProviderConfig struct {
	// ClientID is the public identifier for the Google oauth2 client
	ClientID string `json:"clientid" koanf:"clientid" jsonschema:"required"`
	// ClientSecret is the secret for the Google oauth2 client
	ClientSecret string `json:"clientsecret" koanf:"clientsecret" jsonschema:"required" sensitive:"true"`
	// ClientEndpoint is the endpoint for the Google oauth2 client
	ClientEndpoint string `json:"clientendpoint" koanf:"clientendpoint" domain:"inherit" domainPrefix:"https://api"`
	// Scopes are the scopes that the Google oauth2 client will request
	Scopes []string `json:"scopes" koanf:"scopes" jsonschema:"required"`
	// RedirectURL is the URL that the Google oauth2 client will redirect to after authentication with Google
	RedirectURL string `json:"redirecturl" koanf:"redirecturl" jsonschema:"required" default:"/v1/google/callback"`
}
