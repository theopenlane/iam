package oauthserver

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/theopenlane/httpsling"
)

// Endpoint paths served by the authorization server, unversioned because clients discover them from metadata
const (
	// AuthorizePath is where clients send users to approve a connection
	AuthorizePath = "/oauth2/authorize"
	// TokenPath is where clients exchange codes and refresh tokens
	TokenPath = "/oauth2/token" //nolint:gosec
	// RevokePath is where clients revoke tokens (RFC 7009)
	RevokePath = "/oauth2/revoke"
	// MetadataPath is the RFC 8414 well-known path of the metadata document
	MetadataPath = "/.well-known/oauth-authorization-server"
)

// Protocol values the server supports
const (
	// ResponseTypeCode is the only response type, the authorization code flow
	ResponseTypeCode = "code"
	// GrantTypeAuthorizationCode exchanges an authorization code for tokens
	GrantTypeAuthorizationCode = "authorization_code"
	// GrantTypeRefreshToken exchanges a refresh token for new tokens
	GrantTypeRefreshToken = "refresh_token"
	// AuthMethodNone is the only client authentication method, since every client is public
	AuthMethodNone = "none"
)

const (
	// cacheControlNoStore forbids caching a response that carries tokens
	cacheControlNoStore = "no-store"
	// pragmaNoCache is the HTTP/1.0 equivalent of no-store
	pragmaNoCache = "no-cache"
)

// Metadata is the RFC 8414 authorization server metadata document
type Metadata struct {
	// Issuer is the authorization server's identifier, which clients compare against iss
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is the URL of the authorize endpoint
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is the URL of the token endpoint
	TokenEndpoint string `json:"token_endpoint"`
	// RevocationEndpoint is the URL of the revocation endpoint
	RevocationEndpoint string `json:"revocation_endpoint"`
	// ResponseTypesSupported lists the response types, only code
	ResponseTypesSupported []string `json:"response_types_supported"`
	// GrantTypesSupported lists the grant types, authorization_code and refresh_token
	GrantTypesSupported []string `json:"grant_types_supported"`
	// CodeChallengeMethodsSupported lists the PKCE methods, only S256
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	// TokenEndpointAuthMethodsSupported lists how clients authenticate at the token endpoint, only none for public clients
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// RevocationEndpointAuthMethodsSupported lists how clients authenticate at the revocation endpoint, only none
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported"`
	// ScopesSupported lists the scopes clients may request
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// ClientIDMetadataDocumentSupported tells clients they can use a metadata document URL as their client_id
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported"`
	// AuthorizationResponseIssParameterSupported tells clients the authorize response carries iss (RFC 9207)
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// NewMetadata builds the metadata document for an issuer serving the endpoint paths above with the given scopes
func NewMetadata(issuer string, scopes []string) Metadata {
	issuer = strings.TrimRight(issuer, "/")

	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)

	return Metadata{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      issuer + AuthorizePath,
		TokenEndpoint:                              issuer + TokenPath,
		RevocationEndpoint:                         issuer + RevokePath,
		ResponseTypesSupported:                     []string{ResponseTypeCode},
		GrantTypesSupported:                        []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
		CodeChallengeMethodsSupported:              []string{MethodS256},
		TokenEndpointAuthMethodsSupported:          []string{AuthMethodNone},
		RevocationEndpointAuthMethodsSupported:     []string{AuthMethodNone},
		ScopesSupported:                            sorted,
		ClientIDMetadataDocumentSupported:          true,
		AuthorizationResponseIssParameterSupported: true,
	}
}

// ParseScope splits an OAuth scope parameter (space-delimited) into a deduplicated list
func ParseScope(scope string) []string {
	fields := strings.Fields(scope)
	slices.Sort(fields)

	return slices.Compact(fields)
}

// FormatScope joins scopes into an OAuth scope parameter
func FormatScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// SingleValued returns an invalid_request error when a named parameter is repeated (RFC 6749 §3.1)
func SingleValued(form url.Values, names ...string) error {
	for _, name := range names {
		if len(form[name]) > 1 {
			return NewError(ErrCodeInvalidRequest, name+" must not be repeated")
		}
	}

	return nil
}

// NoStore sets the cache headers RFC 6749 §5.1 requires on responses carrying tokens
func NoStore(h http.Header) {
	h.Set(httpsling.HeaderCacheControl, cacheControlNoStore)
	h.Set(httpsling.HeaderPragma, pragmaNoCache)
}
