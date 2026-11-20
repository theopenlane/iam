package oauthserver

import (
	"mime"
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
	// TokenTypeBearer is the token_type of issued access tokens
	TokenTypeBearer = "Bearer"
)

// Request and response parameter names
const (
	// ParamClientID is the client's identifier
	ParamClientID = "client_id"
	// ParamRedirectURI is where the authorization response is sent
	ParamRedirectURI = "redirect_uri"
	// ParamResponseType is the requested authorization response type
	ParamResponseType = "response_type"
	// ParamCodeChallenge is the PKCE code challenge (RFC 7636)
	ParamCodeChallenge = "code_challenge"
	// ParamCodeChallengeMethod is the PKCE code challenge method (RFC 7636)
	ParamCodeChallengeMethod = "code_challenge_method"
	// ParamCodeVerifier is the PKCE code verifier (RFC 7636)
	ParamCodeVerifier = "code_verifier"
	// ParamState is the client's opaque value echoed back on the redirect
	ParamState = "state"
	// ParamScope is the space-delimited requested scopes
	ParamScope = "scope"
	// ParamResource is the resource indicator (RFC 8707)
	ParamResource = "resource"
	// ParamGrantType is the token endpoint grant type
	ParamGrantType = "grant_type"
	// ParamCode is the authorization code
	ParamCode = "code"
	// ParamRefreshToken is the refresh token
	ParamRefreshToken = "refresh_token"
	// ParamToken is the token to revoke (RFC 7009)
	ParamToken = "token"
	// ParamError is the authorization response error code
	ParamError = "error"
	// ParamIssuer is the authorization response parameter naming the issuer (RFC 9207)
	ParamIssuer = "iss"
)

// AuthorizeParams are the authorize endpoint parameters that must not be repeated (RFC 6749 §3.1)
var AuthorizeParams = []string{ParamClientID, ParamRedirectURI, ParamResponseType, ParamCodeChallenge, ParamCodeChallengeMethod, ParamState, ParamScope}

// TokenParams are the token endpoint parameters that must not be repeated (RFC 6749 §3.1)
var TokenParams = []string{ParamGrantType, ParamCode, ParamRedirectURI, ParamClientID, ParamCodeVerifier, ParamRefreshToken, ParamResource}

// TokenResponse is the RFC 6749 §5.1 token response
type TokenResponse struct {
	// AccessToken is the issued access token
	AccessToken string `json:"access_token"`
	// TokenType is always Bearer
	TokenType string `json:"token_type"`
	// ExpiresIn is the access token lifetime in seconds
	ExpiresIn int64 `json:"expires_in"`
	// RefreshToken is the issued refresh token
	RefreshToken string `json:"refresh_token"`
	// Scope is the space-delimited scopes the tokens carry
	Scope string `json:"scope"`
}

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

// ParseForm returns a form-encoded request body, the only body format the token and revocation endpoints accept
func ParseForm(r *http.Request) (url.Values, *OAuthError) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get(httpsling.HeaderContentType))
	if err != nil || mediaType != httpsling.ContentTypeForm {
		return nil, NewError(ErrCodeInvalidRequest, "the request body must be "+httpsling.ContentTypeForm)
	}

	if err := r.ParseForm(); err != nil {
		return nil, NewError(ErrCodeInvalidRequest, "malformed form body")
	}

	return r.PostForm, nil
}

// RedirectURL adds the non-empty params and the issuer (RFC 9207) to a client redirect URI, keeping its query
func RedirectURL(redirectURI, issuer string, params url.Values) (string, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()

	for k := range params {
		if v := params.Get(k); v != "" {
			q.Set(k, v)
		}
	}

	q.Set(ParamIssuer, issuer)
	u.RawQuery = q.Encode()

	return u.String(), nil
}
