package oauthserver

import "errors"

var (
	// ErrDialerRequired is returned when a resolver is built without a dialer
	ErrDialerRequired = errors.New("a dialer that only reaches public addresses is required")
	// ErrInvalidClientID is returned when a client_id is not an acceptable metadata URL
	ErrInvalidClientID = errors.New("client_id must be an https URL with a path")
	// ErrClientMetadata is returned when the client metadata document can't be fetched or is invalid
	ErrClientMetadata = errors.New("unable to load client metadata document")
	// ErrInvalidRedirectURI is returned when a redirect_uri is not registered for the client
	ErrInvalidRedirectURI = errors.New("redirect_uri is not registered for this client")
	// ErrFetchRateLimited is returned when a metadata document is needed but the fetch budget is spent
	ErrFetchRateLimited = errors.New("metadata fetch rate limit exceeded, try again shortly")
	// ErrResourceMetadata is returned when a resource's protected resource metadata can't be loaded
	ErrResourceMetadata = errors.New("unable to load protected resource metadata")
	// ErrInvalidTarget is returned when a resource indicator is missing, repeated, or not allowed
	ErrInvalidTarget = errors.New("resource is not an allowed target")
	// ErrKeyringRequired is returned when the token manager has no usable API token keyring
	ErrKeyringRequired = errors.New("oauth tokens require an api token keyring with an active key")
	// ErrTokenInvalid is returned when a presented token is malformed or does not verify
	ErrTokenInvalid = errors.New("invalid oauth token")
	// ErrTokenKindMismatch is returned when a presented token's prefix doesn't match its stored record's kind
	ErrTokenKindMismatch = errors.New("oauth token kind does not match its stored record")
)

var (
	// errMetadataUnavailable marks fetch failures that may be temporary, so a cached document can still be served
	errMetadataUnavailable = errors.New("metadata host unavailable")
	// errUnexpectedStatus is returned when a metadata URL answers with a status other than 200
	errUnexpectedStatus = errors.New("unexpected response status")
	// errMalformedDocument is returned when a metadata document is not valid JSON or exceeds the size cap
	errMalformedDocument = errors.New("metadata document is malformed")
	// errInvalidClientName is returned when client_name is empty, too long, or contains hidden characters
	errInvalidClientName = errors.New("client_name must be 1-100 characters with no control or formatting characters")
	// errInvalidRedirectScheme is returned when a redirect URI uses a scheme a browser could execute
	errInvalidRedirectScheme = errors.New("redirect_uris must be https, loopback http, or a reverse-domain private-use scheme")
	// errInvalidClientURI is returned when client_uri points at a different site than client_id
	errInvalidClientURI = errors.New("client_uri must be on the same host as client_id")
	// errInvalidLogoURI is returned when logo_uri is not https
	errInvalidLogoURI = errors.New("logo_uri must be https")
)

// OAuthError is an RFC 6749 §5.2 error response
type OAuthError struct {
	// Code is the RFC 6749 error code
	Code string `json:"error"`
	// Description is a human-readable explanation for the client developer
	Description string `json:"error_description,omitempty"`
}

// Error implements error
func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}

	return e.Code + ": " + e.Description
}

// NewError returns an OAuthError
func NewError(code, description string) *OAuthError {
	return &OAuthError{Code: code, Description: description}
}

// Standard error codes
const (
	// ErrCodeInvalidRequest is for a malformed request or a missing or repeated parameter
	ErrCodeInvalidRequest = "invalid_request"
	// ErrCodeInvalidClient is for an unknown client or failed client authentication
	ErrCodeInvalidClient = "invalid_client"
	// ErrCodeInvalidGrant is for an invalid, expired, revoked, or reused code or refresh token
	ErrCodeInvalidGrant = "invalid_grant"
	// ErrCodeInvalidScope is for a scope that is unknown or exceeds what was granted
	ErrCodeInvalidScope = "invalid_scope"
	// ErrCodeUnsupportedGrantType is for a grant type the server does not support
	ErrCodeUnsupportedGrantType = "unsupported_grant_type"
	// ErrCodeUnsupportedResponse is for a response type the server does not support
	ErrCodeUnsupportedResponse = "unsupported_response_type"
	// ErrCodeAccessDenied is for a user denying consent
	ErrCodeAccessDenied = "access_denied"
	// ErrCodeServerError is for an unexpected failure on the server
	ErrCodeServerError = "server_error"
	// ErrCodeInvalidTarget is for a resource indicator that is missing, repeated, or not allowed (RFC 8707)
	ErrCodeInvalidTarget = "invalid_target"
)
