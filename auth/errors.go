package auth

import (
	"errors"
)

var (
	// ErrNoClaims is returned when no claims are found on the request context
	ErrNoClaims = errors.New("no claims found on the request context")
	// ErrNoUserInfo is returned when no user info is found on the request context
	ErrNoUserInfo = errors.New("no user info found on the request context")
	// ErrNoAuthUser is returned when no authenticated user is found on the request context
	ErrNoAuthUser = errors.New("could not identify authenticated user in request")
	// ErrUnverifiedUser is returned when the user is not verified
	ErrUnverifiedUser = errors.New("user is not verified")
	// ErrParseBearer is returned when the bearer token could not be parsed from the authorization header
	ErrParseBearer = errors.New("could not parse bearer token from authorization header")
	// ErrNoAuthorization is returned when no authorization header is found in the request
	ErrNoAuthorization = errors.New("no authorization header in request")
	// ErrNoAPIKey is returned when no API key is found in the request
	ErrNoAPIKey = errors.New("no API key found in request")
	// ErrNoRequest is returned when no request is found on the context
	ErrNoRequest = errors.New("no request found on the context")
	// ErrNoRefreshToken is returned when no refresh token is found on the request
	ErrNoRefreshToken = errors.New("no refresh token available on request")
	// ErrRefreshDisabled is returned when re-authentication with refresh tokens is disabled
	ErrRefreshDisabled = errors.New("re-authentication with refresh tokens disabled")
	// ErrUnableToConstructValidator is returned when the validator cannot be constructed
	ErrUnableToConstructValidator = errors.New("unable to construct validator")
	// ErrPasswordTooWeak is returned when the password is too weak
	ErrPasswordTooWeak = errors.New("password is too weak: use a combination of upper and lower case letters, numbers, and special characters")
	// ErrCouldNotFetchSubscription is returned when the subscription could not be fetched
	ErrCouldNotFetchSubscription = errors.New("could not fetch subscription")
)
