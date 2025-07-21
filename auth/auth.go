package auth

import (
	"net/http"
	"regexp"
	"time"

	echo "github.com/theopenlane/echox"

	"github.com/theopenlane/iam/sessions"
)

const (
	// Authorization is the key used in HTTP headers or cookies to represent the authorization token
	Authorization = "Authorization"
	// APIKeyHeader is the key used in HTTP headers to represent the API key
	APIKeyHeader = "X-API-Key" //nolint:gosec
	// AccessTokenCookie is the key used in cookies to represent the access token
	AccessTokenCookie = "access_token"
	// RefreshTokenCookie is the key used in cookies to represent the refresh token
	RefreshTokenCookie = "refresh_token"
	// UserIDHeader is the header used by system admins to specify target user ID
	UserIDHeader = "X-User-ID"
	// OrganizationIDHeader is the header used by system admins to specify target organization ID
	OrganizationIDHeader = "X-Organization-ID"
	// ImpersonationScheme is the authorization scheme for impersonation tokens
	ImpersonationScheme = "Impersonation"
)

// used to extract the access token from the header
var (
	bearer        = regexp.MustCompile(`^\s*[Bb]earer\s+([a-zA-Z0-9_\-\.]+)\s*$`)
	impersonation = regexp.MustCompile(`^\s*` + ImpersonationScheme + `\s+([a-zA-Z0-9_\-\.]+)\s*$`)
)

// GetBearerToken retrieves the bearer token from the authorization header and parses it
// to return only the JWT access token component of the header. Alternatively, if the
// authorization header is not present, then the token is fetched from cookies. If the
// header is missing or the token is not available, an error is returned.
//
// NOTE: the authorization header takes precedence over access tokens in cookies.
func GetBearerToken(c echo.Context) (string, error) {
	// Attempt to get the access token from the header.
	if h := c.Request().Header.Get(Authorization); h != "" {
		match := bearer.FindStringSubmatch(h)
		if len(match) == 2 { //nolint:mnd
			return match[1], nil
		}

		return "", ErrParseBearer
	}

	// Attempt to get the access token from cookies.
	if cookie, err := c.Cookie(AccessTokenCookie); err == nil {
		// If the error is nil, that means we were able to retrieve the access token cookie
		if CookieExpired(cookie) {
			return "", ErrNoAuthorization
		}

		return cookie.Value, nil
	}

	return "", ErrNoAuthorization
}

// GetAPIKey retrieves the API key from the authorization header or the X-API-Key header.
func GetAPIKey(c echo.Context) (string, error) {
	// Attempt to get the api token from the header
	if h := c.Request().Header.Get(APIKeyHeader); h != "" {
		return h, nil
	}

	return "", ErrNoAPIKey
}

// GetRefreshToken retrieves the refresh token from the cookies in the request. If the
// cookie is not present or expired then an error is returned.
func GetRefreshToken(c echo.Context) (string, error) {
	cookie, err := c.Cookie(RefreshTokenCookie)
	if err != nil {
		return "", ErrNoRefreshToken
	}

	// ensure cookie is not expired
	if CookieExpired(cookie) {
		return "", ErrNoRefreshToken
	}

	return cookie.Value, nil
}

// SetAuthCookies is a helper function to set authentication cookies on a echo request.
// The access token cookie (access_token) is an http only cookie that expires when the
// access token expires. The refresh token cookie is not an http only cookie (it can be
// accessed by client-side scripts) and it expires when the refresh token expires. Both
// cookies require https and will not be set (silently) over http connections.
func SetAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, c sessions.CookieConfig) {
	sessions.SetCookie(w, accessToken, AccessTokenCookie, c)
	sessions.SetCookie(w, refreshToken, RefreshTokenCookie, c)
}

// ClearAuthCookies is a helper function to clear authentication cookies on a echo
// request to effectively logger out a user.
func ClearAuthCookies(w http.ResponseWriter) {
	sessions.RemoveCookie(w, AccessTokenCookie, *sessions.DefaultCookieConfig)
	sessions.RemoveCookie(w, RefreshTokenCookie, *sessions.DefaultCookieConfig)
}

// CookieExpired checks to see if a cookie is expired
func CookieExpired(cookie *http.Cookie) bool {
	// ensure cookie is not expired
	if !cookie.Expires.IsZero() && cookie.Expires.Before(time.Now()) {
		return true
	}

	// negative max age means to expire immediately
	if cookie.MaxAge < 0 {
		return true
	}

	return false
}

// GetImpersonationToken retrieves the impersonation token from the authorization header
// and parses it to return only the token component. If the header is missing or malformed,
// an error is returned.
func GetImpersonationToken(c echo.Context) (string, error) {
	if h := c.Request().Header.Get(Authorization); h != "" {
		match := impersonation.FindStringSubmatch(h)
		if len(match) == 2 { //nolint:mnd
			return match[1], nil
		}
	}

	return "", ErrNoAuthorization
}

// GetUserContextHeaders retrieves the user context headers used by system admins
// to specify which user context to operate under. Returns the user ID and organization ID
// from the X-User-ID and X-Organization-ID headers respectively.
func GetUserContextHeaders(c echo.Context) (userID, orgID string) {
	userID = c.Request().Header.Get(UserIDHeader)
	orgID = c.Request().Header.Get(OrganizationIDHeader)

	return userID, orgID
}

// HasUserContextHeaders checks if both required user context headers are present
func HasUserContextHeaders(c echo.Context) bool {
	userID, orgID := GetUserContextHeaders(c)

	return userID != "" && orgID != ""
}
