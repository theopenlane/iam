package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/auth"
)

const testJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZGF0dW0ubmV0IiwiYXVkIjoiaHR0cHM6Ly9kYXR1bS5uZXQiLCJzdWIiOiJVMVdNNHVGLTNxcGRsLWRtS0lISjQiLCJpYXQiOjE0NTg3ODU3OTYsImV4cCI6MTQ1ODg3MjE5Nn0.oXIjG4PauoHXEmZRDKRE018bkMv9rdZTjn563ujUh6o" //nolint:gosec

func newRequest() *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		cookie      *http.Cookie
		wantTks     string
		err         error
	}{
		{
			name:        "happy path from header",
			headerValue: "Bearer " + testJWT,
			wantTks:     testJWT,
		},
		{
			name: "happy path from cookie",
			cookie: &http.Cookie{ //nolint:gosec
				Name:  auth.AccessTokenCookie,
				Value: testJWT,
			},
			wantTks: testJWT,
		},
		{
			name:        "unparsable header",
			headerValue: "NotBearer " + testJWT,
			err:         auth.ErrParseBearer,
		},
		{
			name: "no header or cookie",
			err:  auth.ErrNoAuthorization,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest()

			if tc.headerValue != "" {
				req.Header.Set(auth.Authorization, tc.headerValue)
			}

			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}

			gotTks, err := auth.BearerToken(req)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Empty(t, gotTks)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.wantTks, gotTks)
		})
	}
}

func TestAPIKey(t *testing.T) {
	req := newRequest()
	req.Header.Set(auth.APIKeyHeader, "test_api_key")

	key, err := auth.APIKey(req)
	assert.NoError(t, err)
	assert.Equal(t, "test_api_key", key)

	_, err = auth.APIKey(newRequest())
	assert.ErrorIs(t, err, auth.ErrNoAPIKey)
}

func TestRefreshToken(t *testing.T) {
	tests := []struct {
		name    string
		cookie  *http.Cookie
		wantTks string
		err     error
	}{
		{
			name: "happy path from cookie",
			cookie: &http.Cookie{ //nolint:gosec
				Name:  auth.RefreshTokenCookie,
				Value: testJWT,
			},
			wantTks: testJWT,
		},
		{
			name: "no refresh cookie",
			cookie: &http.Cookie{ //nolint:gosec
				Name:  "another_cookie",
				Value: testJWT,
			},
			err: auth.ErrNoRefreshToken,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest()
			req.AddCookie(tc.cookie)

			gotTks, err := auth.RefreshToken(req)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				assert.Empty(t, gotTks)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.wantTks, gotTks)
		})
	}
}

func TestImpersonationToken(t *testing.T) {
	req := newRequest()
	req.Header.Set(auth.Authorization, auth.ImpersonationScheme+" "+testJWT)

	tks, err := auth.ImpersonationToken(req)
	assert.NoError(t, err)
	assert.Equal(t, testJWT, tks)

	req = newRequest()
	req.Header.Set(auth.Authorization, "Bearer "+testJWT)

	_, err = auth.ImpersonationToken(req)
	assert.ErrorIs(t, err, auth.ErrNoAuthorization)

	_, err = auth.ImpersonationToken(newRequest())
	assert.ErrorIs(t, err, auth.ErrNoAuthorization)
}

func TestUserContextHeaders(t *testing.T) {
	req := newRequest()
	req.Header.Set(auth.UserIDHeader, "user-id")
	req.Header.Set(auth.OrganizationIDHeader, "org-id")

	userID, orgID := auth.UserContextHeaders(req)
	assert.Equal(t, "user-id", userID)
	assert.Equal(t, "org-id", orgID)

	userID, orgID = auth.UserContextHeaders(newRequest())
	assert.Empty(t, userID)
	assert.Empty(t, orgID)
}

func TestOrganizationContextHeader(t *testing.T) {
	req := newRequest()
	req.Header.Set(auth.OrganizationIDHeader, "org-id")

	assert.Equal(t, "org-id", auth.OrganizationContextHeader(req))
	assert.Empty(t, auth.OrganizationContextHeader(newRequest()))
}
