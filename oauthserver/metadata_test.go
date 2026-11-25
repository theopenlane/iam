package oauthserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theopenlane/httpsling"
)

func TestNewMetadata(t *testing.T) {
	tests := []struct {
		name       string
		issuer     string
		scopes     []string
		wantIssuer string
		wantScopes []string
	}{
		{name: "sorts and dedupes scopes", issuer: "https://api.example.com", scopes: []string{"risk:read", "control:read", "risk:read"}, wantIssuer: "https://api.example.com", wantScopes: []string{"control:read", "risk:read"}},
		{name: "trims trailing slash from issuer", issuer: "https://api.example.com/", scopes: []string{"control:read"}, wantIssuer: "https://api.example.com", wantScopes: []string{"control:read"}},
		{name: "no scopes", issuer: "https://api.example.com", wantIssuer: "https://api.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := NewMetadata(tc.issuer, tc.scopes)

			assert.Equal(t, tc.wantIssuer, m.Issuer)
			assert.Equal(t, tc.wantIssuer+AuthorizePath, m.AuthorizationEndpoint)
			assert.Equal(t, tc.wantIssuer+TokenPath, m.TokenEndpoint)
			assert.Equal(t, tc.wantIssuer+RevokePath, m.RevocationEndpoint)
			assert.Equal(t, tc.wantScopes, m.ScopesSupported)
			assert.Equal(t, []string{ResponseTypeCode}, m.ResponseTypesSupported)
			assert.Equal(t, []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken}, m.GrantTypesSupported)
			assert.Equal(t, []string{MethodS256}, m.CodeChallengeMethodsSupported)
			assert.Equal(t, []string{AuthMethodNone}, m.TokenEndpointAuthMethodsSupported)
			assert.Equal(t, []string{AuthMethodNone}, m.RevocationEndpointAuthMethodsSupported)
			assert.True(t, m.ClientIDMetadataDocumentSupported)
			assert.True(t, m.AuthorizationResponseIssParameterSupported)
		})
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		name  string
		scope string
		want  []string
	}{
		{name: "sorts and dedupes", scope: " b a  a ", want: []string{"a", "b"}},
		{name: "single scope", scope: "control:read", want: []string{"control:read"}},
		{name: "empty", scope: "", want: []string{}},
		{name: "whitespace only", scope: "   ", want: []string{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ParseScope(tc.scope))
		})
	}
}

func TestFormatScope(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		want   string
	}{
		{name: "joins with spaces", scopes: []string{"a", "b"}, want: "a b"},
		{name: "single scope", scopes: []string{"control:read"}, want: "control:read"},
		{name: "empty", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, FormatScope(tc.scopes))
		})
	}
}

func TestSingleValued(t *testing.T) {
	form := url.Values{
		"client_id": {"https://client.example/c.json"},
		"scope":     {"a", "b"},
	}

	tests := []struct {
		name    string
		names   []string
		wantErr bool
	}{
		{name: "single value", names: []string{"client_id"}},
		{name: "absent parameter", names: []string{"state"}},
		{name: "repeated parameter", names: []string{"client_id", "scope"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := SingleValued(form, tc.names...)
			if !tc.wantErr {
				assert.NoError(t, err)
				return
			}

			var oauthErr *OAuthError
			require.ErrorAs(t, err, &oauthErr)
			assert.Equal(t, ErrCodeInvalidRequest, oauthErr.Code)
		})
	}
}

func TestNoStore(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
	}{
		{name: "empty headers", header: http.Header{}},
		{name: "overwrites existing cache headers", header: http.Header{httpsling.HeaderCacheControl: {"max-age=60"}, httpsling.HeaderPragma: {"cache"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			NoStore(tc.header)

			assert.Equal(t, cacheControlNoStore, tc.header.Get(httpsling.HeaderCacheControl))
			assert.Equal(t, pragmaNoCache, tc.header.Get(httpsling.HeaderPragma))
		})
	}
}

func TestParseForm(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantErr     bool
		wantCode    string
	}{
		{name: "form body", contentType: httpsling.ContentTypeForm, body: "code=abc", wantCode: "abc"},
		{name: "form body with charset", contentType: httpsling.ContentTypeForm + "; charset=utf-8", body: "code=abc", wantCode: "abc"},
		{name: "json body", contentType: httpsling.ContentTypeJSON, body: `{"code":"abc"}`, wantErr: true},
		{name: "no content type", body: "code=abc", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, TokenPath, strings.NewReader(tc.body))
			req.Header.Set(httpsling.HeaderContentType, tc.contentType)

			form, oerr := ParseForm(req)
			if tc.wantErr {
				require.NotNil(t, oerr)
				assert.Equal(t, ErrCodeInvalidRequest, oerr.Code)

				return
			}

			require.Nil(t, oerr)
			assert.Equal(t, tc.wantCode, form.Get("code"))
		})
	}
}

func TestRedirectURL(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		params      url.Values
		want        string
		wantErr     bool
	}{
		{name: "adds params and issuer", redirectURI: "https://client.example/cb", params: url.Values{"code": {"abc"}, "state": {"xyz"}}, want: "https://client.example/cb?code=abc&iss=https%3A%2F%2Fapi.example.com&state=xyz"},
		{name: "keeps existing query", redirectURI: "https://client.example/cb?app=1", params: url.Values{"code": {"abc"}}, want: "https://client.example/cb?app=1&code=abc&iss=https%3A%2F%2Fapi.example.com"},
		{name: "skips empty params", redirectURI: "http://127.0.0.1:8080/cb", params: url.Values{"error": {ErrCodeAccessDenied}, "state": {""}}, want: "http://127.0.0.1:8080/cb?error=access_denied&iss=https%3A%2F%2Fapi.example.com"},
		{name: "unparsable redirect", redirectURI: "http://[::1", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RedirectURL(tc.redirectURI, "https://api.example.com", tc.params)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
