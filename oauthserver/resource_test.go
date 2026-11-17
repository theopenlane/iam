package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveResourceMetadata(w http.ResponseWriter, r *http.Request, base string) {
	if r.URL.Path != protectedResourceMetadataPath+"/mcp" {
		http.NotFound(w, r)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"resource":         base + "/mcp",
		"scopes_supported": []string{"app:read", "control:write"},
	})
}

func TestResourceAllowed(t *testing.T) {
	allowed := []string{"https://mcp.example.com/mcp", "https://api.example.com"}

	tests := []struct {
		name     string
		resource string
		want     bool
	}{
		{name: "allowed resource", resource: "https://mcp.example.com/mcp", want: true},
		{name: "allowed origin", resource: "https://api.example.com", want: true},
		{name: "empty", resource: ""},
		{name: "trailing slash", resource: "https://mcp.example.com/mcp/"},
		{name: "allowed host with another path", resource: "https://mcp.example.com"},
		{name: "sibling host", resource: "https://other.example.com"},
		{name: "unrelated host", resource: "https://evil.test/mcp"},
		{name: "http version of an allowed resource", resource: "http://mcp.example.com/mcp"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResourceAllowed(allowed, tc.resource))
		})
	}
}

func TestResolveResource(t *testing.T) {
	single := []string{"https://mcp.example.com/mcp"}
	both := []string{"https://mcp.example.com/mcp", "https://api.example.com"}

	tests := []struct {
		name      string
		allowed   []string
		requested []string
		want      string
		wantErr   error
	}{
		{name: "defaults to the only allowed resource", allowed: single, want: "https://mcp.example.com/mcp"},
		{name: "requested resource is allowed", allowed: both, requested: []string{"https://api.example.com"}, want: "https://api.example.com"},
		{name: "none requested with several allowed", allowed: both, wantErr: ErrInvalidTarget},
		{name: "several requested", allowed: both, requested: []string{"https://api.example.com", "https://mcp.example.com/mcp"}, wantErr: ErrInvalidTarget},
		{name: "requested resource is not allowed", allowed: single, requested: []string{"https://evil.test/mcp"}, wantErr: ErrInvalidTarget},
		{name: "nothing allowed", wantErr: ErrInvalidTarget},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveResource(tc.allowed, tc.requested)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResourceMetadataURL(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		want     string
		wantErr  error
	}{
		{name: "resource with a path", resource: "https://mcp.example.com/mcp", want: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"},
		{name: "trailing slash", resource: "https://mcp.example.com/mcp/", want: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"},
		{name: "origin only", resource: "https://mcp.example.com", want: "https://mcp.example.com/.well-known/oauth-protected-resource"},
		{name: "query and fragment dropped", resource: "https://mcp.example.com/mcp?x=1#y", want: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"},
		{name: "relative", resource: "/relative", wantErr: ErrResourceMetadata},
		{name: "not a url", resource: "not a url", wantErr: ErrResourceMetadata},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResourceMetadataURL(tc.resource)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResourceScopes(t *testing.T) {
	refused := errors.New("refused by test dialer")

	tests := []struct {
		name     string
		resource string
		path     string
		dial     DialContextFunc
		handler  func(w http.ResponseWriter, r *http.Request, base string)
		want     []string
		wantErr  error
	}{
		{name: "scopes from metadata", path: "/mcp", handler: serveResourceMetadata, want: []string{"app:read", "control:write"}},
		{name: "metadata missing", path: "/other", handler: serveResourceMetadata, wantErr: ErrResourceMetadata},
		{
			name: "metadata names another resource",
			path: "/mcp",
			handler: func(w http.ResponseWriter, _ *http.Request, _ string) {
				_ = json.NewEncoder(w).Encode(map[string]any{"resource": "https://evil.test/mcp", "scopes_supported": []string{"app:read"}})
			},
			wantErr: ErrResourceMetadata,
		},
		{
			name: "server error",
			path: "/mcp",
			handler: func(w http.ResponseWriter, _ *http.Request, _ string) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantErr: ErrResourceMetadata,
		},
		{name: "not a url", resource: "not a url", handler: serveResourceMetadata, wantErr: ErrResourceMetadata},
		{name: "dial refused by the injected dialer", resource: "http://127.0.0.1:1/mcp", dial: refusingDialer(refused), handler: serveResourceMetadata, wantErr: refused},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newDocServer(t, tc.handler)

			resource := tc.resource
			if resource == "" {
				resource = srv.URL + tc.path
			}

			dial := tc.dial
			if dial == nil {
				dial = testDial
			}

			r, err := NewClientResolver(dial)
			require.NoError(t, err)
			t.Cleanup(r.Close)

			got, err := r.ResourceScopes(context.Background(), resource)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("caches scopes", func(t *testing.T) {
		var fetches atomic.Int32

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			fetches.Add(1)
			serveResourceMetadata(w, r, base)
		})

		r, err := NewClientResolver(testDial)
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.ResourceScopes(context.Background(), srv.URL+"/mcp")
		require.NoError(t, err)

		r.resources.Wait()

		for range 2 {
			_, err := r.ResourceScopes(context.Background(), srv.URL+"/mcp")
			require.NoError(t, err)
		}

		assert.Equal(t, int32(1), fetches.Load())
	})

	t.Run("rate limits fetches", func(t *testing.T) {
		srv := newDocServer(t, func(w http.ResponseWriter, _ *http.Request, _ string) {
			w.WriteHeader(http.StatusInternalServerError)
		})

		r, err := NewClientResolver(testDial, WithFetchRate(0, 1))
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.ResourceScopes(context.Background(), srv.URL+"/mcp")
		assert.ErrorIs(t, err, ErrResourceMetadata)

		_, err = r.ResourceScopes(context.Background(), srv.URL+"/mcp")
		assert.ErrorIs(t, err, ErrFetchRateLimited)
	})
}
