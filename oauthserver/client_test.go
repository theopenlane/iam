package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Yiling-J/theine-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/singleflight"
)

func newDocServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, base string)) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler(w, r, srv.URL) }))
	t.Cleanup(srv.Close)

	return srv
}

func validDoc(id string) Client {
	return Client{ID: id, Name: "Test Client", RedirectURIs: []string{"https://client.example/cb"}}
}

func serveValidDoc(w http.ResponseWriter, r *http.Request, base string) {
	_ = json.NewEncoder(w).Encode(validDoc(base + r.URL.Path))
}

func testDial(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

var errRefusedByDialer = errors.New("refused by test dialer")

func refusingDialer(calls *atomic.Int32) DialContextFunc {
	return func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)

		return nil, errRefusedByDialer
	}
}

func expireEntry[T any](t *testing.T, cache *theine.Cache[string, *cachedEntry[T]], key string) {
	t.Helper()

	cached, ok := cache.Get(key)
	require.True(t, ok)

	cache.SetWithTTL(key, &cachedEntry[T]{value: cached.value, fetchedAt: time.Now().Add(-metadataCacheTTL - time.Minute)}, 1, metadataMaxStale)
	cache.Wait()
}

func TestValidateRedirectURI(t *testing.T) {
	c := &Client{RedirectURIs: []string{
		"https://claude.ai/api/mcp/auth_callback",
		"http://localhost:33418/callback",
		"http://127.0.0.1/cb",
	}}

	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{name: "exact https match", uri: "https://claude.ai/api/mcp/auth_callback"},
		{name: "localhost on another port", uri: "http://localhost:5555/callback"},
		{name: "loopback ip on another port", uri: "http://127.0.0.1:9999/cb"},
		{name: "extra query parameter", uri: "https://claude.ai/api/mcp/auth_callback?x=1", wantErr: true},
		{name: "different host", uri: "https://evil.example/api/mcp/auth_callback", wantErr: true},
		{name: "localhost with another path", uri: "http://localhost:5555/other", wantErr: true},
		{name: "lookalike localhost host", uri: "http://localhost.evil.com/callback", wantErr: true},
		{name: "https localhost needs an exact match", uri: "https://localhost:5555/callback", wantErr: true},
		{name: "loopback with userinfo", uri: "http://evil@127.0.0.1:9999/cb", wantErr: true},
		{name: "loopback with a fragment", uri: "http://127.0.0.1:9999/cb#x", wantErr: true},
		{name: "loopback with an empty fragment", uri: "http://127.0.0.1:9999/cb#", wantErr: true},
		{name: "unparsable", uri: "http://[::1", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := c.ValidateRedirectURI(tc.uri)
			if tc.wantErr {
				assert.ErrorIs(t, err, ErrInvalidRedirectURI)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestValidRedirect(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "https", uri: "https://client.example/cb", want: true},
		{name: "http localhost", uri: "http://localhost:8080/cb", want: true},
		{name: "http loopback ip", uri: "http://127.0.0.1/cb", want: true},
		{name: "reverse-domain private-use scheme", uri: "com.example.app:/oauth/cb", want: true},
		{name: "http to a public host", uri: "http://client.example/cb"},
		{name: "javascript", uri: "javascript:alert(1)//"},
		{name: "mixed-case javascript", uri: "JavaScript:alert(1)"},
		{name: "data", uri: "data:text/html,hi"},
		{name: "vbscript", uri: "vbscript:x"},
		{name: "file", uri: "file:///etc/passwd"},
		{name: "private-use scheme without a dot", uri: "myapp:/cb"},
		{name: "fragment", uri: "https://client.example/cb#frag"},
		{name: "https without a host", uri: "https:///nohost"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ValidRedirect(tc.uri))
		})
	}
}

func TestClientValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Client)
		wantErr error
	}{
		{name: "valid document", mutate: func(*Client) {}},
		{name: "javascript redirect", mutate: func(c *Client) { c.RedirectURIs = []string{"javascript:alert(1)//"} }, wantErr: errInvalidRedirectScheme},
		{name: "cross-site client_uri", mutate: func(c *Client) { c.URI = "https://claude.ai" }, wantErr: errInvalidClientURI},
		{name: "javascript client_uri", mutate: func(c *Client) { c.URI = "javascript:alert(1)" }, wantErr: errInvalidClientURI},
		{name: "http logo", mutate: func(c *Client) { c.LogoURI = "http://cdn.example/logo.png" }, wantErr: errInvalidLogoURI},
		{name: "control characters in name", mutate: func(c *Client) { c.Name = "Claude" + string(rune(0x202E)) + "\n" }, wantErr: errInvalidClientName},
		{name: "name too long", mutate: func(c *Client) { c.Name = strings.Repeat("x", 101) }, wantErr: errInvalidClientName},
		{name: "blank name", mutate: func(c *Client) { c.Name = "   " }, wantErr: errInvalidClientName},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Client{
				ID:           "https://client.example/oauth/client.json",
				Name:         "Example",
				URI:          "https://client.example",
				LogoURI:      "https://cdn.example/logo.png",
				RedirectURIs: []string{"https://client.example/cb"},
			}
			tc.mutate(&c)

			err := c.validate()
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestIsHTTPLoopback(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "localhost", uri: "http://localhost:8080/cb", want: true},
		{name: "ipv4 loopback", uri: "http://127.0.0.1/cb", want: true},
		{name: "ipv6 loopback", uri: "http://[::1]:9000/cb", want: true},
		{name: "https localhost", uri: "https://localhost/cb"},
		{name: "public host", uri: "http://client.example/cb"},
		{name: "lookalike host", uri: "http://localhost.evil.com/cb"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.uri)
			require.NoError(t, err)

			assert.Equal(t, tc.want, isHTTPLoopback(u))
		})
	}
}

func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want bool
	}{
		{name: "https with host", uri: "https://cdn.example/logo.png", want: true},
		{name: "http", uri: "http://cdn.example/logo.png"},
		{name: "https without host", uri: "https:///logo.png"},
		{name: "unparsable", uri: "https://[::1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isHTTPS(tc.uri))
		})
	}
}

func TestSameHost(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "same host", a: "https://client.example", b: "https://client.example/oauth/client.json", want: true},
		{name: "case insensitive", a: "https://Client.Example", b: "https://client.example/c.json", want: true},
		{name: "different host", a: "https://claude.ai", b: "https://client.example/c.json"},
		{name: "different scheme", a: "http://client.example", b: "https://client.example/c.json"},
		{name: "different port", a: "https://client.example:8443", b: "https://client.example/c.json"},
		{name: "no scheme", a: "client.example", b: "client.example"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sameHost(tc.a, tc.b))
		})
	}
}

func TestIsHiddenRune(t *testing.T) {
	tests := []struct {
		name string
		r    rune
		want bool
	}{
		{name: "letter", r: 'a'},
		{name: "space", r: ' '},
		{name: "newline", r: '\n', want: true},
		{name: "right-to-left override", r: rune(0x202E), want: true},
		{name: "zero-width joiner", r: rune(0x200D), want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isHiddenRune(tc.r))
		})
	}
}

func TestTransientStatus(t *testing.T) {
	tests := []struct {
		name string
		code int
		want bool
	}{
		{name: "too many requests", code: http.StatusTooManyRequests, want: true},
		{name: "server error", code: http.StatusInternalServerError, want: true},
		{name: "service unavailable", code: http.StatusServiceUnavailable, want: true},
		{name: "not found", code: http.StatusNotFound},
		{name: "forbidden", code: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, transientStatus(tc.code))
		})
	}
}

func TestCachedEntryFresh(t *testing.T) {
	tests := []struct {
		name string
		age  time.Duration
		want bool
	}{
		{name: "just fetched", age: 0, want: true},
		{name: "inside the ttl", age: metadataCacheTTL - time.Minute, want: true},
		{name: "past the ttl", age: metadataCacheTTL + time.Minute},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := &cachedEntry[string]{value: "doc", fetchedAt: time.Now().Add(-tc.age)}

			assert.Equal(t, tc.want, entry.fresh())
		})
	}
}

func TestCloneClient(t *testing.T) {
	tests := []struct {
		name   string
		client *Client
	}{
		{name: "with redirect uris", client: &Client{ID: "https://client.example/c.json", Name: "Example", RedirectURIs: []string{"https://client.example/cb"}}},
		{name: "without redirect uris", client: &Client{ID: "https://client.example/c.json", Name: "Example"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clone := cloneClient(tc.client)
			require.Equal(t, tc.client, clone)

			clone.Name = "Changed"
			if len(clone.RedirectURIs) > 0 {
				clone.RedirectURIs[0] = "https://evil.example/cb"
				assert.Equal(t, "https://client.example/cb", tc.client.RedirectURIs[0])
			}

			assert.Equal(t, "Example", tc.client.Name)
		})
	}
}

func TestShare(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
		delay   time.Duration
		value   string
		err     error
		want    string
		wantErr error
	}{
		{name: "returns the fetched value", timeout: time.Second, value: "doc", want: "doc"},
		{name: "returns the fetch error", timeout: time.Second, err: errRefusedByDialer, wantErr: errRefusedByDialer},
		{name: "stops waiting when the context ends", timeout: 10 * time.Millisecond, delay: 200 * time.Millisecond, value: "late", wantErr: context.DeadlineExceeded},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var group singleflight.Group

			ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
			t.Cleanup(cancel)

			got, err := share(ctx, &group, tc.name, func() (string, error) {
				time.Sleep(tc.delay)

				return tc.value, tc.err
			})
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIsDotSegment(t *testing.T) {
	tests := []struct {
		name    string
		segment string
		want    bool
	}{
		{name: "dot", segment: ".", want: true},
		{name: "dot dot", segment: "..", want: true},
		{name: "empty", segment: ""},
		{name: "name with dots", segment: "client.json"},
		{name: "three dots", segment: "..."},
		{name: "dot dot with a parameter", segment: "..;x=1", want: true},
		{name: "dot with a parameter", segment: ".;", want: true},
		{name: "name with a parameter", segment: "client;v=1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isDotSegment(tc.segment))
		})
	}
}

func TestFetchDomain(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "subdomain", target: "https://a.attacker.example/x", want: "attacker.example"},
		{name: "deep subdomain", target: "https://x.y.attacker.example/x", want: "attacker.example"},
		{name: "registrable domain", target: "https://claude.ai/oauth/client.json", want: "claude.ai"},
		{name: "multi-label public suffix", target: "https://app.example.co.uk/c", want: "example.co.uk"},
		{name: "hosting public suffix", target: "https://someone.github.io/c", want: "someone.github.io"},
		{name: "case insensitive", target: "https://A.Attacker.Example/x", want: "attacker.example"},
		{name: "ipv4", target: "http://127.0.0.1:8080/c", want: "127.0.0.1"},
		{name: "ipv6", target: "http://[::1]:8080/c", want: "::1"},
		{name: "single-label host", target: "http://localhost:8080/c", want: "localhost"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fetchDomain(tc.target))
		})
	}
}

func TestDomainLimiter(t *testing.T) {
	r, err := NewClientResolver(testDial)
	require.NoError(t, err)
	t.Cleanup(r.Close)

	tests := []struct {
		name     string
		domain   string
		other    string
		wantSame bool
	}{
		{name: "same domain shares a limiter", domain: "attacker.example", other: "attacker.example", wantSame: true},
		{name: "different domains get their own", domain: "attacker.example", other: "claude.ai"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantSame, r.domainLimiter(tc.domain) == r.domainLimiter(tc.other))
		})
	}
}

func TestAllowFetch(t *testing.T) {
	r, err := NewClientResolver(testDial, WithFetchRate(0, 1), WithGlobalFetchRate(0, 3))
	require.NoError(t, err)
	t.Cleanup(r.Close)

	steps := []struct {
		name   string
		target string
		want   bool
	}{
		{name: "first fetch for a domain", target: "https://a.attacker.example/x", want: true},
		{name: "another subdomain shares the domain budget", target: "https://b.attacker.example/y"},
		{name: "other domains keep their own budget", target: "https://claude.ai/oauth/client.json", want: true},
		{name: "global budget still allows a third domain", target: "https://client.example/c", want: true},
		{name: "global cap stops a fourth domain", target: "https://another.example/c"},
	}

	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			assert.Equal(t, step.want, r.allowFetch(step.target))
		})
	}
}

func TestNewClientResolver(t *testing.T) {
	tests := []struct {
		name    string
		dial    DialContextFunc
		opts    []ResolverOption
		wantErr error
	}{
		{name: "nil dialer", wantErr: ErrDialerRequired},
		{name: "dialer with defaults", dial: testDial},
		{name: "non-positive cache size falls back to the default", dial: testDial, opts: []ResolverOption{WithCacheSize(0)}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewClientResolver(tc.dial, tc.opts...)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			t.Cleanup(r.Close)

			hc, ok := r.requester.Doer.(*http.Client)
			require.True(t, ok)
			assert.Equal(t, metadataTimeout, hc.Timeout)
			assert.ErrorIs(t, hc.CheckRedirect(nil, nil), http.ErrUseLastResponse)

			transport, ok := hc.Transport.(*http.Transport)
			require.True(t, ok)
			assert.Nil(t, transport.Proxy)
			assert.NotNil(t, transport.DialContext)
		})
	}
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		path     string
		opts     []ResolverOption
		handler  func(w http.ResponseWriter, r *http.Request, base string)
		wantErr  error
		wantName string
	}{
		{
			name:     "valid document",
			path:     "/oauth/client.json",
			opts:     []ResolverOption{WithInsecureClientIDs()},
			handler:  serveValidDoc,
			wantName: "Test Client",
		},
		{
			name:    "http client id without insecure option",
			path:    "/oauth/client.json",
			handler: serveValidDoc,
			wantErr: ErrInvalidClientID,
		},
		{
			name: "redirect is not followed",
			path: "/redirect.json",
			opts: []ResolverOption{WithInsecureClientIDs()},
			handler: func(w http.ResponseWriter, r *http.Request, _ string) {
				http.Redirect(w, r, "/oauth/client.json", http.StatusFound)
			},
			wantErr: ErrClientMetadata,
		},
		{
			name: "document names another client",
			path: "/oauth/client.json",
			opts: []ResolverOption{WithInsecureClientIDs()},
			handler: func(w http.ResponseWriter, _ *http.Request, _ string) {
				_ = json.NewEncoder(w).Encode(validDoc("https://someone-else.example/client.json"))
			},
			wantErr: ErrClientMetadata,
		},
		{
			name: "confidential client",
			path: "/oauth/client.json",
			opts: []ResolverOption{WithInsecureClientIDs()},
			handler: func(w http.ResponseWriter, r *http.Request, base string) {
				doc := validDoc(base + r.URL.Path)
				doc.TokenEndpointAuthMethod = "client_secret_basic"
				_ = json.NewEncoder(w).Encode(doc)
			},
			wantErr: ErrClientMetadata,
		},
		{
			name: "missing redirect uris",
			path: "/oauth/client.json",
			opts: []ResolverOption{WithInsecureClientIDs()},
			handler: func(w http.ResponseWriter, r *http.Request, base string) {
				doc := validDoc(base + r.URL.Path)
				doc.RedirectURIs = nil
				_ = json.NewEncoder(w).Encode(doc)
			},
			wantErr: ErrClientMetadata,
		},
		{
			name: "document not found",
			path: "/oauth/client.json",
			opts: []ResolverOption{WithInsecureClientIDs()},
			handler: func(w http.ResponseWriter, r *http.Request, _ string) {
				http.NotFound(w, r)
			},
			wantErr: ErrClientMetadata,
		},
		{
			name: "oversized document",
			path: "/oauth/client.json",
			opts: []ResolverOption{WithInsecureClientIDs()},
			handler: func(w http.ResponseWriter, r *http.Request, base string) {
				doc := validDoc(base + r.URL.Path)
				doc.LogoURI = "https://cdn.example/" + strings.Repeat("a", maxMetadataBytes)
				_ = json.NewEncoder(w).Encode(doc)
			},
			wantErr: ErrClientMetadata,
		},
		{name: "not a url", clientID: "not a url", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "origin without path", clientID: "https://example.com", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "root path", clientID: "https://example.com/", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "userinfo", clientID: "https://user@example.com/c", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "backslash", clientID: "https://example.com/a%5Cb", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "empty segment", clientID: "https://example.com//c", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "dot-dot segment with a parameter", clientID: "https://example.com/..;/c", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "fragment", clientID: "https://example.com/c#frag", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "dot segment", clientID: "https://example.com/./c", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "dot-dot segment", clientID: "https://example.com/a/../c", handler: serveValidDoc, wantErr: ErrInvalidClientID},
		{name: "encoded dot-dot segment", clientID: "https://example.com/%2e%2e/c", handler: serveValidDoc, wantErr: ErrInvalidClientID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := newDocServer(t, tc.handler)

			clientID := tc.clientID
			if clientID == "" {
				clientID = srv.URL + tc.path
			}

			r, err := NewClientResolver(testDial, tc.opts...)
			require.NoError(t, err)
			t.Cleanup(r.Close)

			c, err := r.Resolve(context.Background(), clientID)
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantName, c.Name)
		})
	}

	t.Run("uses the injected dialer", func(t *testing.T) {
		var calls atomic.Int32

		r, err := NewClientResolver(refusingDialer(&calls), WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.Resolve(context.Background(), "http://127.0.0.1:1/client.json")
		assert.ErrorIs(t, err, ErrClientMetadata)
		assert.NotErrorIs(t, err, errRefusedByDialer)
		assert.Positive(t, calls.Load())
	})

	t.Run("returns a copy of the cached client", func(t *testing.T) {
		srv := newDocServer(t, serveValidDoc)

		r, err := NewClientResolver(testDial, WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		first, err := r.Resolve(context.Background(), srv.URL+"/client.json")
		require.NoError(t, err)

		first.Name = "Changed"
		first.RedirectURIs[0] = "https://evil.example/cb"

		second, err := r.Resolve(context.Background(), srv.URL+"/client.json")
		require.NoError(t, err)
		assert.Equal(t, "Test Client", second.Name)
		assert.Equal(t, []string{"https://client.example/cb"}, second.RedirectURIs)
	})

	t.Run("caches failed client ids", func(t *testing.T) {
		var fetches atomic.Int32

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, _ string) {
			fetches.Add(1)
			http.NotFound(w, r)
		})

		r, err := NewClientResolver(testDial, WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		for range 3 {
			_, err := r.Resolve(context.Background(), srv.URL+"/client.json")
			assert.ErrorIs(t, err, ErrClientMetadata)
		}

		assert.Equal(t, int32(1), fetches.Load())
	})

	t.Run("stops waiting when the caller's context ends", func(t *testing.T) {
		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			time.Sleep(200 * time.Millisecond)
			serveValidDoc(w, r, base)
		})

		r, err := NewClientResolver(testDial, WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		t.Cleanup(cancel)

		_, err = r.Resolve(ctx, srv.URL+"/client.json")
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	})

	t.Run("caches documents", func(t *testing.T) {
		var fetches atomic.Int32

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			fetches.Add(1)
			serveValidDoc(w, r, base)
		})

		r, err := NewClientResolver(testDial, WithInsecureClientIDs(), WithCacheSize(10))
		require.NoError(t, err)
		t.Cleanup(r.Close)

		for range 3 {
			_, err := r.Resolve(context.Background(), srv.URL+"/client.json")
			require.NoError(t, err)
		}

		assert.Equal(t, int32(1), fetches.Load())
	})

	t.Run("shares concurrent fetches", func(t *testing.T) {
		var fetches atomic.Int32

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			fetches.Add(1)
			time.Sleep(100 * time.Millisecond)
			serveValidDoc(w, r, base)
		})

		r, err := NewClientResolver(testDial, WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		var wg sync.WaitGroup

		for range 10 {
			wg.Go(func() {
				_, err := r.Resolve(context.Background(), srv.URL+"/client.json")
				assert.NoError(t, err)
			})
		}

		wg.Wait()

		assert.Equal(t, int32(1), fetches.Load())
	})

	t.Run("rate limits fetches", func(t *testing.T) {
		srv := newDocServer(t, serveValidDoc)

		r, err := NewClientResolver(testDial, WithInsecureClientIDs(), WithFetchRate(0, 1))
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.Resolve(context.Background(), srv.URL+"/first.json")
		require.NoError(t, err)

		_, err = r.Resolve(context.Background(), srv.URL+"/second.json")
		assert.ErrorIs(t, err, ErrFetchRateLimited)

		_, err = r.Resolve(context.Background(), srv.URL+"/first.json")
		assert.NoError(t, err)
	})

	t.Run("serves a stale document while its host is down", func(t *testing.T) {
		var down atomic.Bool

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			if down.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}

			serveValidDoc(w, r, base)
		})

		clientID := srv.URL + "/client.json"

		r, err := NewClientResolver(testDial, WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.Resolve(context.Background(), clientID)
		require.NoError(t, err)

		expireEntry(t, r.clients, clientID)
		down.Store(true)

		c, err := r.Resolve(context.Background(), clientID)
		require.NoError(t, err)
		assert.Equal(t, "Test Client", c.Name)
	})

	t.Run("re-fetches a known client without spending the budget", func(t *testing.T) {
		var fetches atomic.Int32

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			fetches.Add(1)
			serveValidDoc(w, r, base)
		})

		clientID := srv.URL + "/client.json"

		r, err := NewClientResolver(testDial, WithInsecureClientIDs(), WithFetchRate(0, 1))
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.Resolve(context.Background(), clientID)
		require.NoError(t, err)

		_, err = r.Resolve(context.Background(), srv.URL+"/other.json")
		require.ErrorIs(t, err, ErrFetchRateLimited)

		expireEntry(t, r.clients, clientID)

		_, err = r.Resolve(context.Background(), clientID)
		require.NoError(t, err)
		assert.Equal(t, int32(2), fetches.Load())
	})

	t.Run("evicts a document that becomes invalid", func(t *testing.T) {
		var invalid atomic.Bool

		srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request, base string) {
			doc := validDoc(base + r.URL.Path)
			if invalid.Load() {
				doc.Name = ""
			}

			_ = json.NewEncoder(w).Encode(doc)
		})

		clientID := srv.URL + "/client.json"

		r, err := NewClientResolver(testDial, WithInsecureClientIDs())
		require.NoError(t, err)
		t.Cleanup(r.Close)

		_, err = r.Resolve(context.Background(), clientID)
		require.NoError(t, err)

		expireEntry(t, r.clients, clientID)
		invalid.Store(true)

		_, err = r.Resolve(context.Background(), clientID)
		assert.ErrorIs(t, err, ErrClientMetadata)

		r.clients.Wait()

		_, ok := r.clients.Get(clientID)
		assert.False(t, ok)
	})
}
