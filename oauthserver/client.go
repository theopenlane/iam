package oauthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Yiling-J/theine-go"
	"github.com/theopenlane/httpsling"
	"github.com/theopenlane/httpsling/httpclient"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

const (
	// maxMetadataBytes caps how much of a metadata document is read
	maxMetadataBytes = 64 << 10
	// metadataTimeout bounds each metadata fetch
	metadataTimeout = 5 * time.Second
	// metadataCacheTTL is how long a fetched document is used before it is fetched again
	metadataCacheTTL = 10 * time.Minute
	// defaultCacheSize bounds each metadata cache, since anyone can make the server fetch a client_id URL
	defaultCacheSize = 1024
	// metadataMaxStale is how long past its TTL a document is still served while its host is down
	metadataMaxStale = time.Hour
	// defaultFetchRate is how many metadata fetches per second each registrable domain is allowed
	defaultFetchRate = rate.Limit(1)
	// defaultFetchBurst is how many fetches to one registrable domain may run back to back
	defaultFetchBurst = 5
	// defaultGlobalFetchRate is how many metadata fetches per second are allowed across all domains
	defaultGlobalFetchRate = rate.Limit(20)
	// defaultGlobalFetchBurst is how many fetches across all domains may run back to back
	defaultGlobalFetchBurst = 50
	// limiterCacheSize bounds how many per-domain fetch limiters are kept
	limiterCacheSize = 10000
	// schemeHTTPS is the https URL scheme
	schemeHTTPS = "https"
	// schemeHTTP is the http URL scheme, only allowed for loopback hosts and local development
	schemeHTTP = "http"
	// localhostName is the loopback hostname accepted alongside loopback IP addresses
	localhostName = "localhost"
)

// Client is a resolved OAuth client
type Client struct {
	// ID is the client_id, which is the URL of its metadata document
	ID string `json:"client_id"`
	// Name is shown to the user on the consent screen
	Name string `json:"client_name"`
	// URI is the client's home page
	URI string `json:"client_uri,omitempty"`
	// LogoURI is shown on the consent screen
	LogoURI string `json:"logo_uri,omitempty"`
	// RedirectURIs are the allowed redirect URIs
	RedirectURIs []string `json:"redirect_uris"`
	// TokenEndpointAuthMethod must be "none": only public clients are supported
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
}

// ClientResolver loads and caches client metadata documents and protected resource metadata
type ClientResolver struct {
	// requester sends metadata fetches through the injected dialer, without following redirects
	requester *httpsling.Requester
	// allowInsecure accepts http client IDs for local development
	allowInsecure bool
	// clients caches resolved clients by client_id
	clients *theine.Cache[string, *cachedClient]
	// resources caches each resource's scopes_supported
	resources *theine.Cache[string, []string]
	// group shares one fetch between concurrent requests for the same document
	group singleflight.Group
	// domainLimiters holds one fetch limiter per registrable domain, so one domain can't spend another's budget
	domainLimiters *theine.Cache[string, *rate.Limiter]
	// domainLimiterMu serializes creating a domain's limiter so concurrent fetches share one
	domainLimiterMu sync.Mutex
	// globalLimiter caps outbound metadata fetches across all domains
	globalLimiter *rate.Limiter
	// fetchRate is the per-domain fetch rate new limiters get
	fetchRate rate.Limit
	// fetchBurst is the per-domain burst new limiters get
	fetchBurst int
}

// cachedClient is a resolved client and when its document was fetched
type cachedClient struct {
	// client is the resolved client
	client *Client
	// fetchedAt is when the document was fetched, used to decide when to fetch it again
	fetchedAt time.Time
}

// ResolverOption configures a ClientResolver
type ResolverOption func(*resolverOptions)

// resolverOptions holds the settings ResolverOptions apply
type resolverOptions struct {
	// allowInsecure accepts http client IDs
	allowInsecure bool
	// cacheSize bounds each metadata cache
	cacheSize int
	// fetchRate is the allowed metadata fetches per second for each registrable domain
	fetchRate rate.Limit
	// fetchBurst is how many fetches to one registrable domain may run back to back
	fetchBurst int
	// globalFetchRate is the allowed metadata fetches per second across all domains
	globalFetchRate rate.Limit
	// globalFetchBurst is how many fetches across all domains may run back to back
	globalFetchBurst int
}

// WithInsecureClientIDs accepts http client IDs for local development without changing which addresses the dialer reaches
func WithInsecureClientIDs() ResolverOption {
	return func(o *resolverOptions) { o.allowInsecure = true }
}

// WithCacheSize bounds each metadata cache to n entries (default 1024)
func WithCacheSize(n int) ResolverOption {
	return func(o *resolverOptions) { o.cacheSize = n }
}

// WithFetchRate limits metadata fetches to each registrable domain to r per second with bursts of burst (default 1/s, burst 5)
func WithFetchRate(r rate.Limit, burst int) ResolverOption {
	return func(o *resolverOptions) {
		o.fetchRate = r
		o.fetchBurst = burst
	}
}

// WithGlobalFetchRate limits metadata fetches across all domains to r per second with bursts of burst (default 20/s, burst 50)
func WithGlobalFetchRate(r rate.Limit, burst int) ResolverOption {
	return func(o *resolverOptions) {
		o.globalFetchRate = r
		o.globalFetchBurst = burst
	}
}

// DialContextFunc dials a network address, matching http.Transport.DialContext
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// NewClientResolver returns a resolver whose metadata fetches connect through dial, which must refuse non-public addresses
func NewClientResolver(dial DialContextFunc, opts ...ResolverOption) (*ClientResolver, error) {
	if dial == nil {
		return nil, ErrDialerRequired
	}

	o := resolverOptions{
		cacheSize:        defaultCacheSize,
		fetchRate:        defaultFetchRate,
		fetchBurst:       defaultFetchBurst,
		globalFetchRate:  defaultGlobalFetchRate,
		globalFetchBurst: defaultGlobalFetchBurst,
	}
	for _, opt := range opts {
		opt(&o)
	}

	if o.cacheSize <= 0 {
		o.cacheSize = defaultCacheSize
	}

	requester, err := httpsling.New(
		httpsling.Client(dialThrough(dial), httpclient.NoRedirects(), httpclient.Timeout(metadataTimeout)),
		httpsling.Accept(httpsling.ContentTypeJSON),
	)
	if err != nil {
		return nil, err
	}

	clients, err := theine.NewBuilder[string, *cachedClient](int64(o.cacheSize)).Build()
	if err != nil {
		return nil, err
	}

	resources, err := theine.NewBuilder[string, []string](int64(o.cacheSize)).Build()
	if err != nil {
		clients.Close()

		return nil, err
	}

	domainLimiters, err := theine.NewBuilder[string, *rate.Limiter](limiterCacheSize).Build()
	if err != nil {
		clients.Close()
		resources.Close()

		return nil, err
	}

	return &ClientResolver{
		requester:      requester,
		allowInsecure:  o.allowInsecure,
		clients:        clients,
		resources:      resources,
		domainLimiters: domainLimiters,
		globalLimiter:  rate.NewLimiter(o.globalFetchRate, o.globalFetchBurst),
		fetchRate:      o.fetchRate,
		fetchBurst:     o.fetchBurst,
	}, nil
}

// dialThrough connects through dial with no proxy, since a proxy would make the connection instead and skip dial's address checks
func dialThrough(dial DialContextFunc) httpclient.Option {
	return httpclient.TransportOption(func(t *http.Transport) error {
		t.Proxy = nil
		t.DialContext = dial

		return nil
	})
}

// Close stops the resolver's cache maintenance
func (r *ClientResolver) Close() {
	r.clients.Close()
	r.resources.Close()
	r.domainLimiters.Close()
}

// allowFetch spends one fetch from target's registrable domain budget and then from the global budget
func (r *ClientResolver) allowFetch(target string) bool {
	return r.domainLimiter(fetchDomain(target)).Allow() && r.globalLimiter.Allow()
}

// domainLimiter returns the fetch limiter for a registrable domain, creating it on first use
func (r *ClientResolver) domainLimiter(domain string) *rate.Limiter {
	r.domainLimiterMu.Lock()
	defer r.domainLimiterMu.Unlock()

	if limiter, ok := r.domainLimiters.Get(domain); ok {
		return limiter
	}

	limiter := rate.NewLimiter(r.fetchRate, r.fetchBurst)
	r.domainLimiters.Set(domain, limiter, 1)

	return limiter
}

// fetchDomain returns the registrable domain of target's host, or the host itself for IP addresses and single-label hosts
func fetchDomain(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}

	host := strings.ToLower(u.Hostname())
	if net.ParseIP(host) != nil {
		return host
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}

	return domain
}

// Resolve returns the client for a client_id, fetching its metadata document if needed
func (r *ClientResolver) Resolve(ctx context.Context, clientID string) (*Client, error) {
	if err := r.validateClientID(clientID); err != nil {
		return nil, err
	}

	if cached, ok := r.clients.Get(clientID); ok && time.Since(cached.fetchedAt) < metadataCacheTTL {
		return cached.client, nil
	}

	v, err, _ := r.group.Do(clientID, func() (any, error) { return r.refresh(ctx, clientID) })
	if err != nil {
		return nil, err
	}

	return v.(*Client), nil
}

// refresh fetches a document, serving a stale copy only while the client's host is down
func (r *ClientResolver) refresh(ctx context.Context, clientID string) (*Client, error) {
	cached, hasCached := r.clients.Get(clientID)
	if hasCached && time.Since(cached.fetchedAt) < metadataCacheTTL {
		return cached.client, nil
	}

	// a spent budget never serves a stale copy, so draining it can't keep an outdated document in use
	if !r.allowFetch(clientID) {
		return nil, ErrFetchRateLimited
	}

	// the fetch is shared by every waiting caller, so one caller cancelling must not fail the rest
	client, err := r.fetch(context.WithoutCancel(ctx), clientID)
	if err != nil {
		if hasCached && errors.Is(err, errMetadataUnavailable) {
			return cached.client, nil
		}

		r.clients.Delete(clientID)

		return nil, err
	}

	r.clients.SetWithTTL(clientID, &cachedClient{client: client, fetchedAt: time.Now()}, 1, metadataCacheTTL+metadataMaxStale)

	return client, nil
}

// validateClientID checks that a client_id is an https URL with a path and no userinfo or fragment
func (r *ClientResolver) validateClientID(clientID string) error {
	u, err := url.Parse(clientID)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return ErrInvalidClientID
	}

	if u.Scheme != schemeHTTPS && (!r.allowInsecure || u.Scheme != schemeHTTP) {
		return ErrInvalidClientID
	}

	// the spec requires a path component so a whole origin can't be claimed as one client
	if u.Path == "" || u.Path == "/" {
		return ErrInvalidClientID
	}

	// the spec also forbids dot segments, which could make one document claim another path's client ID
	if slices.ContainsFunc(strings.Split(u.Path, "/"), isDotSegment) {
		return ErrInvalidClientID
	}

	return nil
}

// isDotSegment reports whether a path segment is "." or ".."
func isDotSegment(segment string) bool {
	return segment == "." || segment == ".."
}

// fetch loads and validates the metadata document served at clientID
func (r *ClientResolver) fetch(ctx context.Context, clientID string) (*Client, error) {
	var c Client
	if err := r.getJSON(ctx, clientID, &c); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadata, err)
	}

	// the document must describe itself, otherwise any URL could impersonate any client
	if c.ID != clientID {
		return nil, fmt.Errorf("%w: client_id in document does not match its URL", ErrClientMetadata)
	}

	if strings.TrimSpace(c.Name) == "" || len(c.RedirectURIs) == 0 {
		return nil, fmt.Errorf("%w: client_name and redirect_uris are required", ErrClientMetadata)
	}

	if c.TokenEndpointAuthMethod != "" && c.TokenEndpointAuthMethod != AuthMethodNone {
		return nil, fmt.Errorf("%w: only public clients (token_endpoint_auth_method=none) are supported", ErrClientMetadata)
	}

	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrClientMetadata, err)
	}

	return &c, nil
}

// getJSON fetches target and decodes at most maxMetadataBytes of its JSON body into into
func (r *ClientResolver) getJSON(ctx context.Context, target string, into any) error {
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()

	resp, err := r.requester.SendWithContext(ctx, httpsling.Get(), httpsling.URL(target))
	if err != nil {
		return fmt.Errorf("%w: %w", errMetadataUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if transientStatus(resp.StatusCode) {
			return fmt.Errorf("%w: %w: %s returned %s", errMetadataUnavailable, errUnexpectedStatus, target, resp.Status)
		}

		return fmt.Errorf("%w: %s returned %s", errUnexpectedStatus, target, resp.Status)
	}

	// httpsling's Receive reads the whole body, so decode here to keep the size cap on attacker-hosted documents
	return json.NewDecoder(io.LimitReader(resp.Body, maxMetadataBytes)).Decode(into)
}

// transientStatus reports responses that suggest the host is briefly unavailable rather than the document being gone
func transientStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= http.StatusInternalServerError
}

// maxClientNameLength is the longest client_name shown on the consent screen
const maxClientNameLength = 100

// validate constrains the attacker-controlled fields a metadata document shows to users or redirects to
func (c *Client) validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if utf8.RuneCountInString(c.Name) > maxClientNameLength || strings.ContainsFunc(c.Name, isHiddenRune) || c.Name == "" {
		return errInvalidClientName
	}

	for _, uri := range c.RedirectURIs {
		if !validRedirectScheme(uri) {
			return fmt.Errorf("%w: %q", errInvalidRedirectScheme, uri)
		}
	}

	// client_uri is shown as who is asking, so it must be the same site as client_id
	if c.URI != "" && !sameHost(c.URI, c.ID) {
		return errInvalidClientURI
	}

	if c.LogoURI != "" && !isHTTPS(c.LogoURI) {
		return errInvalidLogoURI
	}

	return nil
}

// validRedirectScheme allows https, loopback http and reverse-domain private-use schemes (RFC 8252), never a scheme a browser could execute
func validRedirectScheme(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" {
		return false
	}

	switch strings.ToLower(u.Scheme) {
	case schemeHTTPS:
		return u.Host != ""
	case schemeHTTP:
		return isHTTPLoopback(u)
	case "", "javascript", "data", "vbscript", "file", "blob", "about", "ftp", "ws", "wss":
		return false
	default:
		// private-use schemes must be reverse-domain, e.g. com.example.app:/callback
		return strings.Contains(u.Scheme, ".")
	}
}

// isHTTPS reports whether raw is an https URL with a host
func isHTTPS(raw string) bool {
	u, err := url.Parse(raw)

	return err == nil && u.Scheme == schemeHTTPS && u.Host != ""
}

// sameHost reports whether a and b share a scheme and host
func sameHost(a, b string) bool {
	ua, errA := url.Parse(a)
	ub, errB := url.Parse(b)

	return errA == nil && errB == nil && ua.Scheme == ub.Scheme &&
		ua.Scheme != "" && strings.EqualFold(ua.Host, ub.Host)
}

// isHiddenRune reports control and invisible formatting characters that can disguise a client name
func isHiddenRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
}

// ValidRedirect reports whether a redirect URI is safe to send a browser to
func ValidRedirect(raw string) bool {
	return validRedirectScheme(raw)
}

// ValidateRedirectURI checks redirectURI against the registered list, ignoring the port only for loopback http (RFC 8252 §7.3)
func (c *Client) ValidateRedirectURI(redirectURI string) error {
	if slices.Contains(c.RedirectURIs, redirectURI) {
		return nil
	}

	req, err := url.Parse(redirectURI)
	if err != nil || !isHTTPLoopback(req) {
		return ErrInvalidRedirectURI
	}

	for _, registered := range c.RedirectURIs {
		reg, err := url.Parse(registered)
		if err != nil || !isHTTPLoopback(reg) {
			continue
		}

		if reg.Scheme == req.Scheme && reg.Hostname() == req.Hostname() &&
			reg.Path == req.Path && reg.RawQuery == req.RawQuery {
			return nil
		}
	}

	return ErrInvalidRedirectURI
}

// isHTTPLoopback reports whether u is a plain http URL to a loopback host, the RFC 8252 §7.3 native app redirect
func isHTTPLoopback(u *url.URL) bool {
	if u.Scheme != schemeHTTP {
		return false
	}

	ip := net.ParseIP(u.Hostname())

	return u.Hostname() == localhostName || (ip != nil && ip.IsLoopback())
}
