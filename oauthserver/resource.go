package oauthserver

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// ResourceAllowed reports whether resource exactly matches one of the allowed resource URLs
func ResourceAllowed(allowed []string, resource string) bool {
	return resource != "" && slices.Contains(allowed, resource)
}

// ResolveResource returns the one resource a token is issued for, defaulting to the only allowed resource when none is requested
func ResolveResource(allowed, requested []string) (string, error) {
	switch len(requested) {
	case 0:
		if len(allowed) == 1 {
			return allowed[0], nil
		}
	case 1:
		if ResourceAllowed(allowed, requested[0]) {
			return requested[0], nil
		}
	}

	return "", ErrInvalidTarget
}

const (
	// protectedResourceMetadataPath is the RFC 9728 well-known path
	protectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
	// resourceFlightPrefix keeps resource fetches apart from client fetches in the shared singleflight group
	resourceFlightPrefix = "resource:"
)

// ResourceMetadataURL returns a resource's RFC 9728 metadata URL, the well-known path inserted before the resource's path
func ResourceMetadataURL(resource string) (string, error) {
	u, err := url.Parse(resource)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: invalid resource", ErrResourceMetadata)
	}

	u.Path = protectedResourceMetadataPath + strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""

	return u.String(), nil
}

// ResourceScopes returns a copy of a resource's RFC 9728 scopes_supported, and callers must only pass resources ResourceAllowed accepts
func (r *ClientResolver) ResourceScopes(ctx context.Context, resource string) ([]string, error) {
	if cached, ok := r.resources.Get(resource); ok && cached.fresh() {
		return slices.Clone(cached.value), nil
	}

	scopes, err := share(ctx, &r.group, resourceFlightPrefix+resource, func() ([]string, error) { return r.refreshResourceScopes(ctx, resource) })
	if err != nil {
		return nil, err
	}

	return slices.Clone(scopes), nil
}

// refreshResourceScopes fetches a resource's scopes, serving a stale copy while its host is down
func (r *ClientResolver) refreshResourceScopes(ctx context.Context, resource string) ([]string, error) {
	cached, hasCached := r.resources.Get(resource)
	if hasCached && cached.fresh() {
		return cached.value, nil
	}

	// resources come from the operator's allowlist, not the caller, so they skip the fetch budget anyone can spend
	scopes, err := r.fetchResourceScopes(context.WithoutCancel(ctx), resource)
	if err != nil {
		if hasCached && errors.Is(err, errMetadataUnavailable) {
			return cached.value, nil
		}

		r.resources.Delete(resource)

		return nil, err
	}

	r.resources.SetWithTTL(resource, &cachedEntry[[]string]{value: scopes, fetchedAt: time.Now()}, 1, metadataCacheTTL+metadataMaxStale)

	return scopes, nil
}

// fetchResourceScopes loads a resource's RFC 9728 scopes_supported
func (r *ClientResolver) fetchResourceScopes(ctx context.Context, resource string) ([]string, error) {
	metadataURL, err := ResourceMetadataURL(resource)
	if err != nil {
		return nil, err
	}

	var meta struct {
		Resource        string   `json:"resource"`
		ScopesSupported []string `json:"scopes_supported"`
	}

	if err := r.getJSON(ctx, metadataURL, &meta); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrResourceMetadata, err)
	}

	// RFC 9728 §3.3: the metadata must name the resource it was fetched for
	if strings.TrimRight(meta.Resource, "/") != strings.TrimRight(resource, "/") {
		return nil, fmt.Errorf("%w: resource in metadata does not match", ErrResourceMetadata)
	}

	return meta.ScopesSupported, nil
}
