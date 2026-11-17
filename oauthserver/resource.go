package oauthserver

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
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
		return "", fmt.Errorf("%w: invalid resource %q", ErrResourceMetadata, resource)
	}

	u.Path = protectedResourceMetadataPath + strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""

	return u.String(), nil
}

// ResourceScopes returns a resource's RFC 9728 scopes_supported, and callers must only pass resources ResourceAllowed accepts
func (r *ClientResolver) ResourceScopes(ctx context.Context, resource string) ([]string, error) {
	if scopes, ok := r.resources.Get(resource); ok {
		return scopes, nil
	}

	v, err, _ := r.group.Do(resourceFlightPrefix+resource, func() (any, error) { return r.fetchResourceScopes(ctx, resource) })
	if err != nil {
		return nil, err
	}

	return v.([]string), nil
}

// fetchResourceScopes loads and caches a resource's RFC 9728 scopes_supported
func (r *ClientResolver) fetchResourceScopes(ctx context.Context, resource string) ([]string, error) {
	if scopes, ok := r.resources.Get(resource); ok {
		return scopes, nil
	}

	if !r.allowFetch(resource) {
		return nil, ErrFetchRateLimited
	}

	// shared by every waiting caller, so one caller cancelling must not fail the rest
	ctx = context.WithoutCancel(ctx)

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

	r.resources.SetWithTTL(resource, meta.ScopesSupported, 1, metadataCacheTTL)

	return meta.ScopesSupported, nil
}
