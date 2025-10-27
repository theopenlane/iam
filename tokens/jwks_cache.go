package tokens

import (
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

const (
	defaultJWKSCacheTTL = 5 * time.Minute
)

// jwksCache provides thread-safe caching for JWKS
type jwksCache struct {
	cache      jwk.Set
	cachedAt   time.Time
	ttl        time.Duration
	mu         sync.RWMutex
	generation uint64
}

// newJWKSCache creates a new JWKS cache with the specified TTL
func newJWKSCache(ttl time.Duration) *jwksCache {
	if ttl == 0 {
		ttl = defaultJWKSCacheTTL
	}

	return &jwksCache{
		ttl: ttl,
	}
}

// Get returns the cached JWKS if valid, or nil if expired/empty
func (jc *jwksCache) Get() (jwk.Set, bool) {
	jc.mu.RLock()
	defer jc.mu.RUnlock()

	if jc.cache == nil {
		return nil, false
	}

	if time.Since(jc.cachedAt) > jc.ttl {
		return nil, false
	}

	return jc.cache, true
}

// Set updates the cached JWKS
func (jc *jwksCache) Set(keys jwk.Set) {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	jc.cache = keys
	jc.cachedAt = time.Now()
	jc.generation++
}

// Invalidate clears the cache
func (jc *jwksCache) Invalidate() {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	jc.cache = nil
	jc.cachedAt = time.Time{}
	jc.generation++
}

// Generation returns the current generation number (increments on Set and Invalidate)
func (jc *jwksCache) Generation() uint64 {
	jc.mu.RLock()
	defer jc.mu.RUnlock()

	return jc.generation
}

// IsExpired returns true if the cache is expired
func (jc *jwksCache) IsExpired() bool {
	jc.mu.RLock()
	defer jc.mu.RUnlock()

	if jc.cache == nil {
		return true
	}

	return time.Since(jc.cachedAt) > jc.ttl
}
