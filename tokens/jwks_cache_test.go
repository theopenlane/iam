package tokens_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/tokens"
)

func TestJWKSCache(t *testing.T) {
	_, key1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, key2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	conf := tokens.Config{
		Audience:        "test-audience",
		Issuer:          "test-issuer",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
		JWKSCacheTTL:    50 * time.Millisecond,
	}

	tm, err := tokens.NewWithKey(key1, conf)
	require.NoError(t, err)

	t.Run("cache hit on subsequent calls", func(t *testing.T) {
		keys1, err := tm.Keys()
		require.NoError(t, err)
		assert.Equal(t, 1, keys1.Len())

		keys2, err := tm.Keys()
		require.NoError(t, err)
		assert.Equal(t, 1, keys2.Len())
	})

	t.Run("cache invalidates when key added", func(t *testing.T) {
		keys1, err := tm.Keys()
		require.NoError(t, err)

		originalLen := keys1.Len()

		err = tm.AddSigningKeyWithID("new-key", key2)
		require.NoError(t, err)

		keys2, err := tm.Keys()
		require.NoError(t, err)
		assert.Equal(t, originalLen+1, keys2.Len())
	})

	t.Run("cache expires after TTL", func(t *testing.T) {
		keys1, err := tm.Keys()
		require.NoError(t, err)
		assert.Greater(t, keys1.Len(), 0)

		time.Sleep(60 * time.Millisecond)

		keys2, err := tm.Keys()
		require.NoError(t, err)
		assert.Equal(t, keys1.Len(), keys2.Len())
	})

	t.Run("cache invalidates when key removed", func(t *testing.T) {
		keys1, err := tm.Keys()
		require.NoError(t, err)

		originalLen := keys1.Len()

		tm.RemoveSigningKeyByID("new-key")

		keys2, err := tm.Keys()
		require.NoError(t, err)
		assert.Equal(t, originalLen-1, keys2.Len())
	})
}

func TestJWKSCacheDefault(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	conf := tokens.Config{
		Audience:        "test-audience",
		Issuer:          "test-issuer",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key, conf)
	require.NoError(t, err)

	keys, err := tm.Keys()
	require.NoError(t, err)
	assert.Equal(t, 1, keys.Len())
}
