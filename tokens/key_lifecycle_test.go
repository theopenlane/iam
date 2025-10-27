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

func TestKeyLifecycle(t *testing.T) {
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
	}

	tm, err := tokens.NewWithKey(key1, conf)
	require.NoError(t, err)

	originalKID := tm.CurrentKeyID()

	err = tm.AddSigningKeyWithID("key2", key2)
	require.NoError(t, err)

	t.Run("list active keys", func(t *testing.T) {
		active := tm.ListActiveKeys()
		assert.Len(t, active, 2)
		assert.Contains(t, active, originalKID)
		assert.Contains(t, active, "key2")
	})

	t.Run("deprecate key", func(t *testing.T) {
		err := tm.DeprecateKey(originalKID)
		assert.NoError(t, err)

		deprecated := tm.ListDeprecatedKeys()
		assert.Len(t, deprecated, 1)
		assert.Contains(t, deprecated, originalKID)

		active := tm.ListActiveKeys()
		assert.Len(t, active, 1)
		assert.Contains(t, active, "key2")
	})

	t.Run("get key metadata", func(t *testing.T) {
		meta, err := tm.GetKeyMetadata(originalKID)
		require.NoError(t, err)
		assert.Equal(t, originalKID, meta.KeyID)
		assert.True(t, meta.IsDeprecated())
		assert.False(t, meta.IsActive())
		assert.NotNil(t, meta.DeprecatedAt)
	})

	t.Run("revoke key", func(t *testing.T) {
		err := tm.RevokeKey(originalKID)
		assert.NoError(t, err)

		deprecated := tm.ListDeprecatedKeys()
		assert.Len(t, deprecated, 0)
	})
}

func TestKeyRotation(t *testing.T) {
	_, key1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	conf := tokens.Config{
		Audience:        "test-audience",
		Issuer:          "test-issuer",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key1, conf)
	require.NoError(t, err)

	originalKID := tm.CurrentKeyID()

	t.Run("should rotate based on age", func(t *testing.T) {
		shouldNotRotateYet := tm.ShouldRotate(1 * time.Millisecond)
		assert.False(t, shouldNotRotateYet, "key was just created, should not need rotation yet")

		time.Sleep(2 * time.Millisecond)

		shouldRotateNow := tm.ShouldRotate(1 * time.Millisecond)
		assert.True(t, shouldRotateNow, "key is now older than max age")
	})

	t.Run("rotate keys", func(t *testing.T) {
		time.Sleep(2 * time.Millisecond)

		result, err := tm.RotateKeys(tokens.GenerateEd25519Key, 1*time.Hour)
		require.NoError(t, err)
		assert.NotEmpty(t, result.NewKeyID)
		assert.NotEqual(t, originalKID, result.NewKeyID)
		assert.Contains(t, result.DeprecatedKeys, originalKID)
		assert.Equal(t, result.NewKeyID, tm.CurrentKeyID(), "newly rotated key should be current")
	})

	t.Run("rotate with grace period expiry", func(t *testing.T) {
		currentKID := tm.CurrentKeyID()

		time.Sleep(10 * time.Millisecond)

		result, err := tm.RotateKeys(tokens.GenerateEd25519Key, 1*time.Millisecond)
		require.NoError(t, err)

		assert.NotEmpty(t, result.NewKeyID)
		assert.NotEqual(t, currentKID, result.NewKeyID, "should have created new key")
		assert.Contains(t, result.DeprecatedKeys, currentKID, "previous current key should be deprecated")
		assert.Len(t, result.RevokedKeys, 1, "original key should be revoked after grace period")
		assert.Contains(t, result.RevokedKeys, originalKID, "original key should be in revoked list")
	})
}

func TestGenerateEd25519Key(t *testing.T) {
	kid, signer, err := tokens.GenerateEd25519Key()
	require.NoError(t, err)
	assert.NotEmpty(t, kid)
	assert.NotNil(t, signer)

	_, ok := signer.(ed25519.PrivateKey)
	assert.True(t, ok, "expected ed25519.PrivateKey")
}
