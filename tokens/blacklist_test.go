package tokens_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/tokens"
)

func TestRedisTokenBlacklist(t *testing.T) {
	// Setup miniredis for testing
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	ctx := context.Background()

	t.Run("NewRedisTokenBlacklist", func(t *testing.T) {
		t.Run("with custom prefix", func(t *testing.T) {
			bl := tokens.NewRedisTokenBlacklist(client, "custom:prefix")
			assert.NotNil(t, bl)
		})

		t.Run("with empty prefix uses default", func(t *testing.T) {
			bl := tokens.NewRedisTokenBlacklist(client, "")
			assert.NotNil(t, bl)
		})
	})

	t.Run("Revoke", func(t *testing.T) {
		bl := tokens.NewRedisTokenBlacklist(client, "test:blacklist")

		t.Run("successful revocation", func(t *testing.T) {
			tokenID := "test-token-123"
			ttl := 1 * time.Hour

			err := bl.Revoke(ctx, tokenID, ttl)
			assert.NoError(t, err)

			// Verify token is in Redis
			key := "test:blacklist:" + tokenID
			exists := client.Exists(ctx, key).Val()
			assert.Equal(t, int64(1), exists)

			// Verify TTL is set
			duration := client.TTL(ctx, key).Val()
			assert.Greater(t, duration, 59*time.Minute)
			assert.LessOrEqual(t, duration, 60*time.Minute)
		})

		t.Run("empty token ID returns error", func(t *testing.T) {
			err := bl.Revoke(ctx, "", 1*time.Hour)
			assert.Equal(t, tokens.ErrInvalidTokenID, err)
		})

		t.Run("zero TTL does nothing", func(t *testing.T) {
			tokenID := "expired-token"
			err := bl.Revoke(ctx, tokenID, 0)
			assert.NoError(t, err)

			// Verify token is NOT in Redis
			key := "test:blacklist:" + tokenID
			exists := client.Exists(ctx, key).Val()
			assert.Equal(t, int64(0), exists)
		})

		t.Run("negative TTL does nothing", func(t *testing.T) {
			tokenID := "expired-token-2"
			err := bl.Revoke(ctx, tokenID, -1*time.Hour)
			assert.NoError(t, err)

			// Verify token is NOT in Redis
			key := "test:blacklist:" + tokenID
			exists := client.Exists(ctx, key).Val()
			assert.Equal(t, int64(0), exists)
		})
	})

	t.Run("IsRevoked", func(t *testing.T) {
		bl := tokens.NewRedisTokenBlacklist(client, "test:blacklist")

		t.Run("revoked token returns true", func(t *testing.T) {
			tokenID := "revoked-token"
			// First revoke it
			err := bl.Revoke(ctx, tokenID, 1*time.Hour)
			assert.NoError(t, err)

			// Check if revoked
			revoked, err := bl.IsRevoked(ctx, tokenID)
			assert.NoError(t, err)
			assert.True(t, revoked)
		})

		t.Run("non-revoked token returns false", func(t *testing.T) {
			tokenID := "valid-token"
			revoked, err := bl.IsRevoked(ctx, tokenID)
			assert.NoError(t, err)
			assert.False(t, revoked)
		})

		t.Run("empty token ID returns error", func(t *testing.T) {
			revoked, err := bl.IsRevoked(ctx, "")
			assert.Equal(t, tokens.ErrInvalidTokenID, err)
			assert.False(t, revoked)
		})

		t.Run("expired token returns false", func(t *testing.T) {
			tokenID := "expiring-token" //nolint:gosec
			// Use miniredis FastForward to simulate time passage
			err := bl.Revoke(ctx, tokenID, 1*time.Second)
			assert.NoError(t, err)

			// Verify it's initially revoked
			revoked, err := bl.IsRevoked(ctx, tokenID)
			assert.NoError(t, err)
			assert.True(t, revoked)

			// Fast forward time in miniredis to expire the key
			mr.FastForward(2 * time.Second)

			// Check if revoked (should be expired now)
			revoked, err = bl.IsRevoked(ctx, tokenID)
			assert.NoError(t, err)
			assert.False(t, revoked)
		})
	})

	t.Run("Redis error handling", func(t *testing.T) {
		// Close Redis to simulate connection error
		mr.Close()

		bl := tokens.NewRedisTokenBlacklist(client, "test:blacklist")

		t.Run("Revoke returns Redis error", func(t *testing.T) {
			err := bl.Revoke(ctx, "test-token", 1*time.Hour)
			assert.Error(t, err)
			assert.NotEqual(t, tokens.ErrInvalidTokenID, err)
		})

		t.Run("IsRevoked returns Redis error", func(t *testing.T) {
			revoked, err := bl.IsRevoked(ctx, "test-token")
			assert.Error(t, err)
			assert.False(t, revoked)
			assert.NotEqual(t, tokens.ErrInvalidTokenID, err)
		})
	})
}

func TestNoOpTokenBlacklist(t *testing.T) {
	bl := tokens.NewNoOpTokenBlacklist()
	ctx := context.Background()

	t.Run("Revoke always succeeds", func(t *testing.T) {
		err := bl.Revoke(ctx, "any-token", 1*time.Hour)
		assert.NoError(t, err)

		err = bl.Revoke(ctx, "", 0)
		assert.NoError(t, err)
	})

	t.Run("IsRevoked always returns false", func(t *testing.T) {
		revoked, err := bl.IsRevoked(ctx, "any-token")
		assert.NoError(t, err)
		assert.False(t, revoked)

		revoked, err = bl.IsRevoked(ctx, "")
		assert.NoError(t, err)
		assert.False(t, revoked)
	})
}

func TestTokenBlacklistIntegration(t *testing.T) {
	// This test verifies the blacklist works correctly with concurrent operations
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	ctx := context.Background()
	bl := tokens.NewRedisTokenBlacklist(client, "concurrent:test")

	t.Run("concurrent revocations", func(t *testing.T) {
		tokenIDs := []string{"token1", "token2", "token3", "token4", "token5"}

		// Revoke tokens concurrently
		errCh := make(chan error, len(tokenIDs))

		for _, tokenID := range tokenIDs {
			go func(id string) {
				errCh <- bl.Revoke(ctx, id, 1*time.Hour)
			}(tokenID)
		}

		// Collect errors
		for range tokenIDs {
			err := <-errCh
			assert.NoError(t, err)
		}

		// Verify all tokens are revoked
		for _, tokenID := range tokenIDs {
			revoked, err := bl.IsRevoked(ctx, tokenID)
			assert.NoError(t, err)
			assert.True(t, revoked)
		}
	})

	t.Run("concurrent checks", func(t *testing.T) {
		// Revoke a token
		tokenID := "concurrent-check-token"
		err := bl.Revoke(ctx, tokenID, 1*time.Hour)
		assert.NoError(t, err)

		// Check concurrently
		results := make(chan bool, 10)

		for i := 0; i < 10; i++ {
			go func() {
				revoked, err := bl.IsRevoked(ctx, tokenID)
				assert.NoError(t, err)

				results <- revoked
			}()
		}

		// All checks should return true
		for i := 0; i < 10; i++ {
			assert.True(t, <-results)
		}
	})
}

// BenchmarkRedisTokenBlacklist provides performance benchmarks
func BenchmarkRedisTokenBlacklist(b *testing.B) {
	mr, err := miniredis.Run()
	assert.NoError(b, err)

	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	ctx := context.Background()
	bl := tokens.NewRedisTokenBlacklist(client, "bench:blacklist")

	b.Run("Revoke", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			tokenID := fmt.Sprintf("token-%d", i)
			_ = bl.Revoke(ctx, tokenID, 1*time.Hour)
		}
	})

	b.Run("IsRevoked_Hit", func(b *testing.B) {
		// Setup: revoke a token
		tokenID := "bench-token"
		_ = bl.Revoke(ctx, tokenID, 1*time.Hour)

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = bl.IsRevoked(ctx, tokenID)
		}
	})

	b.Run("IsRevoked_Miss", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			tokenID := fmt.Sprintf("miss-token-%d", i)
			_, _ = bl.IsRevoked(ctx, tokenID)
		}
	})
}

func TestGeneralTokenBlacklist(t *testing.T) {
	// Setup Redis
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	// Setup TokenManager
	_, key, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	conf := tokens.Config{
		Audience:        "test-audience",
		Issuer:          "test-issuer",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 24 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key, conf)
	assert.NoError(t, err)

	// Configure blacklist
	blacklist := tokens.NewRedisTokenBlacklist(client, "test:general")
	tm.WithBlacklist(blacklist)

	ctx := context.Background()

	t.Run("access token revocation", func(t *testing.T) {
		// Create claims
		claims := &tokens.Claims{
			UserID: "user-123",
			OrgID:  "org-456",
		}

		// Create access token
		accessTokenJWT, err := tm.CreateAccessToken(claims)
		assert.NoError(t, err)

		tokenString, err := tm.Sign(accessTokenJWT)
		assert.NoError(t, err)

		// Verify token works initially
		verifiedClaims, err := tm.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)
		assert.Equal(t, "user-123", verifiedClaims.UserID)
		assert.NotEmpty(t, verifiedClaims.ID)

		// Revoke the token using its JWT ID
		tokenID := verifiedClaims.ID
		err = tm.RevokeToken(ctx, tokenID, 30*time.Minute)
		assert.NoError(t, err)

		// Try to verify again (should fail now)
		_, err = tm.VerifyWithContext(ctx, tokenString)
		assert.Error(t, err)
		assert.Equal(t, tokens.ErrTokenInvalid, err)
	})

	t.Run("user suspension affects all tokens", func(t *testing.T) {
		userID := "user-789"

		// Create multiple tokens for the same user
		claims1 := &tokens.Claims{UserID: userID, OrgID: "org-456"}
		claims2 := &tokens.Claims{UserID: userID, OrgID: "org-789"}

		token1JWT, err := tm.CreateAccessToken(claims1)
		assert.NoError(t, err)
		token1String, err := tm.Sign(token1JWT)
		assert.NoError(t, err)

		token2JWT, err := tm.CreateAccessToken(claims2)
		assert.NoError(t, err)
		token2String, err := tm.Sign(token2JWT)
		assert.NoError(t, err)

		// Verify both tokens work initially
		_, err = tm.VerifyWithContext(ctx, token1String)
		assert.NoError(t, err)
		_, err = tm.VerifyWithContext(ctx, token2String)
		assert.NoError(t, err)

		// Suspend the user
		err = tm.SuspendUser(ctx, userID, 1*time.Hour)
		assert.NoError(t, err)

		// Both tokens should now be invalid
		_, err = tm.VerifyWithContext(ctx, token1String)
		assert.Error(t, err)
		assert.Equal(t, tokens.ErrTokenInvalid, err)

		_, err = tm.VerifyWithContext(ctx, token2String)
		assert.Error(t, err)
		assert.Equal(t, tokens.ErrTokenInvalid, err)
	})

	t.Run("refresh token revocation", func(t *testing.T) {
		// Create access token first
		claims := &tokens.Claims{
			UserID: "user-456",
			OrgID:  "org-789",
		}
		// Set Subject for proper token creation
		claims.Subject = "user-456"

		accessTokenJWT, err := tm.CreateAccessToken(claims)
		assert.NoError(t, err)

		// Create refresh token from access token
		refreshTokenJWT, err := tm.CreateRefreshToken(accessTokenJWT)
		assert.NoError(t, err)

		refreshTokenString, err := tm.Sign(refreshTokenJWT)
		assert.NoError(t, err)

		// Parse refresh token
		verifiedClaims, err := tm.Parse(refreshTokenString)
		assert.NoError(t, err)
		assert.Equal(t, "user-456", verifiedClaims.Subject)
		assert.NotEmpty(t, verifiedClaims.ID)

		// Revoke the refresh token
		err = tm.RevokeToken(ctx, verifiedClaims.ID, 1*time.Hour)
		assert.NoError(t, err)

		// Try to parse and check blacklist manually since refresh token may not be valid yet
		parsedClaims, err := tm.Parse(refreshTokenString)
		assert.NoError(t, err)

		// Check if the token ID is blacklisted directly
		revoked, err := blacklist.IsRevoked(ctx, parsedClaims.ID)
		assert.NoError(t, err)
		assert.True(t, revoked, "refresh token should be revoked")
	})

	t.Run("expired blacklist entries allow token validation", func(t *testing.T) {
		claims := &tokens.Claims{
			UserID: "user-expiry-test",
			OrgID:  "org-456",
		}

		accessTokenJWT, err := tm.CreateAccessToken(claims)
		assert.NoError(t, err)

		tokenString, err := tm.Sign(accessTokenJWT)
		assert.NoError(t, err)

		verifiedClaims, err := tm.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)

		// Revoke with short TTL
		err = tm.RevokeToken(ctx, verifiedClaims.ID, 1*time.Second)
		assert.NoError(t, err)

		// Verify it's initially revoked
		_, err = tm.VerifyWithContext(ctx, tokenString)
		assert.Error(t, err)

		// Fast forward time in miniredis to expire the blacklist entry
		mr.FastForward(2 * time.Second)

		// Should work again since blacklist entry expired
		_, err = tm.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)
	})

	t.Run("user suspension expiry", func(t *testing.T) {
		userID := "user-suspension-expiry"
		claims := &tokens.Claims{UserID: userID, OrgID: "org-456"}

		tokenJWT, err := tm.CreateAccessToken(claims)
		assert.NoError(t, err)
		tokenString, err := tm.Sign(tokenJWT)
		assert.NoError(t, err)

		// Suspend user with short TTL
		err = tm.SuspendUser(ctx, userID, 1*time.Second)
		assert.NoError(t, err)

		// Verify token is initially invalid due to suspension
		_, err = tm.VerifyWithContext(ctx, tokenString)
		assert.Error(t, err)

		// Fast forward time to expire suspension
		mr.FastForward(2 * time.Second)

		// Token should work again since suspension expired
		_, err = tm.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)
	})

	t.Run("no blacklist configured", func(t *testing.T) {
		// Create TokenManager without blacklist
		tmNoBlacklist, err := tokens.NewWithKey(key, conf)
		assert.NoError(t, err)

		claims := &tokens.Claims{UserID: "user-no-blacklist", OrgID: "org-456"}

		tokenJWT, err := tmNoBlacklist.CreateAccessToken(claims)
		assert.NoError(t, err)
		tokenString, err := tmNoBlacklist.Sign(tokenJWT)
		assert.NoError(t, err)

		verifiedClaims, err := tmNoBlacklist.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)

		// Try to revoke (should be no-op)
		err = tmNoBlacklist.RevokeToken(ctx, verifiedClaims.ID, 30*time.Minute)
		assert.NoError(t, err)

		// Token should still work since no blacklist
		_, err = tmNoBlacklist.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)

		// Try to suspend user (should be no-op)
		err = tmNoBlacklist.SuspendUser(ctx, "user-no-blacklist", 30*time.Minute)
		assert.NoError(t, err)

		// Token should still work since no blacklist
		_, err = tmNoBlacklist.VerifyWithContext(ctx, tokenString)
		assert.NoError(t, err)
	})
}

func TestTokenBlacklistUserSuspension(t *testing.T) {
	// Setup Redis
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	ctx := context.Background()
	bl := tokens.NewRedisTokenBlacklist(client, "test:user")

	t.Run("user suspension operations", func(t *testing.T) {
		userID := "test-user-123"

		// Initially not suspended
		suspended, err := bl.IsUserRevoked(ctx, userID)
		assert.NoError(t, err)
		assert.False(t, suspended)

		// Suspend user
		err = bl.RevokeAllForUser(ctx, userID, 1*time.Hour)
		assert.NoError(t, err)

		// Check suspension status
		suspended, err = bl.IsUserRevoked(ctx, userID)
		assert.NoError(t, err)
		assert.True(t, suspended)
	})

	t.Run("empty user ID validation", func(t *testing.T) {
		err := bl.RevokeAllForUser(ctx, "", 1*time.Hour)
		assert.Equal(t, tokens.ErrInvalidTokenID, err)

		suspended, err := bl.IsUserRevoked(ctx, "")
		assert.Equal(t, tokens.ErrInvalidTokenID, err)
		assert.False(t, suspended)
	})

	t.Run("zero TTL handling", func(t *testing.T) {
		userID := "test-user-zero-ttl"

		err := bl.RevokeAllForUser(ctx, userID, 0)
		assert.NoError(t, err)

		// Should not be suspended since TTL was zero
		suspended, err := bl.IsUserRevoked(ctx, userID)
		assert.NoError(t, err)
		assert.False(t, suspended)
	})
}
