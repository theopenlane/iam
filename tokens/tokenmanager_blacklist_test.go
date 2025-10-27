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

func TestTokenManagerWithBlacklist(t *testing.T) {
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
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key, conf)
	assert.NoError(t, err)

	// Configure blacklist
	blacklist := tokens.NewRedisTokenBlacklist(client, "test:blacklist")
	tm.WithBlacklist(blacklist)

	ctx := context.Background()

	t.Run("token lifecycle with blacklist", func(t *testing.T) {
		// Create an impersonation token
		opts := tokens.CreateImpersonationTokenOptions{
			ImpersonatorID:    "admin-123",
			ImpersonatorEmail: "admin@example.com",
			TargetUserID:      "user-456",
			TargetUserEmail:   "user@example.com",
			OrganizationID:    "org-789",
			Type:              "admin",
			Reason:            "debugging user issue",
			Duration:          1 * time.Hour,
			Scopes:            []string{"read", "write"},
		}

		tokenString, err := tm.CreateImpersonationToken(ctx, opts)
		assert.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Validate token (should work initially)
		claims, err := tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)
		assert.Equal(t, opts.ImpersonatorID, claims.ImpersonatorID)
		assert.Equal(t, opts.TargetUserID, claims.UserID)
		assert.NotEmpty(t, claims.SessionID)

		// Revoke the token
		remainingTTL := 30 * time.Minute
		err = tm.RevokeImpersonationToken(ctx, claims.SessionID, remainingTTL)
		assert.NoError(t, err)

		// Try to validate again (should fail now)
		_, err = tm.ValidateImpersonationToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Equal(t, tokens.ErrTokenInvalid, err)
	})

	t.Run("token validation without blacklist", func(t *testing.T) {
		// Create TokenManager without blacklist
		tmNoBlacklist, err := tokens.NewWithKey(key, conf)
		assert.NoError(t, err)

		opts := tokens.CreateImpersonationTokenOptions{
			ImpersonatorID:    "admin-123",
			ImpersonatorEmail: "admin@example.com",
			TargetUserID:      "user-456",
			TargetUserEmail:   "user@example.com",
			OrganizationID:    "org-789",
			Type:              "admin",
			Reason:            "debugging user issue",
			Duration:          1 * time.Hour,
			Scopes:            []string{"read", "write"},
		}

		tokenString, err := tmNoBlacklist.CreateImpersonationToken(ctx, opts)
		assert.NoError(t, err)

		// Validate token (should work)
		claims, err := tmNoBlacklist.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)
		assert.NotEmpty(t, claims.SessionID)

		// Try to revoke (should be no-op with no blacklist)
		err = tmNoBlacklist.RevokeImpersonationToken(ctx, claims.SessionID, 30*time.Minute)
		assert.NoError(t, err) // Should not error

		// Validate again (should still work since no blacklist)
		_, err = tmNoBlacklist.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)
	})

	t.Run("expired blacklist entry", func(t *testing.T) {
		opts := tokens.CreateImpersonationTokenOptions{
			ImpersonatorID:    "admin-123",
			ImpersonatorEmail: "admin@example.com",
			TargetUserID:      "user-456",
			TargetUserEmail:   "user@example.com",
			OrganizationID:    "org-789",
			Type:              "admin",
			Reason:            "debugging user issue",
			Duration:          1 * time.Hour,
			Scopes:            []string{"read", "write"},
		}

		tokenString, err := tm.CreateImpersonationToken(ctx, opts)
		assert.NoError(t, err)

		claims, err := tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)

		// Revoke with short TTL
		err = tm.RevokeImpersonationToken(ctx, claims.SessionID, 1*time.Second)
		assert.NoError(t, err)

		// Verify it's initially revoked
		_, err = tm.ValidateImpersonationToken(ctx, tokenString)
		assert.Error(t, err)

		// Fast forward time in miniredis to expire the blacklist entry
		mr.FastForward(2 * time.Second)

		// Should work again since blacklist entry expired
		_, err = tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)
	})

	t.Run("revoke with zero TTL", func(t *testing.T) {
		opts := tokens.CreateImpersonationTokenOptions{
			ImpersonatorID:    "admin-123",
			ImpersonatorEmail: "admin@example.com",
			TargetUserID:      "user-456",
			TargetUserEmail:   "user@example.com",
			OrganizationID:    "org-789",
			Type:              "admin",
			Reason:            "debugging user issue",
			Duration:          1 * time.Hour,
			Scopes:            []string{"read", "write"},
		}

		tokenString, err := tm.CreateImpersonationToken(ctx, opts)
		assert.NoError(t, err)

		claims, err := tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)

		// Revoke with zero TTL (should be no-op)
		err = tm.RevokeImpersonationToken(ctx, claims.SessionID, 0)
		assert.NoError(t, err)

		// Should still work since TTL was zero
		_, err = tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)
	})

	t.Run("redis connection error handling", func(t *testing.T) {
		// Close Redis to simulate connection issues
		mr.Close()

		opts := tokens.CreateImpersonationTokenOptions{
			ImpersonatorID:    "admin-123",
			ImpersonatorEmail: "admin@example.com",
			TargetUserID:      "user-456",
			TargetUserEmail:   "user@example.com",
			OrganizationID:    "org-789",
			Type:              "admin",
			Reason:            "debugging user issue",
			Duration:          1 * time.Hour,
			Scopes:            []string{"read", "write"},
		}

		tokenString, err := tm.CreateImpersonationToken(ctx, opts)
		assert.NoError(t, err)

		claims, err := tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)

		// Try to revoke (should return Redis error)
		err = tm.RevokeImpersonationToken(ctx, claims.SessionID, 30*time.Minute)
		assert.Error(t, err)

		// Validation should still work (fails open when Redis is down)
		// Note: This might change based on logging implementation
		_, err = tm.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err) // Should not fail validation due to Redis being down
	})
}

func TestTokenManagerBlacklistEdgeCases(t *testing.T) {
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
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key, conf)
	assert.NoError(t, err)

	blacklist := tokens.NewRedisTokenBlacklist(client, "test:blacklist")
	tm.WithBlacklist(blacklist)

	ctx := context.Background()

	t.Run("validate token with empty session ID", func(t *testing.T) {
		// Test that empty session ID in blacklist operations returns appropriate error
		err := tm.RevokeImpersonationToken(ctx, "", 1*time.Hour)
		// Should return the expected error from blacklist implementation
		assert.Equal(t, tokens.ErrInvalidTokenID, err)
	})

	t.Run("validate with nil blacklist", func(t *testing.T) {
		// Create TokenManager without blacklist
		tmNil, err := tokens.NewWithKey(key, conf)
		assert.NoError(t, err)
		// Don't set blacklist (should use NoOp)

		opts := tokens.CreateImpersonationTokenOptions{
			ImpersonatorID:    "admin-123",
			ImpersonatorEmail: "admin@example.com",
			TargetUserID:      "user-456",
			TargetUserEmail:   "user@example.com",
			OrganizationID:    "org-789",
			Type:              "admin",
			Reason:            "debugging user issue",
			Duration:          1 * time.Hour,
			Scopes:            []string{"read", "write"},
		}

		tokenString, err := tmNil.CreateImpersonationToken(ctx, opts)
		assert.NoError(t, err)

		// Should validate successfully
		_, err = tmNil.ValidateImpersonationToken(ctx, tokenString)
		assert.NoError(t, err)
	})
}

// BenchmarkTokenManagerBlacklist provides performance benchmarks
func BenchmarkTokenManagerBlacklist(b *testing.B) {
	// Setup Redis
	mr, err := miniredis.Run()
	assert.NoError(b, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	defer client.Close()

	// Setup TokenManager
	_, key, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(b, err)

	conf := tokens.Config{
		Audience:        "bench-audience",
		Issuer:          "bench-issuer",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(key, conf)
	assert.NoError(b, err)

	blacklist := tokens.NewRedisTokenBlacklist(client, "bench:blacklist")
	tm.WithBlacklist(blacklist)

	ctx := context.Background()

	// Create a test token
	opts := tokens.CreateImpersonationTokenOptions{
		ImpersonatorID:    "admin-123",
		ImpersonatorEmail: "admin@example.com",
		TargetUserID:      "user-456",
		TargetUserEmail:   "user@example.com",
		OrganizationID:    "org-789",
		Type:              "admin",
		Reason:            "benchmark test",
		Duration:          1 * time.Hour,
		Scopes:            []string{"read", "write"},
	}

	tokenString, err := tm.CreateImpersonationToken(ctx, opts)
	assert.NoError(b, err)

	b.Run("ValidateImpersonationToken_NotBlacklisted", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = tm.ValidateImpersonationToken(ctx, tokenString)
		}
	})

	// Revoke the token for blacklisted benchmark
	claims, err := tm.ValidateImpersonationToken(ctx, tokenString)
	assert.NoError(b, err)

	_ = tm.RevokeImpersonationToken(ctx, claims.SessionID, 1*time.Hour)

	b.Run("ValidateImpersonationToken_Blacklisted", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = tm.ValidateImpersonationToken(ctx, tokenString)
		}
	})

	b.Run("RevokeImpersonationToken", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			sessionID := fmt.Sprintf("session-%d", i)
			_ = tm.RevokeImpersonationToken(ctx, sessionID, 1*time.Hour)
		}
	})
}
