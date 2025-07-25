package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// TokenBlacklist provides an interface for managing revoked tokens
type TokenBlacklist interface {
	// Revoke adds a token to the blacklist with the specified TTL
	Revoke(ctx context.Context, tokenID string, ttl time.Duration) error
	// IsRevoked checks if a token has been revoked
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
	// RevokeAllForUser revokes all tokens for a specific user
	RevokeAllForUser(ctx context.Context, userID string, ttl time.Duration) error
	// IsUserRevoked checks if all tokens for a user have been revoked (user suspension)
	IsUserRevoked(ctx context.Context, userID string) (bool, error)
}

// RedisTokenBlacklist implements TokenBlacklist using Redis
type RedisTokenBlacklist struct {
	client *redis.Client
	prefix string
}

// NewRedisTokenBlacklist creates a new Redis-based token blacklist
func NewRedisTokenBlacklist(client *redis.Client, prefix string) TokenBlacklist {
	if prefix == "" {
		prefix = "token:blacklist"
	}

	return &RedisTokenBlacklist{
		client: client,
		prefix: prefix,
	}
}

// Revoke adds a token to the blacklist with automatic expiration
func (r *RedisTokenBlacklist) Revoke(ctx context.Context, tokenID string, ttl time.Duration) error {
	if tokenID == "" {
		return ErrInvalidTokenID
	}

	if ttl <= 0 {
		// Token has already expired, no need to blacklist
		return nil
	}

	key := r.blacklistKey(tokenID)
	// Store a simple marker value with TTL
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// RevokeAllForUser revokes all tokens for a specific user (user suspension)
func (r *RedisTokenBlacklist) RevokeAllForUser(ctx context.Context, userID string, ttl time.Duration) error {
	if userID == "" {
		return ErrInvalidTokenID
	}

	if ttl <= 0 {
		// Already expired, no need to blacklist
		return nil
	}

	key := r.userSuspensionKey(userID)
	// Store a simple marker value with TTL
	return r.client.Set(ctx, key, "1", ttl).Err()
}

// IsRevoked checks if a token exists in the blacklist
func (r *RedisTokenBlacklist) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	if tokenID == "" {
		return false, ErrInvalidTokenID
	}

	key := r.blacklistKey(tokenID)

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return exists > 0, nil
}

// IsUserRevoked checks if all tokens for a user have been revoked (user suspension)
func (r *RedisTokenBlacklist) IsUserRevoked(ctx context.Context, userID string) (bool, error) {
	if userID == "" {
		return false, ErrInvalidTokenID
	}

	key := r.userSuspensionKey(userID)

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return exists > 0, nil
}

// blacklistKey generates the Redis key for a blacklisted token
func (r *RedisTokenBlacklist) blacklistKey(tokenID string) string {
	return fmt.Sprintf("%s:%s", r.prefix, tokenID)
}

// userSuspensionKey generates the Redis key for a suspended user
func (r *RedisTokenBlacklist) userSuspensionKey(userID string) string {
	return fmt.Sprintf("%s:user:%s", r.prefix, userID)
}

// NoOpTokenBlacklist is a no-op implementation for when Redis is not available
type NoOpTokenBlacklist struct{}

// NewNoOpTokenBlacklist creates a new no-op token blacklist
func NewNoOpTokenBlacklist() TokenBlacklist {
	return &NoOpTokenBlacklist{}
}

// Revoke is a no-op
func (n *NoOpTokenBlacklist) Revoke(_ context.Context, _ string, _ time.Duration) error {
	return nil
}

// IsRevoked always returns false
func (n *NoOpTokenBlacklist) IsRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}

// RevokeAllForUser is a no-op
func (n *NoOpTokenBlacklist) RevokeAllForUser(_ context.Context, _ string, _ time.Duration) error {
	return nil
}

// IsUserRevoked always returns false
func (n *NoOpTokenBlacklist) IsUserRevoked(_ context.Context, _ string) (bool, error) {
	return false, nil
}
