package sessions

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// userSessionsKeyPrefix is the redis key prefix of the sorted set holding the session ids of a user
	userSessionsKeyPrefix = "user_sessions:"
	// deleteUserSessionsAttempts is how many times a delete is retried when the index changes underneath it
	deleteUserSessionsAttempts = 3
)

// PersistentStore is defining an interface for session store
type PersistentStore interface {
	Exists(ctx context.Context, key string) (int64, error)
	GetSession(ctx context.Context, key string) (string, error)
	StoreSession(ctx context.Context, key, value string) error
	StoreSessionWithExpiration(ctx context.Context, key, value string, ttl time.Duration) error
	DeleteSession(ctx context.Context, key string) error
	// TakeSession returns the value for the key and deletes it in one atomic operation
	TakeSession(ctx context.Context, key string) (string, error)
	// AddUserSession records the session id in the per-user session index for ttl; the index outlives its longest entry
	AddUserSession(ctx context.Context, userID, sessionID string, ttl time.Duration) error
	// RemoveUserSession removes the session id from the per-user session index
	RemoveUserSession(ctx context.Context, userID, sessionID string) error
	// DeleteUserSessions deletes every session recorded for the user along with the index itself
	DeleteUserSessions(ctx context.Context, userID string) error
}

var _ PersistentStore = &persistentStore{}

// persistentStore stores Sessions in a persistent data store (redis)
type persistentStore struct {
	client *redis.Client
	mu     sync.Mutex
}

// NewStore returns a new Store that stores to a persistent backend (redis)
func NewStore(client *redis.Client) PersistentStore {
	return &persistentStore{
		client: client,
	}
}

// Exists checks to see if there is an existing session for the user
func (s *persistentStore) Exists(ctx context.Context, key string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.Exists(ctx, key).Result()
}

// GetSession checks to see if there is an existing session for the user
func (s *persistentStore) GetSession(ctx context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.Get(ctx, key).Result()
}

// StoreSession is used to store a session in the store with a key and value
// the TTL is set to the defaultMaxAgeSeconds to align with the session cookie
func (s *persistentStore) StoreSession(ctx context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.Set(ctx, key, value, time.Duration(defaultMaxAgeSeconds)*time.Second).Err()
}

// StoreSessionWithExpiration is used to store a session in the store with a key and value and a time to live
func (s *persistentStore) StoreSessionWithExpiration(ctx context.Context, key, value string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.Set(ctx, key, value, ttl).Err()
}

// DeleteSession is used to delete a session from the store
func (s *persistentStore) DeleteSession(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.Del(ctx, userID).Err()
}

// TakeSession returns the value for the key and deletes it in one atomic operation
func (s *persistentStore) TakeSession(ctx context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.GetDel(ctx, key).Result()
}

// userSessionsKey returns the redis key of the session index for the user
func userSessionsKey(userID string) string {
	return userSessionsKeyPrefix + userID
}

// AddUserSession records the session id in the per-user session index scored by its expiry, drops
// entries whose expiry has passed, and extends the index expiry so it never ends before a live entry
func (s *persistentStore) AddUserSession(ctx context.Context, userID, sessionID string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := userSessionsKey(userID)
	now := time.Now()

	_, err := s.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.ZAdd(ctx, key, redis.Z{Score: float64(now.Add(ttl).Unix()), Member: sessionID})
		pipe.ZRemRangeByScore(ctx, key, "-inf", "("+strconv.FormatInt(now.Unix(), 10))
		// NX sets the expiry on a new index, GT only ever moves an existing expiry later
		pipe.ExpireNX(ctx, key, ttl)
		pipe.ExpireGT(ctx, key, ttl)

		return nil
	})

	return err
}

// RemoveUserSession removes the session id from the per-user session index
func (s *persistentStore) RemoveUserSession(ctx context.Context, userID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.client.ZRem(ctx, userSessionsKey(userID), sessionID).Err()
}

// DeleteUserSessions deletes every session recorded for the user along with the index itself; the
// index is watched so a session added while the delete is in flight restarts it instead of surviving
func (s *persistentStore) DeleteUserSessions(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := userSessionsKey(userID)

	deleteIndexed := func(tx *redis.Tx) error {
		ids, err := tx.ZRange(ctx, key, 0, -1).Result()
		if err != nil {
			return err
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, append(ids, key)...)

			return nil
		})

		return err
	}

	var err error

	for range deleteUserSessionsAttempts {
		if err = s.client.Watch(ctx, deleteIndexed, key); !errors.Is(err, redis.TxFailedErr) {
			return err
		}
	}

	return err
}
