package sessions_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	echo "github.com/theopenlane/echox"

	"github.com/theopenlane/iam/sessions"
)

// errUserSessionIndex simulates a backing-store failure when writing the per-user session index
var errUserSessionIndex = errors.New("index failed")

// failingIndexStore wraps a PersistentStore but always fails the per-user session index writes
type failingIndexStore struct {
	sessions.PersistentStore
}

// AddUserSession always returns an error
func (failingIndexStore) AddUserSession(context.Context, string, string, time.Duration) error {
	return errUserSessionIndex
}

// RemoveUserSession always returns an error
func (failingIndexStore) RemoveUserSession(context.Context, string, string) error {
	return errUserSessionIndex
}

// indexWriteHook adds a session to the index right after the index is read, standing in for a login
// that lands while DeleteUserSessions is in flight; times bounds how many reads it interferes with
type indexWriteHook struct {
	other  *redis.Client
	userID string
	times  int
	reads  int
}

// DialHook passes dialing through untouched
func (h *indexWriteHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

// ProcessHook writes a new index entry through a second client after each read of the index
func (h *indexWriteHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if err := next(ctx, cmd); err != nil {
			return err
		}

		if cmd.Name() != "zrange" {
			return nil
		}

		h.reads++

		if h.reads > h.times {
			return nil
		}

		late := sessions.NewStore(h.other)
		id := "late-" + time.Now().Format(time.RFC3339Nano)

		if err := late.StoreSessionWithExpiration(ctx, id, h.userID, time.Hour); err != nil {
			return err
		}

		return late.AddUserSession(ctx, h.userID, id, time.Hour)
	}
}

// ProcessPipelineHook passes pipelines through untouched
func (h *indexWriteHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		return next(ctx, cmds)
	}
}

func TestUserSessionIndex(t *testing.T) {
	ctx := context.Background()

	t.Run("add, ttl and remove", func(t *testing.T) {
		ps := sessions.NewStore(newRedisClient())

		defer mr.Close()

		require.NoError(t, ps.AddUserSession(ctx, "u1", "s1", time.Hour))
		require.NoError(t, ps.AddUserSession(ctx, "u1", "s2", time.Hour))

		members, err := mr.ZMembers(sessions.UserSessionsKey("u1"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"s1", "s2"}, members)
		assert.Equal(t, time.Hour, mr.TTL(sessions.UserSessionsKey("u1")))

		require.NoError(t, ps.RemoveUserSession(ctx, "u1", "s1"))

		members, err = mr.ZMembers(sessions.UserSessionsKey("u1"))
		require.NoError(t, err)
		assert.Equal(t, []string{"s2"}, members)
	})

	t.Run("a shorter lived session never shortens the index expiry", func(t *testing.T) {
		ps := sessions.NewStore(newRedisClient())

		defer mr.Close()

		require.NoError(t, ps.AddUserSession(ctx, "u1", "long", time.Hour))
		require.NoError(t, ps.AddUserSession(ctx, "u1", "short", time.Minute))
		assert.Equal(t, time.Hour, mr.TTL(sessions.UserSessionsKey("u1")))

		require.NoError(t, ps.AddUserSession(ctx, "u1", "longer", 2*time.Hour))
		assert.Equal(t, 2*time.Hour, mr.TTL(sessions.UserSessionsKey("u1")))
	})

	t.Run("entries whose expiry has passed are dropped on the next add", func(t *testing.T) {
		ps := sessions.NewStore(newRedisClient())

		defer mr.Close()

		// an entry recorded with an expiry in the past stands in for a session that has since expired
		require.NoError(t, ps.AddUserSession(ctx, "u1", "live", time.Hour))

		_, err := mr.ZAdd(sessions.UserSessionsKey("u1"), float64(time.Now().Add(-time.Minute).Unix()), "stale")
		require.NoError(t, err)

		require.NoError(t, ps.AddUserSession(ctx, "u1", "new", time.Hour))

		members, err := mr.ZMembers(sessions.UserSessionsKey("u1"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"live", "new"}, members)
	})

	t.Run("delete removes every session key and the index", func(t *testing.T) {
		ps := sessions.NewStore(newRedisClient())

		defer mr.Close()

		for _, id := range []string{"s1", "s2"} {
			require.NoError(t, ps.StoreSessionWithExpiration(ctx, id, "u1", time.Hour))
			require.NoError(t, ps.AddUserSession(ctx, "u1", id, time.Hour))
		}

		require.NoError(t, ps.StoreSessionWithExpiration(ctx, "other", "u2", time.Hour))
		require.NoError(t, ps.AddUserSession(ctx, "u2", "other", time.Hour))

		require.NoError(t, ps.DeleteUserSessions(ctx, "u1"))

		assert.False(t, mr.Exists("s1"))
		assert.False(t, mr.Exists("s2"))
		assert.False(t, mr.Exists(sessions.UserSessionsKey("u1")))
		assert.True(t, mr.Exists("other"))
		assert.True(t, mr.Exists(sessions.UserSessionsKey("u2")))
	})

	t.Run("delete restarts when a session is added while it is in flight", func(t *testing.T) {
		client := newRedisClient()
		ps := sessions.NewStore(client)

		defer mr.Close()

		require.NoError(t, ps.StoreSessionWithExpiration(ctx, "s1", "u1", time.Hour))
		require.NoError(t, ps.AddUserSession(ctx, "u1", "s1", time.Hour))

		hook := &indexWriteHook{other: redis.NewClient(&redis.Options{Addr: mr.Addr()}), userID: "u1", times: 1}
		client.AddHook(hook)

		require.NoError(t, ps.DeleteUserSessions(ctx, "u1"))

		// the first attempt was abandoned, the second also removed the session added in between
		assert.Equal(t, 2, hook.reads)
		assert.Empty(t, mr.Keys())
	})

	t.Run("delete gives up when the index keeps changing", func(t *testing.T) {
		client := newRedisClient()
		ps := sessions.NewStore(client)

		defer mr.Close()

		require.NoError(t, ps.AddUserSession(ctx, "u1", "s1", time.Hour))

		hook := &indexWriteHook{other: redis.NewClient(&redis.Options{Addr: mr.Addr()}), userID: "u1", times: 100}
		client.AddHook(hook)

		assert.ErrorIs(t, ps.DeleteUserSessions(ctx, "u1"), redis.TxFailedErr)
		assert.True(t, mr.Exists(sessions.UserSessionsKey("u1")))
	})

	t.Run("delete with no sessions is a no-op", func(t *testing.T) {
		ps := sessions.NewStore(newRedisClient())

		defer mr.Close()

		require.NoError(t, ps.DeleteUserSessions(ctx, "nobody"))
	})
}

func TestSessionConfigUserSessions(t *testing.T) {
	ctx := context.Background()

	t.Run("create populates the index and destroy session removes the entry", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, "user-1")

		session, err := sc.SessionManager.Get(req, sc.CookieConfig.Name)
		require.NoError(t, err)

		sessionID := sc.SessionManager.GetSessionIDFromCookie(session)

		members, err := mr.ZMembers(sessions.UserSessionsKey("user-1"))
		require.NoError(t, err)
		assert.Equal(t, []string{sessionID}, members)
		assert.Positive(t, mr.TTL(sessions.UserSessionsKey("user-1")))

		require.NoError(t, sc.DestroySession(ctx, httptest.NewRecorder(), req))

		assert.False(t, mr.Exists(sessions.UserSessionsKey("user-1")))

		// destroying a session that is already gone stays a successful no-op
		require.NoError(t, sc.DestroySession(ctx, httptest.NewRecorder(), req))
	})

	t.Run("create fails and sets no cookie when the index cannot be written", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.RedisStore = failingIndexStore{sc.RedisStore}

		rec := httptest.NewRecorder()
		_, err := sc.CreateAndStoreSession(ctx, rec, "user-1")

		assert.ErrorIs(t, err, errUserSessionIndex)
		assert.Empty(t, rec.Result().Cookies())
	})

	t.Run("destroy session surfaces an index removal failure and keeps the cookie", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, "user-1")

		failing := sc
		failing.RedisStore = failingIndexStore{sc.RedisStore}

		rec := httptest.NewRecorder()

		assert.ErrorIs(t, failing.DestroySession(ctx, rec, req), errUserSessionIndex)
		assert.Empty(t, rec.Result().Cookies())
	})

	t.Run("sliding a session extends the index expiry", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, "user-1")

		mr.FastForward(10 * time.Minute)

		before := mr.TTL(sessions.UserSessionsKey("user-1"))

		rec := httptest.NewRecorder()
		handler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
		require.NoError(t, sessions.LoadAndSaveWithConfig(sc)(handler)(echo.New().NewContext(req, rec)))

		assert.Greater(t, mr.TTL(sessions.UserSessionsKey("user-1")), before)
	})

	t.Run("sliding a session sets no cookie when the index cannot be written", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, "user-1")

		sc.RedisStore = failingIndexStore{sc.RedisStore}

		rec := httptest.NewRecorder()
		handler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
		require.NoError(t, sessions.LoadAndSaveWithConfig(sc)(handler)(echo.New().NewContext(req, rec)))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, sessionCookies(rec, sc.CookieConfig.Name))
	})

	t.Run("renewing a session indexes the new id and shortens the superseded entry to the grace period", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.RenewalInterval = 0

		req := requestWithSessionCookie(t, sc, "user-1")
		oldID := sessionIDFromCookie(t, sc, req.Cookies()[0])

		rec := httptest.NewRecorder()
		handler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
		require.NoError(t, sessions.LoadAndSaveWithConfig(sc)(handler)(echo.New().NewContext(req, rec)))

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)

		newID := sessionIDFromCookie(t, sc, cookies[0])

		members, err := mr.ZMembers(sessions.UserSessionsKey("user-1"))
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{oldID, newID}, members)

		graceDeadline := float64(time.Now().Add(sc.RenewalGrace).Unix())

		oldScore, err := mr.ZScore(sessions.UserSessionsKey("user-1"), oldID)
		require.NoError(t, err)
		assert.LessOrEqual(t, oldScore, graceDeadline)

		newScore, err := mr.ZScore(sessions.UserSessionsKey("user-1"), newID)
		require.NoError(t, err)
		assert.Greater(t, newScore, graceDeadline)

		// both the superseded and the renewed session are removed with the user's sessions
		require.NoError(t, sc.DestroyUserSessions(ctx, "user-1"))
		assert.Empty(t, mr.Keys())
	})

	t.Run("destroy user sessions leaves other users intact and stops the cookie loading", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		reqA1 := requestWithSessionCookie(t, sc, "user-a")
		reqA2 := requestWithSessionCookie(t, sc, "user-a")
		reqB := requestWithSessionCookie(t, sc, "user-b")

		require.Len(t, mr.Keys(), 5)

		require.NoError(t, sc.DestroyUserSessions(ctx, "user-a"))

		assert.False(t, mr.Exists(sessions.UserSessionsKey("user-a")))
		assert.True(t, mr.Exists(sessions.UserSessionsKey("user-b")))
		assert.Len(t, mr.Keys(), 2)

		middleware := sessions.LoadAndSaveWithConfig(sc)
		handler := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }
		e := echo.New()

		for _, req := range []*http.Request{reqA1, reqA2} {
			rec := httptest.NewRecorder()
			assert.Error(t, middleware(handler)(e.NewContext(req, rec)))
		}

		rec := httptest.NewRecorder()
		require.NoError(t, middleware(handler)(e.NewContext(reqB, rec)))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
