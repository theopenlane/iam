package sessions_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/sessions"
)

// errDeleteSession simulates a backing-store failure when deleting a persisted session
var errDeleteSession = errors.New("delete failed")

// failingDeleteStore wraps a PersistentStore but always fails DeleteSession, used to exercise the
// error path of DestroySession
type failingDeleteStore struct {
	sessions.PersistentStore
}

// DeleteSession always returns an error
func (failingDeleteStore) DeleteSession(context.Context, string) error {
	return errDeleteSession
}

// newDestroyTestConfig builds a redis-backed session config sharing a single named cookie config
// between the cookie store and the session config, mirroring how the server wires sessions
func newDestroyTestConfig(t *testing.T) (sessions.SessionConfig, sessions.Store[map[string]any], *miniredis.Miniredis) {
	t.Helper()

	mr, err := miniredis.Run()
	require.NoError(t, err)

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	cc := sessions.DebugOnlyCookieConfig
	sm := sessions.NewCookieStore[map[string]any](cc, []byte("my-signing-secret"), []byte("encryptionsecret"))

	sc := sessions.NewSessionConfig(sm, sessions.WithPersistence(rc))
	sc.CookieConfig = cc

	return sc, sm, mr
}

// requestWithSessionCookie creates a session in the store and returns a request carrying its cookie
func requestWithSessionCookie(t *testing.T, sc sessions.SessionConfig, userID string) *http.Request {
	t.Helper()

	createRec := httptest.NewRecorder()
	_, err := sc.CreateAndStoreSession(context.Background(), createRec, userID)
	require.NoError(t, err)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout", nil)
	for _, c := range createRec.Result().Cookies() {
		req.AddCookie(c)
	}

	return req
}

func TestDestroySession(t *testing.T) {
	ctx := context.Background()

	t.Run("removes the persisted session and expires the cookie", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, "user-123")

		session, err := sc.SessionManager.Get(req, sc.CookieConfig.Name)
		require.NoError(t, err)

		sessionID := sc.SessionManager.GetSessionIDFromCookie(session)
		require.NotEmpty(t, sessionID)

		exists, err := sc.RedisStore.Exists(ctx, sessionID)
		require.NoError(t, err)
		require.Equal(t, int64(1), exists)

		destroyRec := httptest.NewRecorder()
		err = sc.DestroySession(ctx, destroyRec, req)
		require.NoError(t, err)

		// the persisted session is gone
		exists, err = sc.RedisStore.Exists(ctx, sessionID)
		require.NoError(t, err)
		assert.Equal(t, int64(0), exists)

		// the cookie is expired on the response
		cookies := destroyRec.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, sc.CookieConfig.Name, cookies[0].Name)
		assert.Equal(t, -1, cookies[0].MaxAge)
	})

	t.Run("no session cookie is a no-op that still returns nil", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout", nil)
		rec := httptest.NewRecorder()

		err := sc.DestroySession(ctx, rec, req)
		assert.NoError(t, err)
	})

	t.Run("malformed session cookie is a no-op that still returns nil", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout", nil)
		req.AddCookie(&http.Cookie{
			Name:     sc.CookieConfig.Name,
			Value:    "not-a-valid-encoded-cookie",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		rec := httptest.NewRecorder()

		err := sc.DestroySession(ctx, rec, req)
		assert.NoError(t, err)
	})

	t.Run("returns an error and keeps the cookie when the persisted session cannot be deleted", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, "user-err")

		// swap in a store whose DeleteSession always fails
		failing := sc
		failing.RedisStore = failingDeleteStore{PersistentStore: sc.RedisStore}

		destroyRec := httptest.NewRecorder()
		err := failing.DestroySession(ctx, destroyRec, req)

		// the failure is surfaced, not swallowed
		assert.ErrorIs(t, err, errDeleteSession)

		// the cookie is NOT expired, so the client is forced to retry rather than believe it logged out
		assert.Empty(t, destroyRec.Result().Cookies())
	})

	t.Run("expires the cookie without a persistent store", func(t *testing.T) {
		cc := sessions.DebugOnlyCookieConfig
		sm := sessions.NewCookieStore[map[string]any](cc, []byte("my-signing-secret"), []byte("encryptionsecret"))

		// no WithPersistence, so RedisStore is nil
		sc := sessions.NewSessionConfig(sm)
		sc.CookieConfig = cc
		require.Nil(t, sc.RedisStore)

		// manually create a session cookie using the same store
		setRec := httptest.NewRecorder()
		session := sm.New(cc.Name)
		session.Set(sessions.GenerateSessionID(), map[string]any{sessions.UserIDKey: "user-x"})
		require.NoError(t, session.Save(setRec))

		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/logout", nil)
		for _, c := range setRec.Result().Cookies() {
			req.AddCookie(c)
		}

		destroyRec := httptest.NewRecorder()
		err := sc.DestroySession(ctx, destroyRec, req)
		assert.NoError(t, err)

		cookies := destroyRec.Result().Cookies()
		require.Len(t, cookies, 1)
		assert.Equal(t, -1, cookies[0].MaxAge)
	})
}

// TestCookieStoreDestroy covers the fix that makes Store.Destroy build the deletion cookie from the
// full store config rather than only the path, so it reliably matches the original cookie
func TestCookieStoreDestroy(t *testing.T) {
	t.Run("replaces the original cookie with an expired one matching its identity", func(t *testing.T) {
		cfg := &sessions.CookieConfig{
			Name:     "sess",
			Domain:   "example.com",
			Path:     "/app",
			Secure:   true,
			HTTPOnly: true,
			SameSite: http.SameSiteStrictMode,
		}
		cs := sessions.NewCookieStore[map[string]any](cfg, []byte("my-signing-secret"), []byte("encryptionsecret"))

		// set a real session cookie and capture the original that we intend to remove
		setRec := httptest.NewRecorder()
		session := cs.New(cfg.Name)
		session.Set(sessions.GenerateSessionID(), map[string]any{sessions.UserIDKey: "user-x"})
		require.NoError(t, session.Save(setRec))

		setCookies := setRec.Result().Cookies()
		require.Len(t, setCookies, 1)

		original := setCookies[0]
		require.NotEmpty(t, original.Value)
		require.Equal(t, "example.com", original.Domain) // the attribute the buggy deletion dropped

		// destroy and capture the deletion cookie
		destroyRec := httptest.NewRecorder()
		cs.Destroy(destroyRec, cfg.Name)

		delCookies := destroyRec.Result().Cookies()
		require.Len(t, delCookies, 1)

		deletion := delCookies[0]

		// the deletion cookie must share the original's identity (name+domain+path) and security
		// attributes, otherwise the browser stores a second, non-matching cookie and keeps the original.
		// This is exactly what the old Destroy did by dropping Domain/Secure/SameSite
		assert.Equal(t, original.Name, deletion.Name)
		assert.Equal(t, original.Domain, deletion.Domain)
		assert.Equal(t, original.Path, deletion.Path)
		assert.Equal(t, original.Secure, deletion.Secure)
		assert.Equal(t, original.SameSite, deletion.SameSite)

		// and it must actually expire and empty the value so the original is replaced, not duplicated
		assert.Equal(t, -1, deletion.MaxAge)
		assert.Empty(t, deletion.Value)
	})

	t.Run("sets no cookie when no name can be resolved", func(t *testing.T) {
		cfg := &sessions.CookieConfig{Path: "/"} // empty Name
		cs := sessions.NewCookieStore[map[string]any](cfg, []byte("my-signing-secret"), []byte("encryptionsecret"))

		rec := httptest.NewRecorder()
		cs.Destroy(rec, "") // empty name and empty config name resolves to no cookie

		assert.Empty(t, rec.Result().Cookies())
	})
}
