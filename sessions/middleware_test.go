package sessions_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	echo "github.com/theopenlane/echox"

	"github.com/theopenlane/iam/sessions"
)

func TestNewSessionConfig(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	config := sessions.NewSessionConfig(cs)

	assert.NotNil(t, config.SessionManager)
	assert.NotNil(t, config.Skipper)
	assert.Nil(t, config.RedisClient)
	assert.Nil(t, config.RedisStore)
}

func TestNewSessionConfig_WithOptions(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	// Test skipper function
	skipperCalled := false
	skipper := func(_ echo.Context) bool {
		skipperCalled = true
		return false
	}

	// Test before function
	beforeCalled := false
	before := func(_ echo.Context) {
		beforeCalled = true
	}

	config := sessions.NewSessionConfig(cs,
		sessions.WithSkipperFunc(skipper),
		sessions.WithBeforeFunc(before),
		sessions.WithMaxAge(7200),
	)

	assert.NotNil(t, config.SessionManager)
	assert.NotNil(t, config.Skipper)
	assert.NotNil(t, config.CookieConfig)
	assert.Equal(t, 7200, config.CookieConfig.MaxAge)

	// Test that skipper function is set
	e := echo.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	result := config.Skipper(c)
	assert.False(t, result)
	assert.True(t, skipperCalled)

	// Test before function
	config.BeforeFunc(c)
	assert.True(t, beforeCalled)
}

func TestWithSkipperFunc(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	called := false
	skipper := func(_ echo.Context) bool {
		called = true
		return true
	}

	config := sessions.NewSessionConfig(cs, sessions.WithSkipperFunc(skipper))

	e := echo.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	result := config.Skipper(c)
	assert.True(t, result)
	assert.True(t, called)
}

func TestWithBeforeFunc(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	called := false
	before := func(_ echo.Context) {
		called = true
	}

	config := sessions.NewSessionConfig(cs, sessions.WithBeforeFunc(before))

	e := echo.New()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	config.BeforeFunc(c)
	assert.True(t, called)
}

func TestWithMaxAge(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	config := sessions.NewSessionConfig(cs, sessions.WithMaxAge(7200))

	assert.NotNil(t, config.CookieConfig)
	assert.Equal(t, 7200, config.CookieConfig.MaxAge)
}

func TestLoadAndSave(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](&sessions.CookieConfig{
		Name:     "test-session",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}, []byte("my-signing-secret"), []byte("encryptionsecret"))

	// Create middleware
	middleware := sessions.LoadAndSave(cs)

	assert.NotNil(t, middleware)
}

func TestLoadAndSaveWithConfig_Skipped(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	// Configure to skip all requests
	config := sessions.NewSessionConfig(cs, sessions.WithSkipperFunc(func(_ echo.Context) bool {
		return true
	}))

	middleware := sessions.LoadAndSaveWithConfig(config)

	e := echo.New()
	handlerCalled := false
	handler := func(c echo.Context) error {
		handlerCalled = true
		return c.String(http.StatusOK, "ok")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := middleware(handler)(c)
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestLoadAndSaveWithConfig_MissingSession(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](&sessions.CookieConfig{
		Name:     "test-session",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}, []byte("my-signing-secret"), []byte("encryptionsecret"))

	config := sessions.NewSessionConfig(cs)
	config.CookieConfig = &sessions.CookieConfig{
		Name:   "test-session",
		MaxAge: 3600,
	}

	middleware := sessions.LoadAndSaveWithConfig(config)

	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := middleware(handler)(c)
	assert.Error(t, err)
}

func TestLoadAndSaveWithConfig_DefaultSkipper(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	// Don't set a skipper - should use default, but need CookieConfig
	config := sessions.SessionConfig{
		SessionManager: cs,
		CookieConfig: &sessions.CookieConfig{
			Name:   "test-session",
			MaxAge: 3600,
		},
	}

	middleware := sessions.LoadAndSaveWithConfig(config)

	e := echo.New()
	handler := func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Should not skip (default skipper returns false)
	err := middleware(handler)(c)
	assert.Error(t, err) // Will error due to missing session, but not skipped
}

func TestLoadAndSaveWithConfig_FallbackUserID(t *testing.T) {
	const userID = "user-123"

	t.Run("mints a session for the resolved user when the request carries none", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.FallbackUserID = func(context.Context) (string, bool) { return userID, true }

		middleware := sessions.LoadAndSaveWithConfig(sc)

		e := echo.New()
		handler := func(c echo.Context) error {
			_, err := sessions.SessionToken(c.Request().Context())
			require.NoError(t, err)

			return c.String(http.StatusOK, "ok")
		}

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(handler)(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)

		stored, err := sc.RedisStore.GetSession(context.Background(), sessionIDFromCookie(t, sc, cookies[0]))
		require.NoError(t, err)
		assert.Equal(t, userID, stored)
	})

	t.Run("replaces a session the store no longer holds", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.FallbackUserID = func(context.Context) (string, bool) { return userID, true }

		req := requestWithSessionCookie(t, sc, userID)

		mr.FlushAll()

		stale, err := sc.SessionManager.Get(req, sc.CookieConfig.Name)
		require.NoError(t, err)

		staleID := sc.SessionManager.GetSessionIDFromCookie(stale)

		middleware := sessions.LoadAndSaveWithConfig(sc)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		}

		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err = middleware(handler)(c)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)
		assert.NotEqual(t, staleID, sessionIDFromCookie(t, sc, cookies[0]))
	})

	t.Run("marks the minted response as uncacheable", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.FallbackUserID = func(context.Context) (string, bool) { return userID, true }

		middleware := sessions.LoadAndSaveWithConfig(sc)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		}

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		require.NoError(t, middleware(handler)(c))
		assert.Equal(t, `no-cache="Set-Cookie"`, rec.Header().Get("Cache-Control"))
		assert.Equal(t, "Cookie", rec.Header().Get("Vary"))
	})

	t.Run("rejects the request when the fallback reports an empty user", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.FallbackUserID = func(context.Context) (string, bool) { return "", true }

		middleware := sessions.LoadAndSaveWithConfig(sc)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		}

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(handler)(c)
		assert.ErrorIs(t, err, sessions.ErrInvalidSession)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Empty(t, sessionCookies(rec, sc.CookieConfig.Name))
	})

	t.Run("sets no cookie when the store rejects the minted session", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.FallbackUserID = func(context.Context) (string, bool) { return userID, true }
		sc.RedisStore = failingStoreSession{sc.RedisStore}

		middleware := sessions.LoadAndSaveWithConfig(sc)

		e := echo.New()
		handler := func(c echo.Context) error {
			return c.String(http.StatusOK, "ok")
		}

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(handler)(c)
		assert.ErrorIs(t, err, sessions.ErrInvalidSession)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Empty(t, sessionCookies(rec, sc.CookieConfig.Name))
	})

	t.Run("rejects the request when the fallback reports no user", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.FallbackUserID = func(context.Context) (string, bool) { return "", false }

		middleware := sessions.LoadAndSaveWithConfig(sc)

		e := echo.New()
		handlerCalled := false
		handler := func(c echo.Context) error {
			handlerCalled = true

			return c.String(http.StatusOK, "ok")
		}

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := middleware(handler)(c)
		assert.ErrorIs(t, err, sessions.ErrInvalidSession)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, handlerCalled)
	})
}

// sessionCookies returns the response cookies with the given name
func sessionCookies(rec *httptest.ResponseRecorder, name string) []*http.Cookie {
	var found []*http.Cookie

	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			found = append(found, c)
		}
	}

	return found
}

// sessionIDFromCookie returns the session id carried by a response cookie
func sessionIDFromCookie(t *testing.T, sc sessions.SessionConfig, cookie *http.Cookie) string {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	session, err := sc.SessionManager.Get(req, sc.CookieConfig.Name)
	require.NoError(t, err)

	return sc.SessionManager.GetSessionIDFromCookie(session)
}

// errStoreSession simulates a backing-store failure when persisting a session
var errStoreSession = errors.New("store failed")

// failingStoreSession wraps a PersistentStore but always fails StoreSessionWithExpiration
type failingStoreSession struct {
	sessions.PersistentStore
}

// StoreSessionWithExpiration always returns an error
func (failingStoreSession) StoreSessionWithExpiration(context.Context, string, string, time.Duration) error {
	return errStoreSession
}

// requestWithCraftedSession persists a session with the given timestamps and returns a request carrying its cookie
func requestWithCraftedSession(t *testing.T, sc sessions.SessionConfig, sm sessions.Store[map[string]any], userID string, values map[string]any) (*http.Request, string) {
	t.Helper()

	id := sessions.GenerateSessionID()
	values[sessions.UserIDKey] = userID

	session := sm.New(sc.CookieConfig.Name)
	session.Set(id, values)

	rec := httptest.NewRecorder()
	require.NoError(t, sm.Save(rec, session))
	require.NoError(t, sc.RedisStore.StoreSessionWithExpiration(context.Background(), id, userID, time.Hour))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}

	return req, id
}

// cookieSessionValues returns the session map carried by a response cookie
func cookieSessionValues(t *testing.T, sc sessions.SessionConfig, cookie *http.Cookie) map[string]any {
	t.Helper()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.AddCookie(cookie)

	session, err := sc.SessionManager.Get(req, sc.CookieConfig.Name)
	require.NoError(t, err)

	return sc.SessionManager.GetSessionDataFromCookie(session).(map[string]any)
}

func TestLoadAndSaveWithConfig_Lifecycle(t *testing.T) {
	const userID = "user-123"

	ok := func(c echo.Context) error { return c.String(http.StatusOK, "ok") }

	t.Run("slides a recently renewed session without changing its id", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req := requestWithSessionCookie(t, sc, userID)
		id := sessionIDFromCookie(t, sc, req.Cookies()[0])

		mr.FastForward(10 * time.Minute)

		before := mr.TTL(id)

		rec := httptest.NewRecorder()
		require.NoError(t, sessions.LoadAndSaveWithConfig(sc)(ok)(echo.New().NewContext(req, rec)))

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)
		assert.Equal(t, id, sessionIDFromCookie(t, sc, cookies[0]))
		assert.Greater(t, mr.TTL(id), before)
	})

	t.Run("renews the session id after the renewal interval", func(t *testing.T) {
		sc, sm, mr := newDestroyTestConfig(t)
		defer mr.Close()

		created := time.Now().Add(-time.Hour).Unix()
		req, id := requestWithCraftedSession(t, sc, sm, userID, map[string]any{
			sessions.CreatedAtKey: created,
			sessions.RenewedAtKey: time.Now().Add(-sc.RenewalInterval - time.Minute).Unix(),
		})

		rec := httptest.NewRecorder()
		require.NoError(t, sessions.LoadAndSaveWithConfig(sc)(ok)(echo.New().NewContext(req, rec)))

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)
		assert.NotEqual(t, id, sessionIDFromCookie(t, sc, cookies[0]))

		values := cookieSessionValues(t, sc, cookies[0])
		assert.Equal(t, created, values[sessions.CreatedAtKey])
		assert.Greater(t, values[sessions.RenewedAtKey], created)

		assert.Positive(t, mr.TTL(id))
		assert.LessOrEqual(t, mr.TTL(id), sc.RenewalGrace)

		mr.FastForward(sc.RenewalGrace + time.Second)
		assert.False(t, mr.Exists(id))
	})

	t.Run("renews on every request when the renewal interval is zero", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.RenewalInterval = 0

		req := requestWithSessionCookie(t, sc, userID)
		id := sessionIDFromCookie(t, sc, req.Cookies()[0])

		rec := httptest.NewRecorder()
		require.NoError(t, sessions.LoadAndSaveWithConfig(sc)(ok)(echo.New().NewContext(req, rec)))

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)
		assert.NotEqual(t, id, sessionIDFromCookie(t, sc, cookies[0]))
	})

	t.Run("rejects a session past its absolute timeout and deletes it", func(t *testing.T) {
		sc, sm, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req, id := requestWithCraftedSession(t, sc, sm, userID, map[string]any{
			sessions.CreatedAtKey: time.Now().Add(-sc.AbsoluteTimeout - time.Minute).Unix(),
			sessions.RenewedAtKey: time.Now().Unix(),
		})

		rec := httptest.NewRecorder()
		err := sessions.LoadAndSaveWithConfig(sc)(ok)(echo.New().NewContext(req, rec))
		assert.ErrorIs(t, err, sessions.ErrSessionExpired)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, mr.Exists(id))
	})

	t.Run("rejects a legacy session without a created time", func(t *testing.T) {
		sc, sm, mr := newDestroyTestConfig(t)
		defer mr.Close()

		req, id := requestWithCraftedSession(t, sc, sm, userID, map[string]any{})

		rec := httptest.NewRecorder()
		err := sessions.LoadAndSaveWithConfig(sc)(ok)(echo.New().NewContext(req, rec))
		assert.ErrorIs(t, err, sessions.ErrSessionExpired)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, mr.Exists(id))
	})

	t.Run("caps the store ttl at the absolute timeout", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.AbsoluteTimeout = 10 * time.Minute

		req := requestWithSessionCookie(t, sc, userID)
		id := sessionIDFromCookie(t, sc, req.Cookies()[0])

		assert.Positive(t, mr.TTL(id))
		assert.LessOrEqual(t, mr.TTL(id), sc.AbsoluteTimeout)
	})

	t.Run("does not re-mint a session the handler destroyed", func(t *testing.T) {
		sc, _, mr := newDestroyTestConfig(t)
		defer mr.Close()

		sc.RenewalInterval = 0

		req := requestWithSessionCookie(t, sc, userID)
		rec := httptest.NewRecorder()

		err := sessions.LoadAndSaveWithConfig(sc)(func(c echo.Context) error {
			require.NoError(t, sc.DestroySession(c.Request().Context(), c.Response(), c.Request()))

			return c.NoContent(http.StatusNoContent)
		})(echo.New().NewContext(req, rec))
		require.NoError(t, err)

		cookies := sessionCookies(rec, sc.CookieConfig.Name)
		require.Len(t, cookies, 1)
		assert.Negative(t, cookies[0].MaxAge)
		assert.Empty(t, mr.Keys())
	})
}
