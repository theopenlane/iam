package sessions_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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
	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
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

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Should not skip (default skipper returns false)
	err := middleware(handler)(c)
	assert.Error(t, err) // Will error due to missing session, but not skipped
}
