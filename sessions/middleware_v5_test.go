package sessions_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	echo "github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/sessions"
)

func newV5Context(e *echo.Echo) (*echo.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	return e.NewContext(req, rec), rec
}

func TestMiddlewareSkipped(t *testing.T) {
	cs := sessions.NewCookieStore[map[string]any](sessions.DebugCookieConfig,
		[]byte("my-signing-secret"), []byte("encryptionsecret"))

	config := sessions.NewSessionConfig(cs)

	middleware := sessions.Middleware(config, func(_ *echo.Context) bool {
		return true
	})

	e := echo.New()

	handlerCalled := false
	handler := func(c *echo.Context) error {
		handlerCalled = true
		return c.String(http.StatusOK, "ok")
	}

	c, rec := newV5Context(e)

	err := middleware(handler)(c)
	assert.NoError(t, err)
	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestMiddlewareMissingSession(t *testing.T) {
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

	middleware := sessions.Middleware(config, nil)

	e := echo.New()
	handler := func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	}

	c, rec := newV5Context(e)

	// the middleware writes the unauthorized reply and returns the session error
	err := middleware(handler)(c)
	assert.Error(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
