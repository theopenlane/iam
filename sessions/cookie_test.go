package sessions_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/sessions"
)

func TestNewCookieConfig(t *testing.T) {
	tests := []struct {
		name             string
		secure           bool
		expectedSameSite http.SameSite
	}{
		{
			name:             "secure config",
			secure:           true,
			expectedSameSite: http.SameSiteStrictMode,
		},
		{
			name:             "insecure config",
			secure:           false,
			expectedSameSite: http.SameSiteLaxMode,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := sessions.NewCookieConfig(tc.secure)

			assert.Equal(t, "/", config.Path)
			assert.Equal(t, 3600, config.MaxAge) // 1 hour
			assert.True(t, config.HTTPOnly)
			assert.Equal(t, tc.secure, config.Secure)
			assert.Equal(t, tc.expectedSameSite, config.SameSite)
		})
	}
}

func TestNewCookie(t *testing.T) {
	tests := []struct {
		name         string
		cookieName   string
		value        string
		config       *sessions.CookieConfig
		expectedName string
		expectNil    bool
	}{
		{
			name:       "valid cookie with name",
			cookieName: "test-cookie",
			value:      "test-value",
			config: &sessions.CookieConfig{
				Name:     "config-cookie",
				Path:     "/",
				MaxAge:   3600,
				HTTPOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			},
			expectedName: "test-cookie",
			expectNil:    false,
		},
		{
			name:       "use config name when cookie name empty",
			cookieName: "",
			value:      "test-value",
			config: &sessions.CookieConfig{
				Name:     "config-cookie",
				Path:     "/",
				MaxAge:   3600,
				HTTPOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			},
			expectedName: "config-cookie",
			expectNil:    false,
		},
		{
			name:       "nil when both names empty",
			cookieName: "",
			value:      "test-value",
			config: &sessions.CookieConfig{
				Name:     "",
				Path:     "/",
				MaxAge:   3600,
				HTTPOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			},
			expectedName: "",
			expectNil:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cookie := sessions.NewCookie(tc.cookieName, tc.value, tc.config)

			if tc.expectNil {
				assert.Nil(t, cookie)
				return
			}

			assert.NotNil(t, cookie)
			assert.Equal(t, tc.expectedName, cookie.Name)
			assert.Equal(t, tc.value, cookie.Value)
			assert.Equal(t, tc.config.Path, cookie.Path)
			assert.Equal(t, tc.config.Domain, cookie.Domain)
			assert.Equal(t, tc.config.MaxAge, cookie.MaxAge)
			assert.Equal(t, tc.config.HTTPOnly, cookie.HttpOnly)
			assert.Equal(t, tc.config.Secure, cookie.Secure)
			assert.Equal(t, tc.config.SameSite, cookie.SameSite)

			// Test expires time calculation
			if tc.config.MaxAge > 0 {
				assert.False(t, cookie.Expires.IsZero())
				assert.True(t, cookie.Expires.After(time.Now()))
			}
		})
	}
}

func TestExpiresTime(t *testing.T) {
	tests := []struct {
		name       string
		maxAge     int
		expectTime bool
	}{
		{
			name:       "positive max age",
			maxAge:     3600,
			expectTime: true,
		},
		{
			name:       "negative max age",
			maxAge:     -1,
			expectTime: true,
		},
		{
			name:       "zero max age",
			maxAge:     0,
			expectTime: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// We can't test the internal expiresTime function directly since it's not exported,
			// but we can test it through NewCookie
			config := &sessions.CookieConfig{
				Name:   "test",
				MaxAge: tc.maxAge,
			}

			cookie := sessions.NewCookie("test", "value", config)
			assert.NotNil(t, cookie)

			if tc.expectTime {
				assert.False(t, cookie.Expires.IsZero())

				if tc.maxAge > 0 {
					assert.True(t, cookie.Expires.After(time.Now()))
				} else {
					// Negative MaxAge should set expires to Unix epoch + 1 second
					assert.Equal(t, time.Unix(1, 0), cookie.Expires)
				}
			} else {
				assert.True(t, cookie.Expires.IsZero())
			}
		})
	}
}

func TestGetCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieName string
		cookies    []*http.Cookie
		expectErr  bool
	}{
		{
			name:       "cookie exists",
			cookieName: "test-cookie",
			cookies: []*http.Cookie{
				{Name: "test-cookie", Value: "test-value"},
				{Name: "other-cookie", Value: "other-value"},
			},
			expectErr: false,
		},
		{
			name:       "cookie does not exist",
			cookieName: "missing-cookie",
			cookies: []*http.Cookie{
				{Name: "test-cookie", Value: "test-value"},
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, cookie := range tc.cookies {
				req.AddCookie(cookie)
			}

			cookie, err := sessions.GetCookie(req, tc.cookieName)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, cookie)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cookie)
				assert.Equal(t, tc.cookieName, cookie.Name)
			}
		})
	}
}

func TestCookieExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		cookie   *http.Cookie
		expected bool
	}{
		{
			name: "not expired - future expires",
			cookie: &http.Cookie{
				Name:    "test",
				Expires: now.Add(time.Hour),
				MaxAge:  3600,
			},
			expected: false,
		},
		{
			name: "expired - past expires",
			cookie: &http.Cookie{
				Name:    "test",
				Expires: now.Add(-time.Hour),
				MaxAge:  3600,
			},
			expected: true,
		},
		{
			name: "expired - negative MaxAge",
			cookie: &http.Cookie{
				Name:   "test",
				MaxAge: -1,
			},
			expected: true,
		},
		{
			name: "not expired - no expires set and positive MaxAge",
			cookie: &http.Cookie{
				Name:   "test",
				MaxAge: 3600,
			},
			expected: false,
		},
		{
			name: "not expired - zero expires and zero MaxAge",
			cookie: &http.Cookie{
				Name:   "test",
				MaxAge: 0,
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := sessions.CookieExpired(tc.cookie)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSetCookieB64(t *testing.T) {
	recorder := httptest.NewRecorder()
	body := []byte("test data")
	cookieName := "test-cookie"
	config := sessions.CookieConfig{
		Path:     "/",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	result := sessions.SetCookieB64(recorder, body, cookieName, config)

	// Check that a cookie was set
	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, cookieName, cookie.Name)
	assert.Equal(t, result, cookie.Value)

	// Verify the value is base64 encoded
	assert.Equal(t, "dGVzdCBkYXRh", result) // base64 of "test data"
}

func TestSetCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	value := "test-value"
	cookieName := "test-cookie"
	config := sessions.CookieConfig{
		Path:     "/",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	sessions.SetCookie(recorder, value, cookieName, config)

	// Check that a cookie was set
	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, cookieName, cookie.Name)
	assert.Equal(t, value, cookie.Value)
	assert.Equal(t, config.Path, cookie.Path)
	assert.Equal(t, config.MaxAge, cookie.MaxAge)
	assert.Equal(t, config.HTTPOnly, cookie.HttpOnly)
	assert.Equal(t, config.Secure, cookie.Secure)
	assert.Equal(t, config.SameSite, cookie.SameSite)
}

func TestRemoveCookie(t *testing.T) {
	recorder := httptest.NewRecorder()
	cookieName := "test-cookie"
	config := sessions.CookieConfig{
		Path:     "/",
		MaxAge:   3600,
		HTTPOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	}

	sessions.RemoveCookie(recorder, cookieName, config)

	// Check that a cookie was set with MaxAge -1 for deletion
	cookies := recorder.Result().Cookies()
	assert.Len(t, cookies, 1)

	cookie := cookies[0]
	assert.Equal(t, cookieName, cookie.Name)
	assert.Equal(t, "", cookie.Value)
	assert.Equal(t, -1, cookie.MaxAge)
}

func TestCookieConfigDefaults(t *testing.T) {
	// Test DefaultCookieConfig
	assert.True(t, sessions.DefaultCookieConfig.Secure)
	assert.True(t, sessions.DefaultCookieConfig.HTTPOnly)
	assert.Equal(t, http.SameSiteStrictMode, sessions.DefaultCookieConfig.SameSite)
	assert.Equal(t, "/", sessions.DefaultCookieConfig.Path)
	assert.Equal(t, 3600, sessions.DefaultCookieConfig.MaxAge)

	// Test DebugCookieConfig
	assert.False(t, sessions.DebugCookieConfig.Secure)
	assert.True(t, sessions.DebugCookieConfig.HTTPOnly)
	assert.Equal(t, http.SameSiteLaxMode, sessions.DebugCookieConfig.SameSite)
	assert.Equal(t, "/", sessions.DebugCookieConfig.Path)
	assert.Equal(t, 3600, sessions.DebugCookieConfig.MaxAge)

	// Test DebugOnlyCookieConfig
	assert.Equal(t, sessions.DevCookieName, sessions.DebugOnlyCookieConfig.Name)
	assert.False(t, sessions.DebugOnlyCookieConfig.Secure)
	assert.True(t, sessions.DebugOnlyCookieConfig.HTTPOnly)
	assert.Equal(t, http.SameSiteLaxMode, sessions.DebugOnlyCookieConfig.SameSite)
	assert.Equal(t, "/", sessions.DebugOnlyCookieConfig.Path)
	assert.Equal(t, 3600, sessions.DebugOnlyCookieConfig.MaxAge)
}
