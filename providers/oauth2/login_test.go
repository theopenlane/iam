package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/theopenlane/utils/testutils"

	"github.com/theopenlane/iam/sessions"
)

const (
	FailureHandlerCalled = "failure handler called"
	CodePath             = "/?code=any_code&state=d4e5f6"
	SuccessHandlerCalled = "success handler called"
)

func TestLoginHandler(t *testing.T) {
	expectedState := "state_val"
	expectedRedirect := "https://api.example.com/authorize?client_id=client_id&redirect_uri=redirect_url&response_type=code&state=state_val"
	config := &oauth2.Config{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "redirect_url",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://api.example.com/authorize",
		},
	}

	failure := testutils.AssertFailureNotCalled(t)

	loginHandler := LoginHandler(config, failure)
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil) // nolint: noctx

	ctx := WithState(context.Background(), expectedState)
	loginHandler.ServeHTTP(w, req.WithContext(ctx))

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, expectedRedirect, w.Result().Header.Get("Location")) // nolint: bodyclose
}

func TestLoginState(t *testing.T) {
	config := &oauth2.Config{}
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			assert.Equal(t, "oauth2: context missing state value", err.Error())
		}

		fmt.Fprint(w, FailureHandlerCalled)
	}

	loginHandler := LoginHandler(config, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil) // nolint: noctx
	loginHandler.ServeHTTP(w, req.WithContext(req.Context()))
	assert.Equal(t, FailureHandlerCalled, w.Body.String())
}

func TestCallbackHandler(t *testing.T) {
	jsonData := `{
       "access_token":"2YotnFZFEjr1zCsicMWpAA",
       "token_type":"example",
       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
       "example_parameter":"example_value"
     }`
	expectedToken := &oauth2.Token{ //nolint:gosec // used in tests only, not real credentials
		AccessToken:  "2YotnFZFEjr1zCsicMWpAA",
		TokenType:    "example",
		RefreshToken: "tGzv3JOkF0XG5Qx2TlKWIA",
	}

	server := NewAccessTokenServer(t, jsonData)
	defer server.Close()

	config := &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}

	success := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		token, err := TokenFromContext(ctx)
		assert.Equal(t, expectedToken.AccessToken, token.AccessToken)
		assert.Equal(t, expectedToken.TokenType, token.Type())
		assert.Equal(t, expectedToken.RefreshToken, token.RefreshToken)
		// real oauth2.Token populates internal raw field and unmockable Expiry time
		assert.Nil(t, err)
		fmt.Fprint(w, SuccessHandlerCalled)
	}

	failure := testutils.AssertFailureNotCalled(t)
	callbackHandler := CallbackHandler(config, http.HandlerFunc(success), failure)
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, CodePath, nil) // nolint: noctx
	ctx := WithState(context.Background(), "d4e5f6")
	callbackHandler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, SuccessHandlerCalled, w.Body.String())
}

func TestParseCallback(t *testing.T) {
	config := &oauth2.Config{}
	success := testutils.AssertSuccessNotCalled(t)
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			assert.Equal(t, "oauth2: request missing code or state", err.Error())
		}

		fmt.Fprint(w, FailureHandlerCalled)
	}

	callbackHandler := CallbackHandler(config, success, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "/?code=any_code", nil)
	callbackHandler.ServeHTTP(w, req.WithContext(req.Context()))
	assert.Equal(t, FailureHandlerCalled, w.Body.String())

	w = httptest.NewRecorder()
	req, _ = http.NewRequestWithContext(req.Context(), http.MethodGet, "/?state=any_state", nil)
	callbackHandler.ServeHTTP(w, req.WithContext(req.Context()))
	assert.Equal(t, FailureHandlerCalled, w.Body.String())
}

func TestStateHandler(t *testing.T) {
	config := &oauth2.Config{}
	success := testutils.AssertSuccessNotCalled(t)
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			assert.Equal(t, "oauth2: context missing state value", err.Error())
		}

		fmt.Fprint(w, FailureHandlerCalled)
	}

	callbackHandler := CallbackHandler(config, success, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, CodePath, nil) // nolint: noctx
	callbackHandler.ServeHTTP(w, req.WithContext(req.Context()))
	assert.Equal(t, FailureHandlerCalled, w.Body.String())
}

func TestStateFromContext(t *testing.T) {
	config := &oauth2.Config{}
	success := testutils.AssertSuccessNotCalled(t)
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			assert.Equal(t, "oauth2: invalid oauth2 state parameter", err.Error())
		}

		fmt.Fprint(w, FailureHandlerCalled)
	}

	callbackHandler := CallbackHandler(config, success, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, CodePath, nil) // nolint: noctx
	ctx := WithState(context.Background(), "differentState")
	callbackHandler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, FailureHandlerCalled, w.Body.String())
}

func TestTokenExchange(t *testing.T) {
	_, server := testutils.NewErrorServer("oAuth is no auth'in", http.StatusInternalServerError)
	defer server.Close()

	config := &oauth2.Config{
		Endpoint: oauth2.Endpoint{
			TokenURL: server.URL,
		},
	}
	success := testutils.AssertSuccessNotCalled(t)
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			// error from golang.org/x/oauth2 config.Exchange as provider is down
			assert.True(t, strings.HasPrefix(err.Error(), "oauth2: cannot fetch token"))
		}

		fmt.Fprint(w, FailureHandlerCalled)
	}

	callbackHandler := CallbackHandler(config, success, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, CodePath, nil) // nolint: noctx
	ctx := WithState(context.Background(), "d4e5f6")
	callbackHandler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, FailureHandlerCalled, w.Body.String())
}

func TestStateHandlerBindsStateToCookie(t *testing.T) {
	cookieConfig := sessions.CookieConfig{Name: "oauth_state", Path: "/", MaxAge: 60, HTTPOnly: true, SameSite: http.SameSiteLaxMode}

	t.Run("callback state must match the cookie, not the query", func(t *testing.T) {
		success := testutils.AssertSuccessNotCalled(t)
		failure := func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, ErrInvalidState, ErrorFromContext(req.Context()))
			fmt.Fprint(w, FailureHandlerCalled)
		}

		handler := StateHandler(cookieConfig, CallbackHandler(&oauth2.Config{}, success, http.HandlerFunc(failure)))

		// attacker-controlled state in the query with no cookie must not satisfy the check
		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/?code=any_code&state=attacker", nil)
		handler.ServeHTTP(w, req)
		assert.Equal(t, FailureHandlerCalled, w.Body.String())
	})

	t.Run("state cookie issued on login is accepted on callback", func(t *testing.T) {
		var issued string

		capture := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			state, err := StateFromContext(req.Context())
			assert.NoError(t, err)

			issued = state
		})

		w := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/login", nil)
		StateHandler(cookieConfig, capture).ServeHTTP(w, req)

		cookies := w.Result().Cookies() //nolint:bodyclose
		assert.Len(t, cookies, 1)
		assert.Equal(t, issued, cookies[0].Value)

		server := NewAccessTokenServer(t, `{"access_token":"tok","token_type":"bearer"}`)
		defer server.Close()

		config := &oauth2.Config{Endpoint: oauth2.Endpoint{TokenURL: server.URL}}
		success := func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, SuccessHandlerCalled) }
		failure := testutils.AssertFailureNotCalled(t)

		w = httptest.NewRecorder()
		req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/callback?code=any_code&state="+issued, nil)
		req.AddCookie(cookies[0])
		StateHandler(cookieConfig, CallbackHandler(config, http.HandlerFunc(success), failure)).ServeHTTP(w, req)
		assert.Equal(t, SuccessHandlerCalled, w.Body.String())
	})
}
