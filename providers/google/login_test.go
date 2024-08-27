package google

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	google "google.golang.org/api/oauth2/v2"

	oauth2Login "github.com/theopenlane/core/pkg/providers/oauth2"
	"github.com/theopenlane/core/pkg/testutils"
)

const (
	ErrFailureHandlerCalled = "failure handler called"
)

func TestGoogleHandler(t *testing.T) {
	jsonData := `{"id": "900913", "name": "Rusty Shackleford"}`
	expectedUser := &google.Userinfo{Id: "900913", Name: "Rusty Shackleford"}
	proxyClient, server := newGoogleTestServer(jsonData)

	defer server.Close()

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, proxyClient)
	anyToken := &oauth2.Token{AccessToken: "any-token"}
	ctx = oauth2Login.WithToken(ctx, anyToken)

	config := &oauth2.Config{}
	success := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		googleUser, err := UserFromContext(ctx)
		assert.Nil(t, err)
		// assert required fields; Userinfo contains other raw response info
		assert.Equal(t, expectedUser.Id, googleUser.Id)
		assert.Equal(t, expectedUser.Id, googleUser.Id)
		fmt.Fprintf(w, "success handler called")
	}
	failure := testutils.AssertFailureNotCalled(t)

	// GoogleHandler assert that:
	// - Token is read from the ctx and passed to the Google API
	// - google Userinfo is obtained from the Google API
	// - success handler is called
	// - google Userinfo is added to the ctx of the success handler
	googleHandler := googleHandler(config, http.HandlerFunc(success), failure)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil) // nolint: noctx
	googleHandler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, "success handler called", w.Body.String())
}

func TestMissingCtxToken(t *testing.T) {
	config := &oauth2.Config{}
	success := testutils.AssertSuccessNotCalled(t)
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			assert.Equal(t, "oauth2: context missing token", err.Error())
		}

		fmt.Fprint(w, ErrFailureHandlerCalled)
	}

	// GoogleHandler called without Token in ctx, assert that:
	// - failure handler is called
	// - error about ctx missing token is added to the failure handler ctx
	googleHandler := googleHandler(config, success, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil) // nolint: noctx
	googleHandler.ServeHTTP(w, req)
	assert.Equal(t, ErrFailureHandlerCalled, w.Body.String())
}

func TestErrorGettingUser(t *testing.T) {
	proxyClient, server := testutils.NewErrorServer("Google Service Down", http.StatusInternalServerError)
	defer server.Close()
	// oauth2 Client will use the proxy client's base Transport
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, proxyClient)
	anyToken := &oauth2.Token{AccessToken: "any-token"}
	ctx = oauth2Login.WithToken(ctx, anyToken)

	config := &oauth2.Config{}
	success := testutils.AssertSuccessNotCalled(t)
	failure := func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		err := ErrorFromContext(ctx)

		if assert.NotNil(t, err) {
			assert.Equal(t, ErrUnableToGetGoogleUser, err)
		}

		fmt.Fprint(w, ErrFailureHandlerCalled)
	}

	// GoogleHandler cannot get Google User, assert that:
	// - failure handler is called
	// - error cannot get Google User added to the failure handler ctx
	googleHandler := googleHandler(config, success, http.HandlerFunc(failure))
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil) // nolint: noctx
	googleHandler.ServeHTTP(w, req.WithContext(ctx))
	assert.Equal(t, ErrFailureHandlerCalled, w.Body.String())
}

func TestValidateResponse(t *testing.T) {
	assert.Equal(t, nil, validateResponse(&google.Userinfo{Id: "123"}, nil))
	assert.Equal(t, ErrUnableToGetGoogleUser, validateResponse(nil, ErrServerError))
	assert.Equal(t, ErrCannotValidateGoogleUser, validateResponse(nil, nil))
	assert.Equal(t, ErrCannotValidateGoogleUser, validateResponse(&google.Userinfo{Name: "Ben"}, nil))
}
