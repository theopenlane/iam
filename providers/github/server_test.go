package github

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/theopenlane/utils/testutils"
)

// newGithubTestServer mocks the GitHub user endpoint and a client
func newGithubTestServer(routePrefix, userData, emailData string) (*http.Client, *httptest.Server) {
	client, mux, server := testutils.TestServer()
	mux.HandleFunc(routePrefix+"/user", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, userData)
	})

	mux.HandleFunc(routePrefix+"/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, emailData)
	})

	return client, server
}
