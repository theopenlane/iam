package github

import (
	"context"
	"net/http"
	"net/url"

	"github.com/google/go-github/v73/github"
)

// ClientConfig holds the configuration for the GitHub client
type ClientConfig struct {
	BaseURL   *url.URL
	UploadURL *url.URL

	IsEnterprise bool
	IsMock       bool
}

// Interface defines all necessary methods
// https://godoc.org/github.com/google/go-github/github#NewClient
type Interface interface {
	NewClient(httpClient *http.Client) Client
	GetConfig() *ClientConfig
	SetConfig(config *ClientConfig)
}

// Client defines all necessary methods used by the client
type Client struct {
	Users githubUserService
}

// githubUserService defines all necessary methods for the User service
type githubUserService interface {
	Get(ctx context.Context, user string) (*github.User, *github.Response, error)
	ListEmails(ctx context.Context, opts *github.ListOptions) ([]*github.UserEmail, *github.Response, error)
}

// Creator implements GitHubInterface
type Creator struct {
	Config *ClientConfig
}

// GetConfig returns the current configuration
func (g *Creator) GetConfig() *ClientConfig {
	return g.Config
}

// SetConfig sets the configuration
func (g *Creator) SetConfig(config *ClientConfig) {
	g.Config = config
}

// NewClient returns a new GitHubClient
func (g *Creator) NewClient(httpClient *http.Client) Client {
	client := github.NewClient(httpClient)

	if g.Config.BaseURL != nil {
		client.BaseURL = g.Config.BaseURL
	}

	if g.Config.UploadURL != nil {
		client.UploadURL = g.Config.UploadURL
	}

	return Client{
		Users: client.Users,
	}
}

// MockInterface implements GitHubInterface
type MockInterface struct {
	Config *ClientConfig
}

// GetConfig returns the current configuration
func (g *MockInterface) GetConfig() *ClientConfig {
	return g.Config
}

// SetConfig sets the configuration
func (g *MockInterface) SetConfig(config *ClientConfig) {
	g.Config = config
}

// NewClient returns a new mock GitHubClient
func (g *MockInterface) NewClient(_ *http.Client) Client {
	return Client{
		Users: &UsersMock{},
	}
}

// UsersMock mocks UsersService
type UsersMock struct {
	githubUserService //nolint:unused
}

// Get returns a Github user
func (u *UsersMock) Get(context.Context, string) (*github.User, *github.Response, error) {
	resp := &http.Response{StatusCode: http.StatusOK}

	return &github.User{
		Login: github.Ptr("antman"),
		ID:    github.Ptr(int64(1)),
	}, &github.Response{Response: resp}, nil
}

// ListEmails returns a mock list of Github user emails
func (u *UsersMock) ListEmails(_ context.Context, _ *github.ListOptions) ([]*github.UserEmail, *github.Response, error) {
	resp := &http.Response{StatusCode: http.StatusOK}

	return []*github.UserEmail{
		{
			Email:   github.Ptr("antman@theopenlane.io"),
			Primary: github.Ptr(true),
		},
		{
			Email:   github.Ptr("ant-man@avengers.com"),
			Primary: github.Ptr(false),
		},
	}, &github.Response{Response: resp}, nil
}
