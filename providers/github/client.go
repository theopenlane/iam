package github

import (
	"context"
	"net/http"

	"github.com/google/go-github/v91/github"
)

// ClientConfig holds the configuration for the GitHub client
type ClientConfig struct {
	IsMock bool
}

// Interface defines all necessary methods
type Interface interface {
	NewClient(httpClient *http.Client) (Client, error)
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
func (g *Creator) NewClient(httpClient *http.Client) (Client, error) {
	client, err := github.NewClient(github.WithHTTPClient(httpClient))
	if err != nil {
		return Client{}, err
	}

	return Client{
		Users: client.Users,
	}, nil
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
func (g *MockInterface) NewClient(_ *http.Client) (Client, error) {
	return Client{
		Users: &UsersMock{},
	}, nil
}

// UsersMock mocks UsersService
type UsersMock struct {
	githubUserService //nolint:unused
}

// Get returns a Github user
func (u *UsersMock) Get(context.Context, string) (*github.User, *github.Response, error) {
	resp := &http.Response{StatusCode: http.StatusOK}

	return &github.User{
		Login: new("antman"),
		ID:    new(int64(1)),
	}, &github.Response{Response: resp}, nil
}

// ListEmails returns a mock list of Github user emails
func (u *UsersMock) ListEmails(_ context.Context, _ *github.ListOptions) ([]*github.UserEmail, *github.Response, error) {
	resp := &http.Response{StatusCode: http.StatusOK}

	return []*github.UserEmail{
		{
			Email:   new("antman@theopenlane.io"),
			Primary: new(true),
		},
		{
			Email:   new("ant-man@avengers.com"),
			Primary: new(false),
		},
	}, &github.Response{Response: resp}, nil
}
