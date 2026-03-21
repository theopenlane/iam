package github

import (
	"context"

	"github.com/google/go-github/v84/github"
	"github.com/theopenlane/utils/contextx"
)

var (
	userContextKey  = contextx.NewKey[*github.User]()
	errorContextKey = contextx.NewKey[error]()
)

// WithUser returns a copy of context that stores the GitHub User
func WithUser(ctx context.Context, user *github.User) context.Context {
	return userContextKey.Set(ctx, user)
}

// UserFromContext returns the GitHub User from the context
func UserFromContext(ctx context.Context) (*github.User, error) {
	user, ok := userContextKey.Get(ctx)
	if !ok {
		return nil, ErrContextMissingGithubUser
	}

	return user, nil
}

// WithError returns a copy of context that stores the given error value
func WithError(ctx context.Context, err error) context.Context {
	return errorContextKey.Set(ctx, err)
}

// ErrorFromContext returns the error value from the ctx or an error that the
// context was missing an error value
func ErrorFromContext(ctx context.Context) error {
	err, ok := errorContextKey.Get(ctx)
	if !ok {
		return ErrContextMissingErrorValue
	}

	return err
}
