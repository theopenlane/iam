package google

import (
	"context"

	"github.com/theopenlane/utils/contextx"
	google "google.golang.org/api/oauth2/v2"
)

var (
	userContextKey  = contextx.NewKey[*google.Userinfo]()
	errorContextKey = contextx.NewKey[error]()
)

// WithUser returns a copy of ctx that stores the Google Userinfo
func WithUser(ctx context.Context, user *google.Userinfo) context.Context {
	return userContextKey.Set(ctx, user)
}

// UserFromContext returns the Google Userinfo from the ctx
func UserFromContext(ctx context.Context) (*google.Userinfo, error) {
	user, ok := userContextKey.Get(ctx)
	if !ok {
		return nil, ErrContextMissingGoogleUser
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
