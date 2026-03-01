package oauth2

import (
	"context"

	"github.com/theopenlane/utils/contextx"
	"golang.org/x/oauth2"
)

var (
	tokenContextKey    = contextx.NewKey[*oauth2.Token]()
	stateContextKey    = contextx.NewKey[string]()
	errorContextKey    = contextx.NewKey[error]()
	redirectContextKey = contextx.NewKey[string]()
)

// WithState returns a copy of ctx that stores the state value
func WithState(ctx context.Context, state string) context.Context {
	return stateContextKey.Set(ctx, state)
}

// StateFromContext returns the state value from the ctx
func StateFromContext(ctx context.Context) (string, error) {
	state, ok := stateContextKey.Get(ctx)

	if !ok {
		return "", ErrContextMissingStateValue
	}

	return state, nil
}

// WithToken returns a copy of ctx that stores the Token
func WithToken(ctx context.Context, token *oauth2.Token) context.Context {
	return tokenContextKey.Set(ctx, token)
}

// TokenFromContext returns the Token from the ctx
func TokenFromContext(ctx context.Context) (*oauth2.Token, error) {
	token, ok := tokenContextKey.Get(ctx)

	if !ok {
		return nil, ErrContextMissingToken
	}

	return token, nil
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

// WithRedirectURL returns a copy of ctx that stores the redirect value
func WithRedirectURL(ctx context.Context, redirect string) context.Context {
	return redirectContextKey.Set(ctx, redirect)
}

// RedirectFromContext returns the redirect value from the ctx
func RedirectFromContext(ctx context.Context) string {
	redirect, ok := redirectContextKey.Get(ctx)

	if !ok {
		return ""
	}

	return redirect
}
