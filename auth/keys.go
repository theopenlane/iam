package auth

import (
	"context"

	"github.com/theopenlane/utils/contextx"
)

// CallerKey is the context key for storing and retrieving a *Caller
var CallerKey = contextx.NewKey[*Caller]()

// WithCaller stores c in ctx and returns the updated context
func WithCaller(ctx context.Context, c *Caller) context.Context {
	return CallerKey.Set(ctx, c)
}

// CallerFromContext returns the Caller stored in ctx and true, or nil and false if not set
func CallerFromContext(ctx context.Context) (*Caller, bool) {
	return CallerKey.Get(ctx)
}

// MustCallerFromContext returns the Caller stored in ctx, panicking if not set
func MustCallerFromContext(ctx context.Context) *Caller {
	return CallerKey.MustGet(ctx)
}
