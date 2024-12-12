package sessions

import (
	"context"

	"github.com/pkg/errors"

	"github.com/theopenlane/utils/contextx"
	"golang.org/x/oauth2"
)

// NewContextWithToken returns a copy of ctx that stores the Token
func NewContextWithToken(ctx context.Context, token *oauth2.Token) context.Context {
	return contextx.With(ctx, token)
}

// NewOhAuthTokenFromContext returns the Token from the ctx
func NewOhAuthTokenFromContext(ctx context.Context) (*oauth2.Token, error) {
	token, ok := contextx.From[*oauth2.Token](ctx)
	if !ok {
		return nil, errors.New("context missing Token")
	}

	return token, nil
}

// NewUserIDFromContext returns the user ID from the ctx
// this function assumes the session data is stored in a string map
func NewUserIDFromContext(ctx context.Context) (string, error) {
	sessionDetails, ok := contextx.From[*Session[any]](ctx)
	if !ok {
		return "", ErrInvalidSession
	}

	sessionID := sessionDetails.GetKey()

	sessionData, ok := sessionDetails.GetOk(sessionID)
	if !ok {
		return "", ErrInvalidSession
	}

	sd, ok := sessionData.(map[string]string)
	if !ok {
		return "", ErrInvalidSession
	}

	userID, ok := sd["userID"]
	if !ok {
		return "", ErrInvalidSession
	}

	return userID, nil
}

type UserID string

// NewContextWithUserID returns a copy of ctx that stores the user ID
func NewContextWithUserID(ctx context.Context, userID UserID) context.Context {
	if userID == "" {
		return ctx
	}

	return contextx.With(ctx, userID)
}

// NewSessionToken returns the session token from the context
func NewSessionToken(ctx context.Context) (string, error) {
	sd, err := newGetSessionDataFromContext(ctx)
	if err != nil {
		return "", err
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	return sd.store.EncodeCookie(sd)
}

// NewAddSessionDataToContext adds session data to the context
func (s *Session[P]) NewAddSessionDataToContext(ctx context.Context) context.Context {
	return contextx.With(ctx, s)
}

// newGetSessionDataFromContext retrieves session data from the context
func newGetSessionDataFromContext(ctx context.Context) (*Session[map[string]any], error) {
	sessionData, ok := contextx.From[*Session[map[string]any]](ctx)
	if !ok {
		return nil, errors.New("context missing session data")
	}

	return sessionData, nil
}
