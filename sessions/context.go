package sessions

import (
	"context"

	"github.com/pkg/errors"

	"github.com/theopenlane/utils/contextx"
	"golang.org/x/oauth2"
)

// ContextWithToken returns a copy of ctx that stores the Token
func ContextWithToken(ctx context.Context, token *oauth2.Token) context.Context {
	return contextx.With(ctx, token)
}

// OhAuthTokenFromContext returns the Token from the ctx
func OhAuthTokenFromContext(ctx context.Context) (*oauth2.Token, error) {
	token, ok := contextx.From[*oauth2.Token](ctx)
	if !ok {
		return nil, errors.New("context missing Token")
	}

	return token, nil
}

// getSessionValue is a generic helper for extracting values from session context
func getSessionValue[T any](ctx context.Context) (T, error) {
	var zero T

	sessionDetails, ok := contextx.From[*Session[any]](ctx)
	if !ok {
		return zero, ErrInvalidSession
	}

	sessionID := sessionDetails.GetKey()

	sessionData, ok := sessionDetails.GetOk(sessionID)
	if !ok {
		return zero, ErrInvalidSession
	}

	if value, ok := sessionData.(T); ok {
		return value, nil
	}

	return zero, ErrInvalidSession
}

// UserIDFromContext returns the user ID from the ctx
// this function assumes the session data is stored in a string map
func UserIDFromContext(ctx context.Context) (string, error) {
	sessionMap, err := getSessionValue[map[string]string](ctx)
	if err != nil {
		return "", err
	}

	userID, ok := sessionMap["userID"]
	if !ok {
		return "", ErrInvalidSession
	}

	return userID, nil
}

type UserID string

// ContextWithUserID returns a copy of ctx that stores the user ID
func ContextWithUserID(ctx context.Context, userID UserID) context.Context {
	if userID == "" {
		return ctx
	}

	return contextx.With(ctx, userID)
}

// SessionToken returns the session token from the context
func SessionToken(ctx context.Context) (string, error) {
	sd, err := getSessionDataFromContext(ctx)
	if err != nil {
		return "", err
	}

	sd.mu.Lock()
	defer sd.mu.Unlock()

	return sd.store.EncodeCookie(sd)
}

// addSessionDataToContext adds session data to the context
func (s *Session[P]) addSessionDataToContext(ctx context.Context) context.Context {
	return contextx.With(ctx, s)
}

// getSessionDataFromContext retrieves session data from the context
func getSessionDataFromContext(ctx context.Context) (*Session[map[string]any], error) {
	sessionData, ok := contextx.From[*Session[map[string]any]](ctx)
	if !ok {
		return nil, errors.New("context missing session data")
	}

	return sessionData, nil
}
