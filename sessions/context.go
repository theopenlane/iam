package sessions

import (
	"context"

	"github.com/pkg/errors"

	"golang.org/x/oauth2"
)

// ContextWithToken returns a copy of ctx that stores the Token
func ContextWithToken(ctx context.Context, token *oauth2.Token) context.Context {
	return oauthTokenContextKey.Set(ctx, token)
}

// OhAuthTokenFromContext returns the Token from the ctx
func OhAuthTokenFromContext(ctx context.Context) (*oauth2.Token, error) {
	token, ok := oauthTokenContextKey.Get(ctx)
	if !ok {
		return nil, errors.New("context missing Token")
	}

	return token, nil
}

// getSessionValue is a generic helper for extracting values from session context
func getSessionValue[T any](ctx context.Context) (T, error) {
	var zero T

	sessionDetails, ok := sessionDataContextKey.Get(ctx)
	if !ok {
		return zero, ErrInvalidSession
	}

	sessionID := sessionDetails.GetKey()

	sessionData, ok := sessionDetails.GetOk(sessionID)
	if !ok {
		return zero, ErrInvalidSession
	}

	if value, ok := any(sessionData).(T); ok {
		return value, nil
	}

	return zero, ErrInvalidSession
}

// UserIDFromContext returns the user ID from the ctx
// this function assumes the session data is stored in a string map
func UserIDFromContext(ctx context.Context) (string, error) {
	sessionMap, err := getSessionValue[map[string]any](ctx)
	if err != nil {
		return "", err
	}

	rawUserID, ok := sessionMap["userID"]
	if !ok {
		return "", ErrInvalidSession
	}

	userID, ok := rawUserID.(string)
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

	return userIDContextKey.Set(ctx, userID)
}

// ContextUserIDFromContext returns the UserID stored by ContextWithUserID.
func ContextUserIDFromContext(ctx context.Context) (UserID, bool) {
	return userIDContextKey.Get(ctx)
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

// addSessionDataToContext adds session data to the context.
func (s *Session[P]) addSessionDataToContext(ctx context.Context) context.Context {
	sessionData, ok := any(s).(*Session[map[string]any])
	if !ok {
		return ctx
	}

	return sessionDataContextKey.Set(ctx, sessionData)
}

// getSessionDataFromContext retrieves session data from the context
func getSessionDataFromContext(ctx context.Context) (*Session[map[string]any], error) {
	sessionData, ok := sessionDataContextKey.Get(ctx)
	if !ok {
		return nil, errors.New("context missing session data")
	}

	return sessionData, nil
}
