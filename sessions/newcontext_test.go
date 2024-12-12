package sessions_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theopenlane/utils/contextx"
	"golang.org/x/oauth2"

	"github.com/theopenlane/iam/sessions"
)

func TestNewContextWithToken(t *testing.T) {
	ctx := context.Background()
	token := &oauth2.Token{AccessToken: "test_token"}

	ctx = sessions.NewContextWithToken(ctx, token)
	retrievedToken, ok := contextx.From[*oauth2.Token](ctx)

	assert.True(t, ok)
	assert.Equal(t, token, retrievedToken)
}

func TestNewOhAuthTokenFromContext(t *testing.T) {
	ctx := context.Background()
	token := &oauth2.Token{AccessToken: "test_token"}

	ctx = sessions.NewContextWithToken(ctx, token)
	retrievedToken, err := sessions.NewOhAuthTokenFromContext(ctx)

	assert.NoError(t, err)
	assert.Equal(t, token, retrievedToken)
}

func TestNewOhAuthTokenFromContext_MissingToken(t *testing.T) {
	ctx := context.Background()

	_, err := sessions.NewOhAuthTokenFromContext(ctx)

	assert.Error(t, err)
	assert.Equal(t, "context missing Token", err.Error())
}

func TestNewUserIDFromContext_MissingSession(t *testing.T) {
	ctx := context.Background()

	_, err := sessions.NewUserIDFromContext(ctx)

	assert.Error(t, err)
	assert.Equal(t, sessions.ErrInvalidSession, err)
}

func TestNewContextWithUserID(t *testing.T) {
	ctx := context.Background()
	userID := "test_user"

	ctx = sessions.NewContextWithUserID(ctx, userID)
	retrievedUserID, ok := contextx.From[string](ctx)

	assert.True(t, ok)
	assert.Equal(t, userID, retrievedUserID)
}

func TestNewContextWithUserID_EmptyUserID(t *testing.T) {
	ctx := context.Background()
	userID := ""

	ctx = sessions.NewContextWithUserID(ctx, userID)
	retrievedUserID, ok := contextx.From[string](ctx)

	assert.False(t, ok)
	assert.Equal(t, "", retrievedUserID)
}
