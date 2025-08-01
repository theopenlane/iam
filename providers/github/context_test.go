package github

import (
	"context"
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/stretchr/testify/assert"
)

func TestContextUser(t *testing.T) {
	expectedUser := &github.User{
		ID:   github.Ptr(int64(917408)),
		Name: github.Ptr("Meow Meowingtonr"),
	}
	ctx := WithUser(context.Background(), expectedUser)
	user, err := UserFromContext(ctx)
	assert.Equal(t, expectedUser, user)
	assert.Nil(t, err)
}

func TestFailedContext(t *testing.T) {
	user, err := UserFromContext(context.Background())
	assert.Nil(t, user)

	if assert.NotNil(t, err) {
		assert.Equal(t, "context missing github user", err.Error())
	}
}
