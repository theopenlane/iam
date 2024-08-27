package google

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	google "google.golang.org/api/oauth2/v2"
)

func TestContextUser(t *testing.T) {
	expectedUserinfo := &google.Userinfo{Id: "42", Name: "Google User"}
	ctx := WithUser(context.Background(), expectedUserinfo)
	user, err := UserFromContext(ctx)
	assert.Equal(t, expectedUserinfo, user)
	assert.Nil(t, err)
}

func TestFailGettingContext(t *testing.T) {
	user, err := UserFromContext(context.Background())
	assert.Nil(t, user)

	if assert.NotNil(t, err) {
		assert.Equal(t, "context missing google user", err.Error())
	}
}
