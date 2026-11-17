package oauthserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOAuthErrorError(t *testing.T) {
	tests := []struct {
		name string
		err  *OAuthError
		want string
	}{
		{name: "code and description", err: &OAuthError{Code: ErrCodeInvalidGrant, Description: "code expired"}, want: "invalid_grant: code expired"},
		{name: "code only", err: &OAuthError{Code: ErrCodeAccessDenied}, want: "access_denied"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.err.Error())
		})
	}
}

func TestNewError(t *testing.T) {
	tests := []struct {
		name        string
		code        string
		description string
	}{
		{name: "with description", code: ErrCodeInvalidRequest, description: "state must not be repeated"},
		{name: "without description", code: ErrCodeServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NewError(tc.code, tc.description)

			assert.Equal(t, tc.code, got.Code)
			assert.Equal(t, tc.description, got.Description)
		})
	}
}
