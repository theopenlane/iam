package oauthserver

import (
	"net/http"
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

func TestOAuthErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		code string
		want int
	}{
		{name: "invalid client", code: ErrCodeInvalidClient, want: http.StatusUnauthorized},
		{name: "server error", code: ErrCodeServerError, want: http.StatusInternalServerError},
		{name: "invalid grant", code: ErrCodeInvalidGrant, want: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, NewError(tc.code, "").Status())
		})
	}
}
