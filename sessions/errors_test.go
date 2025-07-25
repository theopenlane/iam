package sessions_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/sessions"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrInvalidSession",
			err:      sessions.ErrInvalidSession,
			expected: "invalid session provided",
		},
		{
			name:     "ErrSigningKeyIsRequired",
			err:      sessions.ErrSigningKeyIsRequired,
			expected: "signing key is required - use GenerateSecureKey() to create one or configure Redis for persistent key management",
		},
		{
			name:     "ErrEncryptionKeyIsRequired",
			err:      sessions.ErrEncryptionKeyIsRequired,
			expected: "encryption key is required - use GenerateSecureKey() to create one or configure Redis for persistent key management",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Error(t, tc.err)
			assert.Equal(t, tc.expected, tc.err.Error())
		})
	}
}

func TestErrorsAreUnique(t *testing.T) {
	// Ensure all errors are distinct
	errors := []error{
		sessions.ErrInvalidSession,
		sessions.ErrSigningKeyIsRequired,
		sessions.ErrEncryptionKeyIsRequired,
	}

	for i, err1 := range errors {
		for j, err2 := range errors {
			if i != j {
				assert.NotEqual(t, err1, err2, "errors should be unique")
				assert.NotEqual(t, err1.Error(), err2.Error(), "error messages should be unique")
			}
		}
	}
}
