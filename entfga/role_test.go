package entfga_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/entfga"
)

func TestEnum(t *testing.T) {
	testCases := []struct {
		name     string
		role     string
		expected entfga.Role
	}{
		{
			name:     "admin",
			role:     "admin",
			expected: entfga.RoleAdmin,
		},
		{
			name:     "member",
			role:     "member",
			expected: entfga.RoleMember,
		},
		{
			name:     "owner",
			role:     "owner",
			expected: entfga.RoleOwner,
		},
		{
			name:     "invalid role",
			role:     "cattypist",
			expected: entfga.Invalid,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := entfga.Enum(tc.role)
			assert.Equal(t, tc.expected, res)
		})
	}
}
