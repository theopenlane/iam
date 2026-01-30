package auth_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/iam/auth"
)

func TestOrganizationRoleTypeIsValid(t *testing.T) {
	type testCase struct {
		name     string
		role     string
		expected bool
	}

	testCases := []testCase{
		{
			name:     "valid admin role",
			role:     "admin",
			expected: true,
		},
		{
			name:     "valid super_admin role",
			role:     "super_admin",
			expected: true,
		},
		{
			name:     "valid owner role",
			role:     "owner",
			expected: true,
		},
		{
			name:     "valid member role",
			role:     "member",
			expected: true,
		},
		{
			name:     "valid auditor role",
			role:     "auditor",
			expected: true,
		},
		{
			name:     "valid anonymous role",
			role:     "anonymous",
			expected: true,
		},
		{
			name:     "invalid role",
			role:     "cattypist",
			expected: false,
		},
		{
			name:     "empty string",
			role:     "",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ort := auth.OrganizationRoleType(tc.role)
			assert.Equal(t, tc.expected, ort.IsValid())
		})
	}
}
func TestToOrganizationRoleType(t *testing.T) {
	type testCase struct {
		name         string
		input        string
		expectedRole auth.OrganizationRoleType
		expectedOk   bool
	}

	testCases := []testCase{
		{
			name:         "valid admin role",
			input:        "admin",
			expectedRole: auth.AdminRole,
			expectedOk:   true,
		},
		{
			name:         "valid super_admin role",
			input:        "super_admin",
			expectedRole: auth.SuperAdminRole,
			expectedOk:   true,
		},
		{
			name:         "valid owner role",
			input:        "owner",
			expectedRole: auth.OwnerRole,
			expectedOk:   true,
		},
		{
			name:         "valid member role",
			input:        "MEMBER",
			expectedRole: auth.MemberRole,
			expectedOk:   true,
		},
		{
			name:         "valid auditor role",
			input:        "auditor",
			expectedRole: auth.AuditorRole,
			expectedOk:   true,
		},
		{
			name:         "valid anonymous role",
			input:        "anonymous",
			expectedRole: auth.AnonymousRole,
			expectedOk:   true,
		},
		{
			name:         "invalid role",
			input:        "cattypist",
			expectedRole: "",
			expectedOk:   false,
		},
		{
			name:         "empty string",
			input:        "",
			expectedRole: "",
			expectedOk:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			role, ok := auth.ToOrganizationRoleType(tc.input)
			assert.Equal(t, tc.expectedOk, ok)
			assert.Equal(t, tc.expectedRole, role)
		})
	}
}
