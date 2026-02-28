package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/auth"
)

func TestGetSubjectIDFromContext(t *testing.T) {
	sub := ulids.New().String()

	validCtx := auth.NewTestContextWithValidUser(sub)
	invalidUserCtx := auth.NewTestContextWithValidUser(ulids.Null.String())

	testCases := []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{
			name: "happy path",
			ctx:  validCtx,
			err:  nil,
		},
		{
			name: "no user",
			ctx:  context.Background(),
			err:  auth.ErrNoAuthUser,
		},
		{
			name: "null user",
			ctx:  invalidUserCtx,
			err:  auth.ErrNoAuthUser,
		},
	}

	for _, tc := range testCases {
		t.Run("Get "+tc.name, func(t *testing.T) {
			got, err := auth.GetSubjectIDFromContext(tc.ctx)
			if tc.err != nil {
				assert.Error(t, err)
				assert.Empty(t, got)
				assert.ErrorContains(t, err, tc.err.Error())

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, sub, got)
		})
	}
}

func TestGetOrganizationIDFromContext(t *testing.T) {
	orgID := ulids.New().String()

	validCtx := auth.NewTestContextWithOrgID(ulids.New().String(), orgID)
	invalidUserCtx := auth.NewTestContextWithOrgID(ulids.Null.String(), ulids.Null.String())

	testCases := []struct {
		name string
		ctx  context.Context
		err  error
	}{
		{
			name: "happy path",
			ctx:  validCtx,
			err:  nil,
		},
		{
			name: "no user",
			ctx:  context.Background(),
			err:  auth.ErrNoAuthUser,
		},
		{
			name: "null user",
			ctx:  invalidUserCtx,
			err:  auth.ErrNoAuthUser,
		},
	}

	for _, tc := range testCases {
		t.Run("Get "+tc.name, func(t *testing.T) {
			got, err := auth.GetOrganizationIDFromContext(tc.ctx)
			if tc.err != nil {
				assert.Error(t, err)
				assert.Empty(t, got)
				assert.ErrorContains(t, err, tc.err.Error())

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, orgID, got)
		})
	}
}

func TestGetOrganizationIDsFromContext(t *testing.T) {
	orgID1 := ulids.New().String()
	orgID2 := ulids.New().String()

	singleOrgValidCtx := auth.NewTestContextWithOrgID(ulids.New().String(), orgID1)

	multiOrgValidCtx := auth.NewTestContextWithOrgID(ulids.New().String(), orgID1)

	multiOrgValidCtx, err := auth.AddOrganizationIDToContext(multiOrgValidCtx, orgID2)
	assert.NoError(t, err)

	invalidUserCtx := auth.NewTestContextWithOrgID(ulids.Null.String(), ulids.Null.String())

	testCases := []struct {
		name        string
		ctx         context.Context
		numExpected int
		err         error
	}{
		{
			name:        "happy path, one org",
			ctx:         singleOrgValidCtx,
			numExpected: 1,
		},
		{
			name:        "happy path, multiple orgs",
			ctx:         multiOrgValidCtx,
			numExpected: 2,
		},
		{
			name: "no user",
			ctx:  context.Background(),
			err:  auth.ErrNoAuthUser,
		},
		{
			name:        "null orgs",
			ctx:         invalidUserCtx,
			numExpected: 0,
		},
	}

	for _, tc := range testCases {
		t.Run("Get "+tc.name, func(t *testing.T) {
			got, err := auth.GetOrganizationIDsFromContext(tc.ctx)
			if tc.err != nil {
				assert.Error(t, err)
				assert.Empty(t, got)
				assert.ErrorContains(t, err, tc.err.Error())

				return
			}

			assert.NoError(t, err)
			assert.Len(t, got, tc.numExpected)

			if tc.numExpected > 0 {
				assert.Contains(t, got, orgID1)
			}

			if tc.numExpected > 1 {
				assert.Contains(t, got, orgID2)
			}
		})
	}
}

func TestGetAuthzSubjectType(t *testing.T) {
	testCases := []struct {
		name     string
		caller   *auth.Caller
		expected string
	}{
		{
			name: "jwt authentication",
			caller: &auth.Caller{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.JWTAuthentication,
			},
			expected: auth.UserSubjectType,
		},
		{
			name: "api token authentication",
			caller: &auth.Caller{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.APITokenAuthentication,
			},
			expected: auth.ServiceSubjectType,
		},
		{
			name: "PAT authentication",
			caller: &auth.Caller{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.PATAuthentication,
			},
			expected: auth.UserSubjectType,
		},
		{
			name:     "no authentication",
			caller:   nil,
			expected: "",
		},
		{
			name:     "empty authentication",
			caller:   &auth.Caller{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller != nil {
				ctx = auth.WithCaller(ctx, tc.caller)
			}

			got := auth.GetAuthzSubjectType(ctx)

			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestGetAuthTypeFromContext(t *testing.T) {
	testCases := []struct {
		name     string
		caller   *auth.Caller
		expected auth.AuthenticationType
	}{
		{
			name: "jwt authentication",
			caller: &auth.Caller{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.JWTAuthentication,
			},
			expected: auth.JWTAuthentication,
		},
		{
			name: "api token authentication",
			caller: &auth.Caller{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.APITokenAuthentication,
			},
			expected: auth.APITokenAuthentication,
		},
		{
			name: "PAT authentication",
			caller: &auth.Caller{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.PATAuthentication,
			},
			expected: auth.PATAuthentication,
		},
		{
			name:     "no authentication",
			caller:   nil,
			expected: "",
		},
		{
			name:     "empty authentication",
			caller:   &auth.Caller{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller != nil {
				ctx = auth.WithCaller(ctx, tc.caller)
			}

			got := auth.GetAuthTypeFromContext(ctx)

			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestIsSystemAdminFromContext(t *testing.T) {
	testCases := []struct {
		name     string
		caller   *auth.Caller
		expected bool
	}{
		{
			name:     "system admin",
			caller:   &auth.Caller{Capabilities: auth.CapSystemAdmin},
			expected: true,
		},
		{
			name:     "not a system admin",
			caller:   &auth.Caller{},
			expected: false,
		},
		{
			name:     "no authenticated user",
			caller:   nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller != nil {
				ctx = auth.WithCaller(ctx, tc.caller)
			}

			got := auth.IsSystemAdminFromContext(ctx)

			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestHasFullOrgWriteAccessFromContext(t *testing.T) {
	testCases := []struct {
		name            string
		caller          *auth.Caller
		expectedHasFull bool
	}{
		{
			name:            "owner role",
			caller:          &auth.Caller{OrganizationRole: auth.OwnerRole},
			expectedHasFull: true,
		},
		{
			name:            "super admin role",
			caller:          &auth.Caller{OrganizationRole: auth.SuperAdminRole},
			expectedHasFull: true,
		},
		{
			name:            "admin role",
			caller:          &auth.Caller{OrganizationRole: auth.AdminRole},
			expectedHasFull: false,
		},
		{
			name:            "member role",
			caller:          &auth.Caller{OrganizationRole: auth.MemberRole},
			expectedHasFull: false,
		},
		{
			name:            "no authenticated user",
			caller:          nil,
			expectedHasFull: false,
		},
		{
			name:            "empty role",
			caller:          &auth.Caller{},
			expectedHasFull: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.caller != nil {
				ctx = auth.WithCaller(ctx, tc.caller)
			}

			got := auth.HasFullOrgWriteAccessFromContext(ctx)
			assert.Equal(t, tc.expectedHasFull, got)
		})
	}
}
