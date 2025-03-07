package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

	err := auth.AddOrganizationIDToContext(multiOrgValidCtx, orgID2)
	require.NoError(t, err)

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
				require.Error(t, err)
				assert.Empty(t, got)
				assert.ErrorContains(t, err, tc.err.Error())

				return
			}

			require.NoError(t, err)
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

func TestGetSubscriptionFromContext(t *testing.T) {
	validSubscription := true
	invalidSubscription := false

	validCtx := auth.NewTestContextWithValidUser(ulids.New().String())
	if err := auth.AddSubscriptionToContext(validCtx, true); err != nil {
		t.Fatal(err)
	}

	invalidCtx := auth.NewTestContextWithValidUser(ulids.Null.String())

	testCases := []struct {
		name   string
		ctx    context.Context
		expect bool
	}{
		{
			name:   "happy path",
			ctx:    invalidCtx,
			expect: invalidSubscription,
		},
		{
			name:   "MITB BABBYYYYY",
			ctx:    validCtx,
			expect: validSubscription,
		},
	}

	for _, tc := range testCases {
		t.Run("Get "+tc.name, func(t *testing.T) {
			got := auth.GetSubscriptionFromContext(tc.ctx)

			assert.Equal(t, tc.expect, got)
		})
	}
}
func TestGetAuthzSubjectType(t *testing.T) {
	testCases := []struct {
		name     string
		au       *auth.AuthenticatedUser
		expected string
	}{
		{
			name: "jwt authentication",
			au: &auth.AuthenticatedUser{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.JWTAuthentication,
			},
			expected: auth.UserSubjectType,
		},
		{
			name: "api token authentication",
			au: &auth.AuthenticatedUser{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.APITokenAuthentication,
			}, expected: auth.ServiceSubjectType,
		},
		{
			name: "PAT authentication",
			au: &auth.AuthenticatedUser{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.PATAuthentication,
			},
			expected: auth.UserSubjectType,
		},
		{
			name:     "no authentication",
			au:       nil,
			expected: "",
		},
		{
			name:     "empty authentication",
			au:       &auth.AuthenticatedUser{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.au != nil {
				ctx = auth.WithAuthenticatedUser(ctx, tc.au)
			}

			got := auth.GetAuthzSubjectType(ctx)

			assert.Equal(t, tc.expected, got)
		})
	}
}
func TestGetAuthTypeFromContext(t *testing.T) {
	testCases := []struct {
		name     string
		au       *auth.AuthenticatedUser
		expected auth.AuthenticationType
	}{
		{
			name: "jwt authentication",
			au: &auth.AuthenticatedUser{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.JWTAuthentication,
			},
			expected: auth.JWTAuthentication,
		},
		{
			name: "api token authentication",
			au: &auth.AuthenticatedUser{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.APITokenAuthentication,
			},
			expected: auth.APITokenAuthentication,
		},
		{
			name: "PAT authentication",
			au: &auth.AuthenticatedUser{
				SubjectID:          ulids.New().String(),
				AuthenticationType: auth.PATAuthentication,
			},
			expected: auth.PATAuthentication,
		},
		{
			name:     "no authentication",
			au:       nil,
			expected: "",
		},
		{
			name:     "empty authentication",
			au:       &auth.AuthenticatedUser{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.au != nil {
				ctx = auth.WithAuthenticatedUser(ctx, tc.au)
			}

			got := auth.GetAuthTypeFromContext(ctx)

			assert.Equal(t, tc.expected, got)
		})
	}
}
