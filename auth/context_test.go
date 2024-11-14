package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/echox/middleware/echocontext"
	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/auth"
)

func TestGetSubjectIDFromContext(t *testing.T) {
	// context with no user set
	ec := echocontext.NewTestEchoContext()

	basicContext := context.WithValue(ec.Request().Context(), echocontext.EchoContextKey, ec)

	ec.SetRequest(ec.Request().WithContext(basicContext))

	sub := ulids.New().String()

	validCtx, err := auth.NewTestContextWithValidUser(sub)
	if err != nil {
		t.Fatal()
	}

	invalidUserCtx, err := auth.NewTestContextWithValidUser(ulids.Null.String())
	if err != nil {
		t.Fatal()
	}

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
			ctx:  basicContext,
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
			got, err := auth.GetUserIDFromContext(tc.ctx)
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
	// context with no user set
	ec := echocontext.NewTestEchoContext()

	basicContext := context.WithValue(ec.Request().Context(), echocontext.EchoContextKey, ec)

	ec.SetRequest(ec.Request().WithContext(basicContext))

	orgID := ulids.New().String()

	validCtx, err := auth.NewTestContextWithOrgID(ulids.New().String(), orgID)
	if err != nil {
		t.Fatal()
	}

	invalidUserCtx, err := auth.NewTestContextWithOrgID(ulids.Null.String(), ulids.Null.String())
	if err != nil {
		t.Fatal()
	}

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
			ctx:  basicContext,
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

func TestGetSubscriptionFromContext(t *testing.T) {
	validsubscription := true
	invalidsubscription := false

	ec := echocontext.NewTestEchoContext()

	basicContext := context.WithValue(ec.Request().Context(), echocontext.EchoContextKey, ec)

	ec.SetRequest(ec.Request().WithContext(basicContext))

	invalidCtx, err := auth.NewTestContextWithValidUser(ulids.Null.String())
	if err != nil {
		t.Fatal()
	}

	validCtx, err := auth.NewTestContextWithValidUser(ulids.New().String())
	if err != nil {
		t.Fatal()
	}

	if err := auth.AddSubscriptionToContext(validCtx, true); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name   string
		ctx    context.Context
		expect bool
	}{
		{
			name:   "happy path",
			ctx:    invalidCtx,
			expect: invalidsubscription,
		},
		{
			name:   "MITB BABBYYYYY",
			ctx:    validCtx,
			expect: validsubscription,
		},
	}

	for _, tc := range testCases {
		t.Run("Get "+tc.name, func(t *testing.T) {
			got, err := auth.GetSubscriptionFromContext(tc.ctx)

			assert.NoError(t, err)

			if tc.expect == validsubscription {
				assert.Equal(t, validsubscription, got)
			}

			if tc.expect == invalidsubscription {
				assert.Equal(t, invalidsubscription, got)
			}
		})
	}
}
