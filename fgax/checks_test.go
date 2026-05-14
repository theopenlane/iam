package fgax

import (
	"context"
	"fmt"
	"slices"
	"testing"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/assert"

	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/auth"
	mock_fga "github.com/theopenlane/iam/fgax/internal/mockery"
)

func TestCheckTuple(t *testing.T) {
	testCases := []struct {
		name        string
		relation    string
		object      string
		expectedRes bool
		errRes      string
	}{
		{
			name:        "happy path, valid tuple",
			relation:    "member",
			object:      "organization:openlane",
			expectedRes: true,
			errRes:      "",
		},
		{
			name:        "tuple does not exist",
			relation:    "member",
			object:      "organization:cat-friends",
			expectedRes: false,
			errRes:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			c := mock_fga.NewMockSdkClient(t)
			mc := NewMockFGAClient(c)

			// mock response for input
			user := fmt.Sprintf("user:%s", ulids.New().String())
			body := ofgaclient.ClientCheckRequest{
				User:     user,
				Relation: tc.relation,
				Object:   tc.object,
			}

			mock_fga.CheckAny(t, c, tc.expectedRes)

			// do request
			valid, err := mc.checkTupleMinimizeLatency(context.Background(), body)

			if tc.errRes != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errRes)
				assert.Equal(t, tc.expectedRes, valid)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRes, valid)
		})
	}
}

func TestCheckAccess(t *testing.T) {
	validULID := ulids.New().String()

	tests := []struct {
		name        string
		ac          AccessCheck
		expectedRes bool
		wantErr     bool
	}{
		{
			name: "happy path, valid access",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relation:   "member",
				SubjectID:  validULID,
			},
			expectedRes: true,
			wantErr:     false,
		},
		{
			name: "happy path, valid access with context",
			ac: AccessCheck{
				ObjectType:  "organization",
				ObjectID:    validULID,
				SubjectType: "service",
				Relation:    "member",
				SubjectID:   validULID,
				Context:     &map[string]any{"service": "github"},
			},
			expectedRes: true,
			wantErr:     false,
		},
		{
			name: "missing object type",
			ac: AccessCheck{
				ObjectID:  validULID,
				Relation:  "member",
				SubjectID: validULID,
			},
			expectedRes: false,
			wantErr:     true,
		},
		{
			name: "missing relation",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   validULID,
				SubjectID:  validULID,
			},
			expectedRes: false,
			wantErr:     true,
		},
		{
			name: "missing object type",
			ac: AccessCheck{
				Relation:  "member",
				ObjectID:  validULID,
				SubjectID: validULID,
			},
			expectedRes: false,
			wantErr:     true,
		},
		{
			name: "missing subject",
			ac: AccessCheck{
				Relation:   "member",
				ObjectType: "organization",
				ObjectID:   validULID,
			},
			expectedRes: false,
			wantErr:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			c := mock_fga.NewMockSdkClient(t)
			mc := NewMockFGAClient(c)

			if tc.expectedRes {
				mock_fga.CheckAny(t, c, tc.expectedRes)
			}

			// do request
			valid, err := mc.CheckAccess(context.Background(), tc.ac)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedRes, valid)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRes, valid)
		})
	}
}

func TestListRelations(t *testing.T) {
	validULID := ulids.New().String()

	tests := []struct {
		name        string
		check       ListAccess
		expectedRes []string
		wantErr     bool
	}{
		{
			name: "happy path",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relations:  []string{"can_delete", "can_view", "can_read"},
				SubjectID:  validULID,
			},
			expectedRes: []string{"can_view", "can_read"},
			wantErr:     false,
		},
		{
			name: "happy path, no relations provided",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
				SubjectID:  validULID,
			},
			expectedRes: []string{"can_view", "can_read"},
			wantErr:     false,
		},
		{
			name: "happy path with context",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relations:  []string{"can_delete", "can_view", "can_read"},
				SubjectID:  validULID,
				Context:    &map[string]any{"role": "admin"},
			},
			expectedRes: []string{"can_view", "can_read"},
			wantErr:     false,
		},
		{
			name: "missing object type",
			check: ListAccess{
				ObjectID:  validULID,
				Relations: []string{"can_delete", "can_view", "can_read"},
				SubjectID: validULID,
			},
			wantErr: true,
		},
		{
			name: "missing object id",
			check: ListAccess{
				ObjectType: "organization",
				Relations:  []string{"can_delete", "can_view", "can_read"},
				SubjectID:  validULID,
			},
			wantErr: true,
		},
		{
			name: "missing subject id",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relations:  []string{"can_delete", "can_view", "can_read"},
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			c := mock_fga.NewMockSdkClient(t)
			mc := NewMockFGAClient(c)

			if !tc.wantErr {
				// if the relations are not provided, we need to mock the read request
				if tc.check.Relations == nil {
					mock_fga.ReadAuthorizationModel(t, c, tc.expectedRes, nil)
				}

				res := map[string]openfga.BatchCheckSingleResult{}
				for _, relation := range tc.check.Relations {
					res[relation] = openfga.BatchCheckSingleResult{
						Allowed: openfga.PtrBool(slices.Contains(tc.expectedRes, relation)),
					}
				}

				mock_fga.BatchCheck(t, c, res)
			}

			// do request
			_, err := mc.ListRelations(context.Background(), tc.check)

			if tc.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
			// do not assert the result here because we don't know the correlation id for the mocks
			// batchCheckTuples test will cover the result
		})
	}
}

func TestBatchCheckTuples(t *testing.T) {
	validULID := ulids.New().String()

	tests := []struct {
		name        string
		checks      []ofgaclient.ClientBatchCheckItem
		expectedRes []string
		wantErr     bool
	}{
		{
			name: "happy path",
			checks: []ofgaclient.ClientBatchCheckItem{
				{
					User:          "user:" + validULID,
					Relation:      "can_edit",
					Object:        "organization:" + validULID,
					CorrelationId: ulids.New().String(),
				},
				{
					User:          "user:" + validULID,
					Relation:      "can_view",
					Object:        "organization:" + validULID,
					CorrelationId: ulids.New().String(),
				},
				{
					User:          "user:" + validULID,
					Relation:      "can_delete",
					Object:        "organization:" + validULID,
					CorrelationId: ulids.New().String(),
				},
			},
			expectedRes: []string{"can_edit", "can_view"},
			wantErr:     false,
		},
		{
			name: "happy path with context",
			checks: []ofgaclient.ClientBatchCheckItem{
				{
					User:          "user:" + validULID,
					Relation:      "can_edit",
					Object:        "organization:" + validULID,
					CorrelationId: ulids.New().String(),
					Context:       &map[string]any{"role": "admin"},
				},
				{
					User:          "user:" + validULID,
					Relation:      "can_view",
					Object:        "organization:" + validULID,
					CorrelationId: ulids.New().String(),
					Context:       &map[string]any{"role": "admin"},
				},
				{
					User:          "user:" + validULID,
					Relation:      "can_delete",
					Object:        "organization:" + validULID,
					CorrelationId: ulids.New().String(),
					Context:       &map[string]any{"role": "admin"},
				},
			},
			expectedRes: []string{"can_view", "can_edit"},
			wantErr:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			c := mock_fga.NewMockSdkClient(t)
			mc := NewMockFGAClient(c)

			if !tc.wantErr {
				res := map[string]openfga.BatchCheckSingleResult{}
				for _, c := range tc.checks {
					res[c.CorrelationId] = openfga.BatchCheckSingleResult{
						Allowed: openfga.PtrBool(slices.Contains(tc.expectedRes, c.Relation)),
					}
				}

				mock_fga.BatchCheck(t, c, res)
			}

			// do request
			res, err := mc.batchCheckTuples(context.Background(), tc.checks)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Empty(t, res)

				return
			}

			assert.NoError(t, err)
			assert.Len(t, res, len(tc.expectedRes))

			// ensure that the result contains all expected relations
			for _, relation := range tc.expectedRes {
				assert.Contains(t, res, relation)
			}
		})
	}
}

func TestBatchCheckObjectAccess(t *testing.T) {
	validULID := ulids.New().String()

	tests := []struct {
		name           string
		checks         []AccessCheck
		checkedObjects []string
		expectedRes    []string
		wantErr        bool
	}{
		{
			name: "happy path, valid access",
			checks: []AccessCheck{
				{
					ObjectType: "organization",
					ObjectID:   validULID,
					Relation:   "member",
					SubjectID:  validULID,
				},
				{
					ObjectType: "organization",
					ObjectID:   validULID,
					Relation:   "member",
					SubjectID:  validULID,
				},
			},
			checkedObjects: []string{validULID, validULID},
			expectedRes:    []string{"organization:" + validULID},
			wantErr:        false,
		},
		{
			name: "one invalid access check",
			checks: []AccessCheck{
				{
					ObjectType: "organization",
					ObjectID:   validULID,
					Relation:   "member",
					SubjectID:  validULID,
				},
				{
					ObjectType: "",
					ObjectID:   validULID,
					Relation:   "member",
					SubjectID:  validULID,
				},
			},
			expectedRes: nil,
			wantErr:     true,
		},
		{
			name:        "no access checks",
			checks:      []AccessCheck{},
			expectedRes: []string{},
			wantErr:     false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			c := mock_fga.NewMockSdkClient(t)
			mc := NewMockFGAClient(c)

			if !tc.wantErr && len(tc.checks) > 0 {
				res := map[string]openfga.BatchCheckSingleResult{}
				for _, relation := range tc.checkedObjects {
					res[relation] = openfga.BatchCheckSingleResult{
						Allowed: openfga.PtrBool(slices.Contains(tc.expectedRes, relation)),
					}
				}

				mock_fga.BatchCheck(t, c, res)
			}

			// do request
			_, err := mc.BatchCheckObjectAccess(context.Background(), tc.checks)

			if tc.wantErr {
				assert.Error(t, err)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestValidateAccessCheck(t *testing.T) {
	validULID := ulids.New().String()

	tests := []struct {
		name    string
		ac      AccessCheck
		wantErr bool
		errRes  string
	}{
		{
			name: "valid access check",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relation:   "member",
				SubjectID:  validULID,
			},
			wantErr: false,
			errRes:  "",
		},
		{
			name: "valid access check, wildcard tuple",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   Wildcard,
				Relation:   "member",
				SubjectID:  Wildcard,
			},
			wantErr: false,
			errRes:  "",
		},
		{
			name: "missing object type",
			ac: AccessCheck{
				ObjectID:  validULID,
				Relation:  "member",
				SubjectID: validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "missing relation",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   validULID,
				SubjectID:  validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "missing object id",
			ac: AccessCheck{
				ObjectType: "organization",
				Relation:   "member",
				SubjectID:  validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "missing subject id",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relation:   "member",
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "invalid subject id",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   validULID,
				Relation:   "member",
				SubjectID:  "invalid ulid",
			},
			wantErr: true,
			errRes:  ErrInvalidIDInAccessCheck.Error(),
		},
		{
			name: "invalid object id",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   "invalid ulid",
				Relation:   "member",
				SubjectID:  validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidIDInAccessCheck.Error(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessCheck(tc.ac)

			if tc.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errRes)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestValidateListAccess(t *testing.T) {
	validULID := ulids.New().String()

	tests := []struct {
		name    string
		la      ListAccess
		wantErr bool
		errRes  string
	}{
		{
			name: "valid list access",
			la: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
				SubjectID:  validULID,
			},
			wantErr: false,
			errRes:  "",
		},
		{
			name: "valid list access, wildcard tuple",
			la: ListAccess{
				ObjectType: "organization",
				ObjectID:   Wildcard,
				SubjectID:  Wildcard,
			},
			wantErr: false,
			errRes:  "",
		},
		{
			name: "missing object type",
			la: ListAccess{
				ObjectID:  validULID,
				SubjectID: validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "missing object id",
			la: ListAccess{
				ObjectType: "organization",
				SubjectID:  validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "missing subject id",
			la: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidAccessCheck.Error(),
		},
		{
			name: "invalid subject id",
			la: ListAccess{
				ObjectType: "organization",
				ObjectID:   validULID,
				SubjectID:  "invalid ulid",
			},
			wantErr: true,
			errRes:  ErrInvalidIDInAccessCheck.Error(),
		},
		{
			name: "invalid object id",
			la: ListAccess{
				ObjectType: "organization",
				ObjectID:   "invalid ulid",
				SubjectID:  validULID,
			},
			wantErr: true,
			errRes:  ErrInvalidIDInAccessCheck.Error(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateListAccess(tc.la)

			if tc.wantErr {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errRes)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestGetParentContextualTuple(t *testing.T) {
	validULID := ulids.New().String()

	contextWithOrg := auth.NewTestContextWithOrgID(ulids.New().String(), validULID)

	tests := []struct {
		name             string
		context          context.Context
		object           string
		expectedTupleKey *ofgaclient.ClientTupleKey
	}{
		{
			name:             "no organization in context",
			context:          context.Background(),
			object:           "program:" + validULID,
			expectedTupleKey: nil,
		},
		{
			name:             "organization object",
			context:          contextWithOrg,
			object:           "organization:" + validULID,
			expectedTupleKey: nil,
		},
		{
			name:             "user object",
			context:          contextWithOrg,
			object:           "user:" + validULID,
			expectedTupleKey: nil,
		},
		{
			name:    "organization in context",
			context: contextWithOrg,
			object:  "program:" + validULID,
			expectedTupleKey: &ofgaclient.ClientTupleKey{
				User:     "organization:" + validULID,
				Relation: ParentContextRelation,
				Object:   "program:" + validULID,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ct := getParentContextualTuple(tc.context, tc.object)

			if tc.expectedTupleKey == nil {
				assert.Nil(t, ct)
				return
			}

			assert.NotNil(t, ct)
			assert.Equal(t, tc.expectedTupleKey, ct)
		})
	}
}
