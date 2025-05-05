package fgax

import (
	"context"
	"slices"
	"testing"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/utils/ulids"

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
			body := ofgaclient.ClientCheckRequest{
				User:     "user:ulid-of-member",
				Relation: tc.relation,
				Object:   tc.object,
			}

			mock_fga.CheckAny(t, c, tc.expectedRes)

			// do request
			valid, err := mc.checkTuple(context.Background(), body)

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
				ObjectID:   "ulid-of-org",
				Relation:   "member",
				SubjectID:  "ulid-of-member",
			},
			expectedRes: true,
			wantErr:     false,
		},
		{
			name: "happy path, valid access with context",
			ac: AccessCheck{
				ObjectType:  "organization",
				ObjectID:    "ulid-of-org",
				SubjectType: "service",
				Relation:    "member",
				SubjectID:   "ulid-of-token",
				Context:     &map[string]any{"service": "github"},
			},
			expectedRes: true,
			wantErr:     false,
		},
		{
			name: "missing object type",
			ac: AccessCheck{
				ObjectID:  "ulid-of-org",
				Relation:  "member",
				SubjectID: "ulid-of-member",
			},
			expectedRes: false,
			wantErr:     true,
		},
		{
			name: "missing relation",
			ac: AccessCheck{
				ObjectType: "organization",
				ObjectID:   "ulid-of-org",
				SubjectID:  "ulid-of-member",
			},
			expectedRes: false,
			wantErr:     true,
		},
		{
			name: "missing object type",
			ac: AccessCheck{
				Relation:  "member",
				ObjectID:  "ulid-of-org",
				SubjectID: "ulid-of-member",
			},
			expectedRes: false,
			wantErr:     true,
		},
		{
			name: "missing subject",
			ac: AccessCheck{
				Relation:   "member",
				ObjectType: "organization",
				ObjectID:   "ulid-of-org",
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
				ObjectID:   "ulid-of-org",
				Relations:  []string{"can_delete", "can_view", "can_read"},
				SubjectID:  "ulid-of-member",
			},
			expectedRes: []string{"can_view", "can_read"},
			wantErr:     false,
		},
		{
			name: "happy path, no relations provided",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   "ulid-of-org",
				SubjectID:  "ulid-of-member",
			},
			expectedRes: []string{"can_view", "can_read"},
			wantErr:     false,
		},
		{
			name: "happy path with context",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   "ulid-of-org",
				Relations:  []string{"can_delete", "can_view", "can_read"},
				SubjectID:  "ulid-of-member",
				Context:    &map[string]any{"role": "admin"},
			},
			expectedRes: []string{"can_view", "can_read"},
			wantErr:     false,
		},
		{
			name: "missing object type",
			check: ListAccess{
				ObjectID:  "ulid-of-org",
				Relations: []string{"can_delete", "can_view", "can_read"},
				SubjectID: "ulid-of-member",
			},
			wantErr: true,
		},
		{
			name: "missing object id",
			check: ListAccess{
				ObjectType: "organization",
				Relations:  []string{"can_delete", "can_view", "can_read"},
				SubjectID:  "ulid-of-member",
			},
			wantErr: true,
		},
		{
			name: "missing subject id",
			check: ListAccess{
				ObjectType: "organization",
				ObjectID:   "ulid-of-org",
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
					User:          "user:ulid-of-member",
					Relation:      "can_edit",
					Object:        "organization:ulid-of-org",
					CorrelationId: ulids.New().String(),
				},
				{
					User:          "user:ulid-of-member",
					Relation:      "can_view",
					Object:        "organization:ulid-of-org",
					CorrelationId: ulids.New().String(),
				},
				{
					User:          "user:ulid-of-member",
					Relation:      "can_delete",
					Object:        "organization:ulid-of-org",
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
					User:          "user:ulid-of-member",
					Relation:      "can_edit",
					Object:        "organization:ulid-of-org",
					CorrelationId: ulids.New().String(),
					Context:       &map[string]any{"role": "admin"},
				},
				{
					User:          "user:ulid-of-member",
					Relation:      "can_view",
					Object:        "organization:ulid-of-org",
					CorrelationId: ulids.New().String(),
					Context:       &map[string]any{"role": "admin"},
				},
				{
					User:          "user:ulid-of-member",
					Relation:      "can_delete",
					Object:        "organization:ulid-of-org",
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
				require.Error(t, err)
				assert.Empty(t, res)

				return
			}

			require.NoError(t, err)
			require.Len(t, res, len(tc.expectedRes))

			// ensure that the result contains all expected relations
			for _, relation := range tc.expectedRes {
				assert.Contains(t, res, relation)
			}
		})
	}
}

func TestBatchCheckObjectAccess(t *testing.T) {
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
					ObjectID:   "ulid-of-org-1",
					Relation:   "member",
					SubjectID:  "ulid-of-member",
				},
				{
					ObjectType: "organization",
					ObjectID:   "ulid-of-org-2",
					Relation:   "member",
					SubjectID:  "ulid-of-member",
				},
			},
			checkedObjects: []string{"organization:ulid-of-org-1", "organization:ulid-of-org-2"},
			expectedRes:    []string{"organization:ulid-of-org-1"},
			wantErr:        false,
		},
		{
			name: "one invalid access check",
			checks: []AccessCheck{
				{
					ObjectType: "organization",
					ObjectID:   "ulid-of-org-1",
					Relation:   "member",
					SubjectID:  "ulid-of-member",
				},
				{
					ObjectType: "",
					ObjectID:   "ulid-of-org-2",
					Relation:   "member",
					SubjectID:  "ulid-of-member",
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
