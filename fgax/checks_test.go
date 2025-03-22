package fgax

import (
	"context"
	"testing"

	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/assert"

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
			mc := NewMockFGAClient(t, c)

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
			mc := NewMockFGAClient(t, c)

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
			mc := NewMockFGAClient(t, c)

			if !tc.wantErr {
				mock_fga.BatchCheck(t, c, tc.check.Relations, tc.expectedRes)
			}

			// do request
			valid, err := mc.ListRelations(context.Background(), tc.check)

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
			mc := NewMockFGAClient(t, c)

			if !tc.wantErr {
				mock_fga.BatchCheck(t, c, tc.checkedObjects, tc.expectedRes)
			}

			// do request
			valid, err := mc.BatchCheckObjectAccess(context.Background(), tc.checks)

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

func TestBatchGetAllowedIDs(t *testing.T) {
	tests := []struct {
		name           string
		checks         []AccessCheck
		checkedObjects []string
		checkResults   []string
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
			checkResults:   []string{"organization:ulid-of-org-1"},
			expectedRes:    []string{"ulid-of-org-1"},
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
			mc := NewMockFGAClient(t, c)

			if !tc.wantErr {
				mock_fga.BatchCheck(t, c, tc.checkedObjects, tc.checkResults)
			}

			// do request
			valid, err := mc.BatchGetAllowedIDs(context.Background(), tc.checks)

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
