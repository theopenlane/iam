package fgax

import (
	"context"
	"errors"
	"fmt"
	"testing"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mock_fga "github.com/theopenlane/iam/fgax/mockery"
)

func TestListContains(t *testing.T) {
	testCases := []struct {
		name        string
		objectID    string
		fgaObjects  []string
		expectedRes bool
	}{
		{
			name:     "happy path, object found",
			objectID: "TbaK4knu9NDoG85DAKob0",
			fgaObjects: []string{
				"organization:TbaK4knu9NDoG85DAKob0",
				"organization:-AV6JyT7-qmedy0WPOjKM",
				"something-else:TbaK4knu9NDoG85DAKob0",
			},
			expectedRes: true,
		},
		{
			name:     "incorrect type but correct id, not found",
			objectID: "TbaK4knu9NDoG85DAKob0",
			fgaObjects: []string{
				"organization:GxSAidJu4LZzjcnHQ-KTV",
				"organization:-AV6JyT7-qmedy0WPOjKM",
				"something-else:TbaK4knu9NDoG85DAKob0",
			},
			expectedRes: false,
		},
		{
			name:     "id not found",
			objectID: "TbaK4knu9NDoG85DAKob0",
			fgaObjects: []string{
				"organization:GxSAidJu4LZzjcnHQ-KTV",
				"organization:-AV6JyT7-qmedy0WPOjKM",
			},
			expectedRes: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entityType := "organization"
			found := ListContains(entityType, tc.fgaObjects, tc.objectID)

			assert.Equal(t, tc.expectedRes, found)
		})
	}
}

func TestListObjectsRequest(t *testing.T) {
	objects := []string{"organization:openlane"}
	testCases := []struct {
		name        string
		relation    string
		userID      string
		subjectType string
		objectType  string
		expectedRes *ofgaclient.ClientListObjectsResponse
		errRes      error
	}{
		{
			name:        "happy path",
			relation:    "can_view",
			userID:      "ulid-of-user",
			subjectType: "user",
			objectType:  "organization",
			expectedRes: &openfga.ListObjectsResponse{
				Objects: objects,
			},
			errRes: nil,
		},
		{
			name:        "happy path, service account",
			relation:    "can_view",
			userID:      "ulid-of-token",
			subjectType: "service",
			objectType:  "organization",
			expectedRes: &openfga.ListObjectsResponse{
				Objects: objects,
			},
			errRes: nil,
		},
		{
			name:        "error response",
			relation:    "can_view",
			userID:      "ulid-of-user",
			objectType:  "organization",
			expectedRes: nil,
			errRes:      errors.New("boom"), //nolint:err113
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			mc := mock_fga.NewMockSdkClient(t)

			c := NewMockFGAClient(t, mc)

			// mock response for input
			body := []string{
				"organization:openlane",
			}

			mock_fga.ListOnce(t, mc, body, tc.errRes)

			// do request
			req := ListRequest{
				SubjectID:   tc.userID,
				SubjectType: tc.subjectType,
				ObjectType:  tc.objectType,
				Relation:    tc.relation,
			}

			resp, err := c.ListObjectsRequest(
				context.Background(),
				req,
			)

			if tc.errRes != nil {
				assert.Error(t, err)
				assert.Equal(t, err, tc.errRes)
				assert.Equal(t, tc.expectedRes, resp)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRes.GetObjects(), resp.GetObjects())
		})
	}
}

func TestListUsersRequest(t *testing.T) {
	users := []openfga.User{
		{
			Object: &openfga.FgaObject{
				Type: "user",
				Id:   "mitb",
			},
		},
		{
			Object: &openfga.FgaObject{
				Type: "user",
				Id:   "funk",
			},
		},
	}

	testCases := []struct {
		name        string
		relation    string
		objectType  string
		objectID    string
		expectedRes *ofgaclient.ClientListUsersResponse
		errRes      error
	}{
		{
			name:       "happy path",
			relation:   "can_view",
			objectType: "organization",
			objectID:   "ulid-of-object",
			expectedRes: &openfga.ListUsersResponse{
				Users: users,
			},
			errRes: nil,
		},
		{
			name:        "error response",
			relation:    "can_view",
			objectType:  "organization",
			objectID:    "ulid-of-object1",
			expectedRes: nil,
			errRes:      errors.New("boom"), //nolint:err113
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// setup mock client
			mc := mock_fga.NewMockSdkClient(t)

			c := NewMockFGAClient(t, mc)

			// mock response for input
			mock_fga.ListUsers(t, mc, users, tc.errRes)

			req := ListRequest{
				ObjectID:   tc.objectID,
				ObjectType: tc.objectType,
				Relation:   tc.relation,
			}

			// do request
			resp, err := c.ListUserRequest(
				context.Background(),
				req,
			)

			if tc.errRes != nil {
				assert.Error(t, err)
				assert.Equal(t, err, tc.errRes)
				assert.Equal(t, tc.expectedRes, resp)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRes.GetUsers(), resp.GetUsers())
		})
	}
}

func TestGetEntityIDs(t *testing.T) {
	testCases := []struct {
		name        string
		objects     []string
		expectedIDs []string
		expectedErr string
	}{
		{
			name:        "happy path",
			objects:     []string{"organization:openlane"},
			expectedIDs: []string{"openlane"},
		},
		{
			name:        "multiple objects",
			objects:     []string{"organization:openlane", "organization:another"},
			expectedIDs: []string{"openlane", "another"},
		},
		{
			name:        "empty objects",
			objects:     []string{},
			expectedIDs: []string{},
		},

		{
			name:        "invalid object",
			objects:     []string{"organization"},
			expectedIDs: []string{},
			expectedErr: "invalid entity representation: organization",
		},
	}

	for _, tc := range testCases {
		response := &ofgaclient.ClientListObjectsResponse{
			Objects: tc.objects,
		}

		ids, err := GetEntityIDs(response)
		if tc.expectedErr != "" {
			assert.Error(t, err)
			assert.Nil(t, ids)

			return
		}

		require.NoError(t, err)
		assert.Equal(t, tc.expectedIDs, ids)
	}
}

func TestSetListRequestDefaults(t *testing.T) {
	testCases := []struct {
		name        string
		req         ListRequest
		expectedReq ListRequest
	}{
		{
			name: "set all",
			req:  ListRequest{},
			expectedReq: ListRequest{
				SubjectType: defaultSubject,
				Relation:    CanView,
			},
		},
		{
			name: "set default subject type",
			req: ListRequest{
				Relation: CanEdit,
			},
			expectedReq: ListRequest{
				SubjectType: defaultSubject,
				Relation:    CanEdit,
			},
		},
		{
			name: "set default relation",
			req: ListRequest{
				SubjectType: "service",
			},
			expectedReq: ListRequest{
				SubjectType: "service",
				Relation:    CanView,
			},
		},
		{
			name: "set none",
			req: ListRequest{
				SubjectType: "service",
				Relation:    CanEdit,
			},
			expectedReq: ListRequest{
				SubjectType: "service",
				Relation:    CanEdit,
			},
		},
	}

	for _, tc := range testCases {
		// Call the function to set the default values
		tc.req.setListRequestDefaults()

		// Check if the default values are set correctly
		assert.Equal(t, tc.expectedReq, tc.req)
	}
}
func TestValidateListObjectsInput(t *testing.T) {
	testCases := []struct {
		name     string
		req      ListRequest
		expected error
	}{
		{
			name: "valid input",
			req: ListRequest{
				SubjectID:   "user123",
				SubjectType: "user",
				Relation:    "can_view",
			},
			expected: nil,
		},
		{
			name: "missing subject ID",
			req: ListRequest{
				SubjectType: "user",
				Relation:    "can_view",
			},
			expected: fmt.Errorf("%w, subject_id", ErrMissingRequiredField),
		},
		{
			name: "default subject type",
			req: ListRequest{
				SubjectID: "user123",
				Relation:  "can_view",
			},
			expected: nil,
		},
		{
			name: "default relation",
			req: ListRequest{
				SubjectID:   "user123",
				SubjectType: "user",
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.validateListObjectsInput()
			assert.Equal(t, tc.expected, err)
		})
	}
}
func TestValidateListUsersInput(t *testing.T) {
	testCases := []struct {
		name     string
		req      ListRequest
		expected error
	}{
		{
			name: "valid input",
			req: ListRequest{
				ObjectID:   "object123",
				ObjectType: "organization",
				Relation:   "can_view",
			},
			expected: nil,
		},
		{
			name: "missing object ID",
			req: ListRequest{
				ObjectType: "organization",
				Relation:   "can_view",
			},
			expected: fmt.Errorf("%w, object_id", ErrMissingRequiredField),
		},
		{
			name: "default object type",
			req: ListRequest{
				ObjectID: "object123",
				Relation: "can_view",
			},
			expected: nil,
		},
		{
			name: "default relation",
			req: ListRequest{
				ObjectID:   "object123",
				ObjectType: "organization",
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.validateListUsersInput()
			assert.Equal(t, tc.expected, err)
		})
	}
}
