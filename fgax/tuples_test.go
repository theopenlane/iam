package fgax

import (
	"context"
	"fmt"
	"testing"

	openfga "github.com/openfga/go-sdk"
	"github.com/stretchr/testify/assert"

	mock_fga "github.com/theopenlane/iam/fgax/internal/mockery"
)

func TestEntityString(t *testing.T) {
	memberRelation := Relation("member")

	testCases := []struct {
		name        string
		entity      Entity
		expectedRes string
	}{
		{
			name: "relationship empty",
			entity: Entity{
				Kind:       "user",
				Identifier: "bz0yOLsL460V-6L9HauX4",
				Relation:   "",
			},
			expectedRes: "user:bz0yOLsL460V-6L9HauX4",
		},
		{
			name: "relationship member",
			entity: Entity{
				Kind:       "organization",
				Identifier: "yKreKfzq3-iG-rhj0N9o9",
				Relation:   memberRelation,
			},
			expectedRes: "organization:yKreKfzq3-iG-rhj0N9o9#member",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.entity.String()

			// result should never be empty
			assert.NotEmpty(t, res)
			assert.Equal(t, tc.expectedRes, res)
		})
	}
}

func TestParseEntity(t *testing.T) {
	memberRelation := Relation("member")

	testCases := []struct {
		name        string
		entity      string
		expectedRes Entity
		errRes      string
	}{
		{
			name: "happy path, user",

			entity: "user:bz0yOLsL460V-6L9HauX4",
			expectedRes: Entity{
				Kind:       "user",
				Identifier: "bz0yOLsL460V-6L9HauX4",
				Relation:   "",
			},
			errRes: "",
		},
		{
			name:   "relationship member",
			entity: "organization:yKreKfzq3-iG-rhj0N9o9#member",
			expectedRes: Entity{
				Kind:       "organization",
				Identifier: "yKreKfzq3-iG-rhj0N9o9",
				Relation:   memberRelation,
			},
			errRes: "",
		},
		{
			name:        "missing parts",
			entity:      "organization",
			expectedRes: Entity{},
			errRes:      "invalid entity representation",
		},
		{
			name:        "too many parts",
			entity:      "organization:yKreKfzq3-iG-rhj0N9o9#member:user:bz0yOLsL460V-6L9HauX4",
			expectedRes: Entity{},
			errRes:      "invalid entity representation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ParseEntity(tc.entity)

			// if we expect an error, check that first
			if tc.errRes != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errRes)
				assert.Empty(t, res)

				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, res)
			assert.Equal(t, tc.expectedRes, res)
		})
	}
}

func TestTupleKeyToWriteRequest(t *testing.T) {
	testCases := []struct {
		name             string
		writes           []TupleKey
		expectedUser     string
		expectedRelation string
		expectedObject   string
		expectedCount    int
	}{
		{
			name: "happy path, user",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "THEBESTUSER",
					},
					Relation: "member",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
					Condition: Condition{
						Name: "condition_name",
						Context: &map[string]any{
							"key": true,
						},
					},
				},
			},
			expectedUser:     "user:THEBESTUSER",
			expectedRelation: "member",
			expectedObject:   "organization:IDOFTHEORG",
			expectedCount:    1,
		},
		{
			name: "happy path, should lowercase kind and relations, no context in condition",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "USER",
						Identifier: "THEBESTUSER",
					},
					Relation: "MEMBER",
					Object: Entity{
						Kind:       "ORGANIZATION",
						Identifier: "IDOFTHEORG",
					},
					Condition: Condition{
						Name: "condition_name",
					},
				},
			},
			expectedUser:     "user:THEBESTUSER",
			expectedRelation: "member",
			expectedObject:   "organization:IDOFTHEORG",
			expectedCount:    1,
		},
		{
			name: "happy path, group",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "group",
						Identifier: "AOPENLANEGROUP",
					},
					Relation: "parent",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
						Relation:   "member",
					},
				},
			},
			expectedUser:     "group:AOPENLANEGROUP",
			expectedRelation: "parent",
			expectedObject:   "organization:IDOFTHEORG#member",
			expectedCount:    1,
		},
		{
			name: "happy path, multiple",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "SITB",
					},
					Relation: "member",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
				},
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "MITB",
					},
					Relation: "admin",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
				},
			},
			expectedCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctk := tupleKeyToWriteRequest(tc.writes)
			assert.NotEmpty(t, ctk)

			if tc.expectedCount == 1 {
				assert.Equal(t, tc.expectedUser, ctk[0].User)
				assert.Equal(t, tc.expectedRelation, ctk[0].Relation)
				assert.Equal(t, tc.expectedObject, ctk[0].Object)

				if tc.writes[0].Condition.Name != "" {
					assert.NotNil(t, ctk[0].Condition)
					assert.Equal(t, tc.writes[0].Condition.Name, ctk[0].Condition.Name)
					assert.Equal(t, tc.writes[0].Condition.Context, ctk[0].Condition.Context)
				}
			} else {
				assert.Len(t, ctk, tc.expectedCount)
			}
		})
	}
}

func TestTupleKeyToDeleteRequest(t *testing.T) {
	testCases := []struct {
		name             string
		writes           []TupleKey
		expectedUser     string
		expectedRelation string
		expectedObject   string
		expectedCount    int
	}{
		{
			name: "happy path, user",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "THEBESTUSER",
					},
					Relation: "member",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
					Condition: Condition{
						Name: "condition_name",
						Context: &map[string]any{
							"key":  true,
							"key2": "value",
						},
					},
				},
			},
			expectedUser:     "user:THEBESTUSER",
			expectedRelation: "member",
			expectedObject:   "organization:IDOFTHEORG",
			expectedCount:    1,
		},
		{
			name: "happy path, uppercase",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "USER",
						Identifier: "THEBESTUSER",
					},
					Relation: "MEMBER",
					Object: Entity{
						Kind:       "ORGANIZATION",
						Identifier: "IDOFTHEORG",
					},
				},
			},
			expectedUser:     "user:THEBESTUSER",
			expectedRelation: "member",
			expectedObject:   "organization:IDOFTHEORG",
			expectedCount:    1,
		},
		{
			name: "happy path, group",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "group",
						Identifier: "AOPENLANEGROUP",
					},
					Relation: "parent",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
						Relation:   "member",
					},
				},
			},
			expectedUser:     "group:AOPENLANEGROUP",
			expectedRelation: "parent",
			expectedObject:   "organization:IDOFTHEORG#member",
			expectedCount:    1,
		},
		{
			name: "happy path, multiple",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "SITB",
					},
					Relation: "member",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
				},
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "MITB",
					},
					Relation: "admin",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
				},
			},
			expectedCount: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctk := tupleKeyToDeleteRequest(tc.writes)
			assert.NotEmpty(t, ctk)

			if tc.expectedCount == 1 {
				assert.Equal(t, tc.expectedUser, ctk[0].User)
				assert.Equal(t, tc.expectedRelation, ctk[0].Relation)
				assert.Equal(t, tc.expectedObject, ctk[0].Object)
			} else {
				assert.Len(t, ctk, tc.expectedCount)
			}
		})
	}
}

func TestWriteTupleKeys(t *testing.T) {
	// setup mock client
	c := mock_fga.NewMockSdkClient(t)

	fc := NewMockFGAClient(c)

	mock_fga.WriteAny(t, c)

	testCases := []struct {
		name    string
		writes  []TupleKey
		deletes []TupleKey
		errExp  string
	}{
		{
			name: "happy path with relation",
			writes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: "THEBESTUSER",
					},
					Relation: "member",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
					Condition: Condition{
						Name: "condition_name",
						Context: &map[string]any{
							"key":  true,
							"key2": "value",
						},
					},
				},
			},
			deletes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user2",
						Identifier: "THEBESTESTUSER",
					},
					Relation: "member",
					Object: Entity{
						Kind:       "organization",
						Identifier: "IDOFTHEORG",
					},
					Condition: Condition{
						Name: "condition_name",
						Context: &map[string]any{
							"key":  true,
							"key2": "value",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fc.WriteTupleKeys(context.Background(), tc.writes, tc.deletes)
			assert.NoError(t, err)
		})
	}
}

func TestDeleteRelationshipTuple(t *testing.T) {
	// setup mock client
	c := mock_fga.NewMockSdkClient(t)

	fc := NewMockFGAClient(c)

	testCases := []struct {
		name              string
		relation          string
		object            string
		expectedRes       string
		errRes            string
		numTuplesToDelete int
	}{
		{
			name:              "happy path with relation",
			object:            "organization:openlane",
			relation:          "member",
			expectedRes:       "",
			numTuplesToDelete: 12,
			errRes:            "",
		},
		{
			name:              "error, missing relation",
			object:            "organization:openlane",
			relation:          "",
			expectedRes:       "",
			numTuplesToDelete: 1,
			errRes:            "Reason: the 'relation' field is malformed",
		},
		{
			name:              "error, missing object",
			object:            "",
			relation:          "member",
			expectedRes:       "",
			numTuplesToDelete: 1,
			errRes:            "Reason: invalid 'object' field format",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer mock_fga.ClearMocks(c)

			tuples := []openfga.TupleKeyWithoutCondition{}

			for i := range tc.numTuplesToDelete {
				tuples = append(tuples, openfga.TupleKeyWithoutCondition{
					User:     fmt.Sprintf("user:ulid-of-member-%d", i),
					Relation: tc.relation,
					Object:   tc.object,
				})
			}

			mock_fga.DeleteAny(t, c, tc.errRes)

			_, err := fc.deleteRelationshipTuple(context.Background(), tuples)

			if tc.errRes != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.errRes)

				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestGetTupleKey(t *testing.T) {
	tests := []struct {
		name    string
		req     TupleRequest
		want    TupleKey
		wantErr bool
	}{
		{
			name: "happy path",
			req: TupleRequest{
				SubjectID:   "HIITSME",
				SubjectType: "user",
				ObjectType:  "organization",
				ObjectID:    "MIDNIGHTSAFTERNOON",
				Relation:    "member",
			},
			want: TupleKey{
				Subject: Entity{
					Kind:       "user",
					Identifier: "HIITSME",
				},
				Relation: "member",
				Object: Entity{
					Kind:       "organization",
					Identifier: "MIDNIGHTSAFTERNOON",
				},
			},
			wantErr: false,
		},
		{
			name: "happy path with tuple set relations",
			req: TupleRequest{
				SubjectID:       "HIITSME",
				SubjectType:     "user",
				SubjectRelation: "member",
				ObjectType:      "organization",
				ObjectID:        "MIDNIGHTSAFTERNOON",
				ObjectRelation:  "member",
				Relation:        "member",
			},
			want: TupleKey{
				Subject: Entity{
					Kind:       "user",
					Identifier: "HIITSME",
					Relation:   "member",
				},
				Relation: "member",
				Object: Entity{
					Kind:       "organization",
					Identifier: "MIDNIGHTSAFTERNOON",
					Relation:   "member",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetTupleKey(tt.req)
			assert.Equal(t, tt.want, got)
		})
	}
}
func TestCreateWildcardTuple(t *testing.T) {
	testCases := []struct {
		name        string
		objectID    string
		objectType  string
		expectedRes []TupleKey
	}{
		{
			name:       "happy path",
			objectID:   "object123",
			objectType: "document",
			expectedRes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: Wildcard,
					},
					Object: Entity{
						Kind:       "document",
						Identifier: "object123",
					},
					Relation: CanView,
				},
				{
					Subject: Entity{
						Kind:       "service",
						Identifier: Wildcard,
					},
					Object: Entity{
						Kind:       "document",
						Identifier: "object123",
					},
					Relation: CanView,
				},
			},
		},
		{
			name:       "another object type",
			objectID:   "object456",
			objectType: "file",
			expectedRes: []TupleKey{
				{
					Subject: Entity{
						Kind:       "user",
						Identifier: Wildcard,
					},
					Object: Entity{
						Kind:       "file",
						Identifier: "object456",
					},
					Relation: CanView,
				},
				{
					Subject: Entity{
						Kind:       "service",
						Identifier: Wildcard,
					},
					Object: Entity{
						Kind:       "file",
						Identifier: "object456",
					},
					Relation: CanView,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res := CreateWildcardViewerTuple(tc.objectID, tc.objectType)
			assert.Equal(t, tc.expectedRes, res)
		})
	}
}
