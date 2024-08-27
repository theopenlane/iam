package fgax

import (
	"testing"

	openfga "github.com/openfga/go-sdk"
	typesystem "github.com/openfga/openfga/pkg/typesystem"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

func TestNewDirectRelation(t *testing.T) {
	testCases := []struct {
		name        string
		role        string
		expectedRes openfga.Userset
	}{
		{
			name: "new admin role",
			role: "admin",
			expectedRes: openfga.Userset{
				This: &map[string]interface{}{
					"admin": typesystem.This(),
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userset := newDirectRelation(tc.role)

			assert.Equal(t, tc.expectedRes, userset)
		})
	}
}

func TestNewComputedUsersetRelation(t *testing.T) {
	testCases := []struct {
		name        string
		relation    string
		expectedRes openfga.Userset
	}{
		{
			name:     "new relation",
			relation: "meow",
			expectedRes: openfga.Userset{
				ComputedUserset: &openfga.ObjectRelation{
					Relation: lo.ToPtr("meow"),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userset := newComputedUsersetRelation(tc.relation)

			assert.Equal(t, tc.expectedRes, userset)
		})
	}
}

func TestNewTupleUsersetRelation(t *testing.T) {
	testCases := []struct {
		name         string
		relation     string
		fromRelation string
		expectedRes  openfga.Userset
	}{
		{
			name:         "new tuple userset relation",
			relation:     "relation",
			fromRelation: "fromRelation",
			expectedRes: openfga.Userset{
				TupleToUserset: &openfga.TupleToUserset{
					Tupleset: openfga.ObjectRelation{
						Relation: lo.ToPtr("fromRelation"),
					},
					ComputedUserset: openfga.ObjectRelation{
						Relation: lo.ToPtr("relation"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userset := newTupleUsersetRelation(tc.relation, tc.fromRelation)

			assert.Equal(t, tc.expectedRes, userset)
		})
	}
}

func TestCreateNewMetadata(t *testing.T) {
	testCases := []struct {
		name       string
		relation   string
		userType   string
		expectedRD map[string]openfga.RelationMetadata
	}{
		{
			name:     "empty user type, not direct",
			relation: "relation",
			userType: "",
			expectedRD: map[string]openfga.RelationMetadata{
				"relation": {
					DirectlyRelatedUserTypes: &[]openfga.RelationReference{},
				},
			},
		},
		{
			name:     "non-empty user type, direct relation",
			relation: "relation",
			userType: "user",
			expectedRD: map[string]openfga.RelationMetadata{
				"relation": {
					DirectlyRelatedUserTypes: &[]openfga.RelationReference{
						{
							Type: "user",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rd := createNewMetadata(tc.relation, tc.userType)

			assert.Equal(t, tc.expectedRD, rd)
		})
	}
}

func TestCreateUsersets(t *testing.T) {
	testCases := []struct {
		name           string
		role           string
		relations      []RelationSetting
		expectedUses   []openfga.Userset
		expectedDirect string
	}{
		{
			name: "direct relation",
			role: "admin",
			relations: []RelationSetting{
				{
					IsDirect: true,
					Relation: "admin",
				},
			},
			expectedUses: []openfga.Userset{
				{
					This: &map[string]interface{}{
						"admin": typesystem.This(),
					},
				},
			},
			expectedDirect: "admin",
		},
		{
			name: "tuple set for a from relation",
			role: "user",
			relations: []RelationSetting{
				{
					Relation:     "relation",
					FromRelation: "fromRelation",
				},
			},
			expectedUses: []openfga.Userset{
				{
					TupleToUserset: &openfga.TupleToUserset{
						Tupleset: openfga.ObjectRelation{
							Relation: lo.ToPtr("fromRelation"),
						},
						ComputedUserset: openfga.ObjectRelation{
							Relation: lo.ToPtr("relation"),
						},
					},
				},
			},
			expectedDirect: "",
		},
		{
			name: "computed userset",
			role: "user",
			relations: []RelationSetting{
				{
					Relation: "relation",
				},
			},
			expectedUses: []openfga.Userset{
				{
					ComputedUserset: &openfga.ObjectRelation{
						Relation: lo.ToPtr("relation"),
					},
				},
			},
			expectedDirect: "",
		},
		{
			name: "multiple relations with direct",
			role: "user",
			relations: []RelationSetting{
				{
					Relation: "relation",
				},
				{
					IsDirect: true,
					Relation: "admin",
				},
			},
			expectedUses: []openfga.Userset{
				{
					ComputedUserset: &openfga.ObjectRelation{
						Relation: lo.ToPtr("relation"),
					},
				},
				{
					This: &map[string]interface{}{
						"user": typesystem.This(),
					},
				},
			},
			expectedDirect: "admin",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			uses, directRelation := createUsersets(RoleRequest{
				Role:      tc.role,
				Relations: tc.relations,
			})

			assert.Equal(t, tc.expectedUses, uses)
			assert.Equal(t, tc.expectedDirect, directRelation)
		})
	}
}

func TestGenerateUserset(t *testing.T) {
	testCases := []struct {
		name                string
		role                string
		relations           []RelationSetting
		relationCombination RelationCombination
		expectedUserset     openfga.Userset
		expectedMetadata    *openfga.Metadata
	}{
		{
			name: "intersection combination",
			role: "admin",
			relations: []RelationSetting{
				{
					IsDirect: true,
					Relation: "user",
				},
				{
					Relation: "member",
				},
			},
			relationCombination: Intersection,
			expectedUserset: openfga.Userset{
				Intersection: &openfga.Usersets{
					Child: []openfga.Userset{
						{
							This: &map[string]interface{}{
								"admin": typesystem.This(),
							},
						},
						{
							ComputedUserset: &openfga.ObjectRelation{
								Relation: lo.ToPtr("member"),
							},
						},
					},
				},
			},
			expectedMetadata: &openfga.Metadata{
				Relations: &map[string]openfga.RelationMetadata{
					"admin": {
						DirectlyRelatedUserTypes: &[]openfga.RelationReference{
							{
								Type: "user",
							},
						},
					},
				},
			},
		},
		{
			name: "union combination",
			role: "user",
			relations: []RelationSetting{
				{
					Relation:     "relation",
					FromRelation: "fromRelation",
				},
				{
					Relation: "member",
				},
			},
			relationCombination: Union,
			expectedUserset: openfga.Userset{
				Union: &openfga.Usersets{
					Child: []openfga.Userset{
						{
							TupleToUserset: &openfga.TupleToUserset{
								Tupleset: openfga.ObjectRelation{
									Relation: lo.ToPtr("fromRelation"),
								},
								ComputedUserset: openfga.ObjectRelation{
									Relation: lo.ToPtr("relation"),
								},
							},
						},
						{
							ComputedUserset: &openfga.ObjectRelation{
								Relation: lo.ToPtr("member"),
							},
						},
					},
				},
			},
			expectedMetadata: &openfga.Metadata{
				Relations: &map[string]openfga.RelationMetadata{
					"user": {
						DirectlyRelatedUserTypes: &[]openfga.RelationReference{},
					},
				},
			},
		},
		{
			name: "default combination with one userset",
			role: "user",
			relations: []RelationSetting{
				{
					Relation: "relation",
				},
			},
			relationCombination: "",
			expectedUserset: openfga.Userset{
				ComputedUserset: &openfga.ObjectRelation{
					Relation: lo.ToPtr("relation"),
				},
			},
			expectedMetadata: &openfga.Metadata{
				Relations: &map[string]openfga.RelationMetadata{
					"user": {
						DirectlyRelatedUserTypes: &[]openfga.RelationReference{},
					},
				},
			},
		},
		{
			name: "default combination with multiple usersets",
			role: "user",
			relations: []RelationSetting{
				{
					Relation: "relation",
				},
				{
					IsDirect: true,
					Relation: "admin",
				},
			},
			relationCombination: "",
			expectedUserset: openfga.Userset{
				Union: &openfga.Usersets{
					Child: []openfga.Userset{
						{
							ComputedUserset: &openfga.ObjectRelation{
								Relation: lo.ToPtr("relation"),
							},
						},
						{
							This: &map[string]interface{}{
								"user": typesystem.This(),
							},
						},
					},
				},
			},
			expectedMetadata: &openfga.Metadata{
				Relations: &map[string]openfga.RelationMetadata{
					"user": {
						DirectlyRelatedUserTypes: &[]openfga.RelationReference{
							{
								Type: "admin",
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userset, metadata := generateUserset(RoleRequest{
				Role:                tc.role,
				Relations:           tc.relations,
				RelationCombination: tc.relationCombination,
			})

			assert.Equal(t, tc.expectedUserset, userset)
			assert.Equal(t, tc.expectedMetadata, metadata)
		})
	}
}
