package fgax

import (
	"context"
	"encoding/json"
	"os"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	language "github.com/openfga/language/pkg/go/transformer"
	typesystem "github.com/openfga/openfga/pkg/typesystem"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"
)

// CreateModelFromFile creates a new fine grained authorization model and returns the model ID
func (c *Client) CreateModelFromFile(ctx context.Context, fn string, forceCreate bool) (string, error) {
	options := ofgaclient.ClientReadAuthorizationModelsOptions{}

	models, err := c.Ofga.ReadAuthorizationModels(context.Background()).Options(options).Execute()
	if err != nil {
		return "", err
	}

	// Only create a new test model if one does not exist and we aren't forcing a new model to be created
	if !forceCreate {
		if len(models.AuthorizationModels) > 0 {
			modelID := models.GetAuthorizationModels()[0].Id
			c.Logger.Infow("fga model exists", "model_id", modelID)

			return modelID, nil
		}
	}

	// Create new model
	dsl, err := os.ReadFile(fn)
	if err != nil {
		return "", err
	}

	return c.CreateModelFromDSL(ctx, dsl)
}

// CreateModelFromDSL creates a new fine grained authorization model from the DSL and returns the model ID
func (c *Client) CreateModelFromDSL(ctx context.Context, dsl []byte) (string, error) {
	// convert to json
	dslJSON, err := dslToJSON(dsl)
	if err != nil {
		return "", err
	}

	var body ofgaclient.ClientWriteAuthorizationModelRequest
	if err := json.Unmarshal(dslJSON, &body); err != nil {
		return "", err
	}

	return c.CreateModel(ctx, body)
}

// CreateModel creates a new authorization model and returns the new model ID
func (c *Client) CreateModel(ctx context.Context, model ofgaclient.ClientWriteAuthorizationModelRequest) (string, error) {
	resp, err := c.Ofga.WriteAuthorizationModel(ctx).Body(model).Execute()
	if err != nil {
		return "", err
	}

	modelID := resp.GetAuthorizationModelId()

	c.Logger.Infow("fga model created", "model_id", modelID)

	return modelID, nil
}

// dslToJSON converts fga model to JSON
func dslToJSON(dslString []byte) ([]byte, error) {
	parsedAuthModel, err := language.TransformDSLToProto(string(dslString))
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedToTransformModel.Error())
	}

	return protojson.Marshal(parsedAuthModel)
}

// RoleRequest is the request to add a role to the model for an existing object
type RoleRequest struct {
	// Role is the relation to add to the model
	Role string
	// Relation is the relation to the object
	Relations []RelationSetting
	// RelationCombination is the combination of the relation
	RelationCombination RelationCombination
	// ObjectType is the object type to add the role to
	ObjectType string
}

// RelationCombination is the combination of the relation as an `and`, `or`, or `not`
type RelationCombination string

const (
	// Union is an `or` relation
	Union RelationCombination = "union"
	// Intersection is an `and` relation
	Intersection RelationCombination = "intersection"
	// Difference is a `not` relation, currently not supported
	// Difference RelationCombination = "difference"
)

// RelationSetting includes the name of the relation as well as flags to determine the type of relation
type RelationSetting struct {
	// Relation is the relation to the object
	Relation string
	// IsDirect is the direct relation to another fga object type
	IsDirect bool
	// FromRelation is the relation from another relation, leave empty if not a from relation
	FromRelation string
}

// AddOrReplaceRole adds (or replaces the existing) the role to the model and updates the config with the new model id
func (c *Client) AddOrReplaceRole(ctx context.Context, r RoleRequest) error {
	// read the latest model
	model, err := c.Ofga.ReadLatestAuthorizationModel(ctx).Execute()
	if err != nil {
		return err
	}

	// get the model
	m := model.GetAuthorizationModel()

	// get the type definitions from the existing model
	td := m.TypeDefinitions

	addedRole := false

	for i, t := range td {
		if t.Type == r.ObjectType {
			// initialize the relation map
			relations := t.GetRelations()

			// add the role to the relation map
			var metadata *openfga.Metadata
			relations[r.Role], metadata = generateUserset(r)

			// set the relation map and metadata
			t.SetRelations(relations)
			// t.SetMetadata(metadata)

			metadataRelations := t.Metadata.GetRelations()
			for k, v := range *metadata.Relations {
				metadataRelations[k] = v
			}

			t.Metadata.SetRelations(metadataRelations)

			// set the updated type definition
			m.TypeDefinitions[i] = t

			// track that we added the role
			addedRole = true
		}
	}

	// if we didn't add the role, create a new type definition
	if !addedRole {
		m.TypeDefinitions = append(m.TypeDefinitions,
			createNewTypeDefinition(r))
	}

	// create the request to write the model
	request := ofgaclient.ClientWriteAuthorizationModelRequest{
		SchemaVersion:   m.SchemaVersion,
		Conditions:      m.Conditions,
		TypeDefinitions: m.TypeDefinitions,
	}

	// write the model back
	resp, err := c.Ofga.WriteAuthorizationModel(ctx).Body(request).Execute()
	if err != nil {
		return err
	}

	// update to the new model ID in the config
	c.Config.AuthorizationModelId = resp.GetAuthorizationModelId()

	return nil
}

// createNewTypeDefinition creates a new type definition for the model
func createNewTypeDefinition(r RoleRequest) openfga.TypeDefinition {
	relation := make(map[string]openfga.Userset)
	td := openfga.TypeDefinition{
		Type: r.ObjectType,
	}

	// get all the usersets
	us, metadata := generateUserset(r)

	relation[r.Role] = us
	td.Relations = &relation
	td.Metadata = metadata

	return td
}

// generateUserset creates the userset and metadata for the role request
func generateUserset(r RoleRequest) (us openfga.Userset, metadata *openfga.Metadata) {
	// create the default metadata
	metadata = openfga.NewMetadataWithDefaults()

	// create the usersets and determine if we have a direct relation
	uses, directRelation := createUsersets(r)

	// generate the metadata
	md := createNewMetadata(r.Role, directRelation)
	metadata.SetRelations(md)

	// now combine the usersets
	switch r.RelationCombination {
	case Intersection:
		us.Intersection = &openfga.Usersets{
			Child: uses,
		}
	case Union:
		us.Union = &openfga.Usersets{
			Child: uses,
		}
	default:
		// if we only have one userset, just return it
		if len(uses) == 1 {
			us = uses[0]
		} else { // default to union
			us.Union = &openfga.Usersets{
				Child: uses,
			}
		}
	}

	return us, metadata
}

// createUsersets creates the usersets for the role request and determines if there is a direct relation
func createUsersets(r RoleRequest) (uses []openfga.Userset, directRelation string) {
	for _, relation := range r.Relations {
		rel := relation

		switch {
		case relation.IsDirect:
			// create direct relation
			relations := newDirectRelation(r.Role)
			uses = append(uses, relations)

			directRelation = relation.Relation
		case relation.FromRelation != "":
			// create tuple set for a from relation
			uses = append(uses, newTupleUsersetRelation(rel.Relation, rel.FromRelation))
		default:
			// create computed userset, which is a relation to another relation
			uses = append(uses, newComputedUsersetRelation(rel.Relation))
		}
	}

	return
}

// createNewMetadata creates a new metadata for the relations
func createNewMetadata(r string, userType string) map[string]openfga.RelationMetadata {
	rd := make(map[string]openfga.RelationMetadata)
	rd[r] = openfga.RelationMetadata{
		DirectlyRelatedUserTypes: &[]openfga.RelationReference{},
	}

	if userType != "" {
		rd[r] = openfga.RelationMetadata{
			DirectlyRelatedUserTypes: &[]openfga.RelationReference{
				{
					Type: userType,
				},
			},
		}
	}

	return rd
}

// newDirectRelation creates a new relation to an existing object
func newDirectRelation(role string) openfga.Userset {
	// create the user set
	thisRelation := make(map[string]interface{})
	thisRelation[role] = typesystem.This()

	us := openfga.Userset{
		This: &thisRelation,
	}

	return us
}

// newComputedUsersetRelation creates a new computed relation to another relation
func newComputedUsersetRelation(relation string) openfga.Userset {
	return openfga.Userset{
		ComputedUserset: &openfga.ObjectRelation{
			Relation: &relation,
		},
	}
}

// newTupleUsersetRelation creates a new tuple relation to another relation
func newTupleUsersetRelation(relation, fromRelation string) openfga.Userset {
	ts := openfga.TupleToUserset{
		Tupleset: openfga.ObjectRelation{
			Relation: &fromRelation,
		},
		ComputedUserset: openfga.ObjectRelation{
			Relation: &relation,
		},
	}

	return openfga.Userset{
		TupleToUserset: &ts,
	}
}
