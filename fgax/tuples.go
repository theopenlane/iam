package fgax

import (
	"context"
	"regexp"
	"slices"
	"strings"

	openfga "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/rs/zerolog/log"
)

// setup relations for use in creating tuples
const (
	// SystemAdminRelation is the relation for system admins that have the highest level of access
	SystemAdminRelation = "system_admin"
	// MemberRelation is the relation for members of an entity
	MemberRelation = "member"
	// AdminRelation is the relation for admins of an entity
	AdminRelation = "admin"
	// OwnerRelation is the relation for owners of an entity
	OwnerRelation = "owner"
	// AuditorRelation is the relation for auditors of an entity
	AuditorRelation = "auditor"
	// CollaboratorRelation is the relation for collaborators of an entity
	CollaboratorRelation = "collaborator"

	// SelfRelation is the relation for the object to itself, usually for user relations
	SelfRelation = "_self"
	// ParentRelation is the relation for parents of an entity
	ParentRelation = "parent"
	// EditorRelation is the relation to assign editors to an entity
	EditorRelation = "editor"
	// BlockedRelation is the relation to block access to an entity
	BlockedRelation = "blocked"

	// AssigneeRelation is the relation for assignee of an entity
	AssigneeRelation = "assignee"

	// CanView is the relation for viewing an entity
	CanView = "can_view"
	// CanEdit is the relation for editing an entity
	CanEdit = "can_edit"
	// CanDelete is the relation for deleting an entity
	CanDelete = "can_delete"
	// CanInviteMembers is the relation for inviting members to an entity
	CanInviteMembers = "can_invite_members"
	// CanInviteAdmins is the relation for inviting admins to an entity
	CanInviteAdmins = "can_invite_admins"
)

const (
	// defaultPageSize is based on the openfga max of 100
	defaultPageSize = 100
	// maxWrites is the maximum number of Writes and Deletes supported by the OpenFGA transactional write api
	// see https://openfga.dev/docs/interacting/transactional-writes for more details
	maxWrites = 10
)

// TupleKey represents a relationship tuple in OpenFGA
type TupleKey struct {
	// Subject is the entity that is the subject of the relationship, usually a user
	Subject Entity
	// Object is the entity that is the object of the relationship, (e.g. organization, project, document, etc)
	Object Entity
	// Relation is the relationship between the subject and object
	Relation Relation `json:"relation"`
}

// TupleRequest is the fields needed to check a tuple in the FGA store
type TupleRequest struct {
	// ObjectID is the identifier of the object that the subject is related to
	ObjectID string
	// ObjectType is the type of object that the subject is related to
	ObjectType string
	// SubjectID is the identifier of the subject that is related to the object
	SubjectID string
	// SubjectType is the type of subject that is related to the object
	SubjectType string
	// Relation is the relationship between the subject and object
	Relation string
}

func NewTupleKey() TupleKey { return TupleKey{} }

// entityRegex is used to validate that a string represents an Entity/EntitySet
// and helps to convert from a string representation into an Entity struct.
var entityRegex = regexp.MustCompile(`([A-za-z0-9_][A-za-z0-9_-]*):([A-za-z0-9_][A-za-z0-9_@.+-]*)(#([A-za-z0-9_][A-za-z0-9_-]*))?`)

// Kind represents the type of the entity in OpenFGA.
type Kind string

// String implements the Stringer interface.
func (k Kind) String() string {
	return strings.ToLower(string(k))
}

// Relation represents the type of relation between entities in OpenFGA.
type Relation string

// String implements the Stringer interface.
func (r Relation) String() string {
	return strings.ToLower(string(r))
}

// Entity represents an entity/entity-set in OpenFGA.
// Example: `user:<user-id>`, `org:<org-id>#member`
type Entity struct {
	Kind       Kind
	Identifier string
	Relation   Relation
}

// String returns a string representation of the entity/entity-set.
func (e *Entity) String() string {
	if e.Relation == "" {
		return e.Kind.String() + ":" + e.Identifier
	}

	return e.Kind.String() + ":" + e.Identifier + "#" + e.Relation.String()
}

// ParseEntity will parse a string representation into an Entity. It expects to
// find entities of the form:
//   - <entityType>:<Identifier>
//     eg. organization:openlane
//   - <entityType>:<Identifier>#<relationship-set>
//     eg. organization:openlane#member
func ParseEntity(s string) (Entity, error) {
	// entities should only contain a single colon
	c := strings.Count(s, ":")
	if c != 1 {
		return Entity{}, newInvalidEntityError(s)
	}

	match := entityRegex.FindStringSubmatch(s)
	if match == nil {
		return Entity{}, newInvalidEntityError(s)
	}

	// Extract and return the relevant information from the sub-matches.
	return Entity{
		Kind:       Kind(match[1]),
		Identifier: match[2],
		Relation:   Relation(match[4]),
	}, nil
}

// tupleKeyToWriteRequest converts a TupleKey to a ClientTupleKey to send to FGA
func tupleKeyToWriteRequest(writes []TupleKey) (w []ofgaclient.ClientTupleKey) {
	for _, k := range writes {
		ctk := ofgaclient.ClientTupleKey{}
		ctk.SetObject(k.Object.String())
		ctk.SetUser(k.Subject.String())
		ctk.SetRelation(k.Relation.String())

		w = append(w, ctk)
	}

	return
}

// tupleKeyToDeleteRequest converts a TupleKey to a TupleKeyWithoutCondition to send to FGA
func tupleKeyToDeleteRequest(deletes []TupleKey) (d []openfga.TupleKeyWithoutCondition) {
	for _, k := range deletes {
		ctk := openfga.TupleKeyWithoutCondition{}
		ctk.SetObject(k.Object.String())
		ctk.SetUser(k.Subject.String())
		ctk.SetRelation(k.Relation.String())

		d = append(d, ctk)
	}

	return
}

// WriteTupleKeys takes a tuples keys, converts them to a client write request, which can contain up to 10 writes and deletes,
// and executes in a single transaction
func (c *Client) WriteTupleKeys(ctx context.Context, writes []TupleKey, deletes []TupleKey) (*ofgaclient.ClientWriteResponse, error) {
	opts := ofgaclient.ClientWriteOptions{AuthorizationModelId: openfga.PtrString(c.Config.AuthorizationModelId)}

	body := ofgaclient.ClientWriteRequest{
		Writes:  tupleKeyToWriteRequest(writes),
		Deletes: tupleKeyToDeleteRequest(deletes),
	}

	resp, err := c.Ofga.Write(ctx).Body(body).Options(opts).Execute()
	if err != nil {
		log.Info().Err(err).Interface("user", resp.Writes).Msg("error writing relationship tuples")

		return resp, err
	}

	for _, writes := range resp.Writes {
		if writes.Error != nil {
			log.Error().Err(writes.Error).
				Str("user", writes.TupleKey.User).
				Str("relation", writes.TupleKey.Relation).
				Str("object", writes.TupleKey.Object).
				Msg("error creating relationship tuples")

			return resp, newWritingTuplesError(writes.TupleKey.User, writes.TupleKey.Relation, writes.TupleKey.Object, "writing", err)
		}
	}

	for _, deletes := range resp.Deletes {
		if deletes.Error != nil {
			log.Error().Err(deletes.Error).
				Str("user", deletes.TupleKey.User).
				Str("relation", deletes.TupleKey.Relation).
				Str("object", deletes.TupleKey.Object).
				Msg("error deleting relationship tuples")

			return resp, newWritingTuplesError(deletes.TupleKey.User, deletes.TupleKey.Relation, deletes.TupleKey.Object, "writing", err)
		}
	}

	return resp, nil
}

// deleteRelationshipTuple deletes a relationship tuple in the openFGA store
func (c *Client) deleteRelationshipTuple(ctx context.Context, tuples []openfga.TupleKeyWithoutCondition) (*ofgaclient.ClientWriteResponse, error) {
	if len(tuples) == 0 {
		return nil, nil
	}

	opts := ofgaclient.ClientWriteOptions{AuthorizationModelId: openfga.PtrString(c.Config.AuthorizationModelId)}

	resp, err := c.Ofga.DeleteTuples(ctx).Body(tuples).Options(opts).Execute()
	if err != nil {
		log.Error().Err(err).Msg("error deleting relationship tuples")

		return resp, err
	}

	for _, del := range resp.Deletes {
		if del.Error != nil {
			log.Error().Err(del.Error).
				Str("user", del.TupleKey.User).
				Str("relation", del.TupleKey.Relation).
				Str("object", del.TupleKey.Object).
				Msg("error deleting relationship tuples")

			return resp, newWritingTuplesError(del.TupleKey.User, del.TupleKey.Relation, del.TupleKey.Object, "deleting", err)
		}
	}

	return resp, nil
}

// getAllTuples gets all the relationship tuples in the openFGA store
func (c *Client) getAllTuples(ctx context.Context) ([]openfga.Tuple, error) {
	var tuples []openfga.Tuple

	opts := ofgaclient.ClientReadOptions{
		PageSize: openfga.PtrInt32(defaultPageSize),
	}

	notComplete := true

	// paginate through all the tuples
	for notComplete {
		resp, err := c.Ofga.Read(ctx).Options(opts).Execute()
		if err != nil {
			log.Error().Err(err).Msg("error getting relationship tuples")

			return nil, err
		}

		tuples = append(tuples, resp.GetTuples()...)

		if resp.ContinuationToken == "" {
			notComplete = false
		} else {
			opts.ContinuationToken = &resp.ContinuationToken
		}
	}

	return tuples, nil
}

// DeleteAllObjectRelations deletes all the relationship tuples for a given object
func (c *Client) DeleteAllObjectRelations(ctx context.Context, object string, excludeRelations []string) error {
	// validate object is not empty
	if object == "" {
		return ErrMissingObjectOnDeletion
	}

	match := entityRegex.FindStringSubmatch(object)
	if match == nil {
		return newInvalidEntityError(object)
	}

	tuples, err := c.getAllTuples(ctx)
	if err != nil {
		return err
	}

	var tuplesToDelete []openfga.TupleKeyWithoutCondition

	// check all the tuples for the object
	for _, t := range tuples {
		if t.Key.Object == object {
			// if the relation is in the exclude list, skip it
			if slices.Contains(excludeRelations, t.Key.Relation) {
				continue
			}

			k := openfga.TupleKeyWithoutCondition{
				User:     t.Key.User,
				Relation: t.Key.Relation,
				Object:   t.Key.Object,
			}
			tuplesToDelete = append(tuplesToDelete, k)
		}
	}

	// delete the tuples in batches of 10, the max supported by the OpenFGA transactional write api
	for i := 0; i < len(tuplesToDelete); i += maxWrites {
		end := i + maxWrites
		if end > len(tuplesToDelete) {
			end = len(tuplesToDelete)
		}

		allTuples := tuplesToDelete[i:end]

		if _, err := c.deleteRelationshipTuple(ctx, allTuples); err != nil {
			return err
		}
	}

	return nil
}

// GetTupleKey creates a Tuple key with the provided subject, object, and role
func GetTupleKey(req TupleRequest) TupleKey {
	sub := Entity{
		Kind:       Kind(req.SubjectType),
		Identifier: req.SubjectID,
	}

	object := Entity{
		Kind:       Kind(req.ObjectType),
		Identifier: req.ObjectID,
	}

	return TupleKey{
		Subject:  sub,
		Object:   object,
		Relation: Relation(req.Relation),
	}
}
