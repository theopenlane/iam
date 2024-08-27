package fgax

import (
	"context"
	"fmt"

	fgasdk "github.com/openfga/go-sdk"
	ofgaclient "github.com/openfga/go-sdk/client"
)

// ListRequest is the fields needed to list objects or users
type ListRequest struct {
	// ObjectID is the identifier of the object that the subject is related to, required on ListUsers
	ObjectID string
	// ObjectType is the type of object that the subject is related to, required on ListUsers
	ObjectType string
	// SubjectID is the identifier of the subject that is related to the object, required on ListObjects
	SubjectID string
	// SubjectType is the type of subject that is related to the object, required on ListObjects
	SubjectType string
	// Relation is the relationship between the subject and object
	Relation string
}

// ListObjectsRequest creates the ClientListObjectsRequest and queries the FGA store for all objects with the user+relation
func (c *Client) ListObjectsRequest(ctx context.Context, req ListRequest) (*ofgaclient.ClientListObjectsResponse, error) {
	// valid and set defaults
	if err := req.validateListObjectsInput(); err != nil {
		return nil, err
	}

	sub := Entity{
		Kind:       Kind(req.SubjectType),
		Identifier: req.SubjectID,
	}

	listReq := ofgaclient.ClientListObjectsRequest{
		User:     sub.String(),
		Relation: req.Relation,
		Type:     req.ObjectType,
	}

	c.Logger.Debugw("listing objects", "relation", req.SubjectType, sub.String(), req.Relation, "type", req.ObjectType)

	return c.listObjects(ctx, listReq)
}

// ListUserRequest creates the ClientListUserRequest and queries the FGA store for all users with the object+relation
func (c *Client) ListUserRequest(ctx context.Context, req ListRequest) (*ofgaclient.ClientListUsersResponse, error) {
	if err := req.validateListUsersInput(); err != nil {
		return nil, err
	}

	// create the fga object
	obj := fgasdk.FgaObject{
		Type: req.ObjectType,
		Id:   req.ObjectID,
	}

	// compose the list request
	listReq := ofgaclient.ClientListUsersRequest{
		Object:      obj,
		Relation:    req.Relation,
		UserFilters: []fgasdk.UserTypeFilter{{Type: req.SubjectType}},
	}

	c.Logger.Debugw("listing users", "relation", req.Relation, "object", obj.Id, "type", obj.Type)

	return c.listUsers(ctx, listReq)
}

// listObjects checks the openFGA store for all objects associated with a user+relation
func (c *Client) listObjects(ctx context.Context, req ofgaclient.ClientListObjectsRequest) (*ofgaclient.ClientListObjectsResponse, error) {
	list, err := c.Ofga.ListObjects(ctx).Body(req).Execute()
	if err != nil {
		c.Logger.Errorw("error listing objects",
			"user", req.User,
			"relation", req.Relation,
			"type", req.Type,
			"error", err.Error())

		return nil, err
	}

	return list, nil
}

// listUsers checks the openFGA store for all users associated with a object+relation
func (c *Client) listUsers(ctx context.Context, req ofgaclient.ClientListUsersRequest) (*ofgaclient.ClientListUsersResponse, error) {
	list, err := c.Ofga.ListUsers(ctx).Body(req).Execute()
	if err != nil {
		c.Logger.Errorw("error listing users",
			"object", req.Object.Id,
			"type", req.Object.Type,
			"relation", req.Relation,
			"error", err.Error())

		return nil, err
	}

	return list, nil
}

func (r *ListRequest) setListRequestDefaults() {
	// default to user type
	if r.SubjectType == "" {
		r.SubjectType = defaultSubject
	}

	// default to view permissions
	if r.Relation == "" {
		r.Relation = CanView
	}
}

func (r *ListRequest) validateListObjectsInput() error {
	if r.SubjectID == "" {
		return fmt.Errorf("%w, subject_id", ErrMissingRequiredField)
	}

	r.setListRequestDefaults()

	return nil
}

func (r *ListRequest) validateListUsersInput() error {
	if r.ObjectID == "" {
		return fmt.Errorf("%w, object_id", ErrMissingRequiredField)
	}

	r.setListRequestDefaults()

	return nil
}

// ListContains checks the results of an fga ListObjects and parses the entities
// to get the identifier to compare to another identifier based on entity type
func ListContains(entityType string, l []string, i string) bool {
	for _, o := range l {
		e, _ := ParseEntity(o)

		// make sure its the correct entity type
		if e.Kind.String() != entityType {
			continue
		}

		if i == e.Identifier {
			return true
		}
	}

	return false
}

// GetEntityIDs returns a list of identifiers from a list of objects
func GetEntityIDs(l *ofgaclient.ClientListObjectsResponse) ([]string, error) {
	ids := make([]string, 0, len(l.Objects))

	for _, o := range l.Objects {
		e, err := ParseEntity(o)
		if err != nil {
			return nil, err
		}

		ids = append(ids, e.Identifier)
	}

	return ids, nil
}
