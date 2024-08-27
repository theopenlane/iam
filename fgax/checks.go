package fgax

import (
	"context"

	ofgaclient "github.com/openfga/go-sdk/client"
)

const (
	// subject types
	defaultSubject = userSubject
	userSubject    = "user"
	serviceSubject = "service"

	// object types
	organizationObject = "organization"
	groupObject        = "group"
	roleObject         = "role"
)

// AccessCheck is a struct to hold the information needed to check access
type AccessCheck struct {
	// ObjectType is the type of object being checked
	ObjectType Kind
	// ObjectID is the ID of the object being checked
	ObjectID string
	// SubjectID is the ID of the user making the request
	SubjectID string
	// SubjectType is the type of subject being checked
	SubjectType string
	// Relation is the relationship being checked (e.g. "view", "edit", "delete")
	Relation string
}

// ListAccess is a struct to hold the information needed to list all relations
type ListAccess struct {
	// ObjectType is the type of object being checked
	ObjectType Kind
	// ObjectID is the ID of the object being checked
	ObjectID string
	// SubjectID is the ID of the user making the request
	SubjectID string
	// SubjectType is the type of subject being checked
	SubjectType string
	// Relations is the relationship being checked (e.g. "can_view", "can_edit", "can_delete")
	Relations []string
}

// CheckAccess checks if the user has access to the object type with the given relation
func (c *Client) CheckAccess(ctx context.Context, ac AccessCheck) (bool, error) {
	if err := validateAccessCheck(ac); err != nil {
		return false, err
	}

	if ac.SubjectType == "" {
		ac.SubjectType = defaultSubject
	}

	sub := Entity{
		Kind:       Kind(ac.SubjectType),
		Identifier: ac.SubjectID,
	}

	obj := Entity{
		Kind:       ac.ObjectType,
		Identifier: ac.ObjectID,
	}

	c.Logger.Infow("checking relationship tuples", "relation", ac.Relation, "object", obj.String())

	checkReq := ofgaclient.ClientCheckRequest{
		User:     sub.String(),
		Relation: ac.Relation,
		Object:   obj.String(),
	}

	return c.checkTuple(ctx, checkReq)
}

// ListRelations returns the list of relations the user has with the object
func (c *Client) ListRelations(ctx context.Context, ac ListAccess) ([]string, error) {
	if err := validateListAccess(ac); err != nil {
		return nil, err
	}

	if ac.SubjectType == "" {
		ac.SubjectType = defaultSubject
	}

	sub := Entity{
		Kind:       Kind(ac.SubjectType),
		Identifier: ac.SubjectID,
	}

	obj := Entity{
		Kind:       ac.ObjectType,
		Identifier: ac.ObjectID,
	}

	checks := []ofgaclient.ClientCheckRequest{}

	for _, rel := range ac.Relations {
		check := ofgaclient.ClientCheckRequest{
			User:     sub.String(),
			Relation: rel,
			Object:   obj.String(),
		}

		checks = append(checks, check)
	}

	return c.batchCheckTuples(ctx, checks)
}

// CheckOrgReadAccess checks if the user has read access to the organization
func (c *Client) CheckOrgReadAccess(ctx context.Context, ac AccessCheck) (bool, error) {
	ac.ObjectType = organizationObject
	ac.Relation = CanView // read access

	return c.CheckAccess(ctx, ac)
}

// CheckOrgWriteAccess checks if the user has write access to the organization
func (c *Client) CheckOrgWriteAccess(ctx context.Context, ac AccessCheck) (bool, error) {
	ac.ObjectType = organizationObject
	ac.Relation = CanEdit // write access

	return c.CheckAccess(ctx, ac)
}

// CheckOrgAccess checks if the user has access to the organization with the given relation
func (c *Client) CheckOrgAccess(ctx context.Context, ac AccessCheck) (bool, error) {
	ac.ObjectType = organizationObject

	return c.CheckAccess(ctx, ac)
}

// CheckGroupAccess checks if the user has access to the group with the given relation
func (c *Client) CheckGroupAccess(ctx context.Context, ac AccessCheck) (bool, error) {
	ac.ObjectType = groupObject

	return c.CheckAccess(ctx, ac)
}

// checkTuple checks the openFGA store for provided relationship tuple
func (c *Client) checkTuple(ctx context.Context, check ofgaclient.ClientCheckRequest) (bool, error) {
	data, err := c.Ofga.Check(ctx).Body(check).Execute()
	if err != nil {
		c.Logger.Errorw("error checking tuple", "tuple", check, "error", err.Error())

		return false, err
	}

	return *data.Allowed, nil
}

// batchCheckTuples checks the openFGA store for provided relationship tuples and returns the allowed relations
func (c *Client) batchCheckTuples(ctx context.Context, checks []ofgaclient.ClientCheckRequest) ([]string, error) {
	res, err := c.Ofga.BatchCheck(ctx).Body(checks).Execute()
	if err != nil || res == nil {
		return nil, err
	}

	relations := []string{}

	for _, r := range *res {
		if r.Allowed != nil && *r.Allowed {
			relations = append(relations, r.Request.Relation)
		}
	}

	return relations, nil
}

// CheckSystemAdminRole checks if the user has system admin access
func (c *Client) CheckSystemAdminRole(ctx context.Context, userID string) (bool, error) {
	ac := AccessCheck{
		ObjectType:  roleObject,
		ObjectID:    SystemAdminRole,
		Relation:    RoleRelation,
		SubjectID:   userID,
		SubjectType: userSubject, // admin roles are always user roles, never an API token
	}

	return c.CheckAccess(ctx, ac)
}

// validateAccessCheck checks if the AccessCheck struct is valid
func validateAccessCheck(ac AccessCheck) error {
	if ac.SubjectID == "" {
		return ErrInvalidAccessCheck
	}

	if ac.ObjectType == "" {
		return ErrInvalidAccessCheck
	}

	if ac.ObjectID == "" {
		return ErrInvalidAccessCheck
	}

	if ac.Relation == "" {
		return ErrInvalidAccessCheck
	}

	return nil
}

// validateListAccess checks if the ListAccess struct is valid
func validateListAccess(ac ListAccess) error {
	if ac.SubjectID == "" {
		return ErrInvalidAccessCheck
	}

	if ac.ObjectType == "" {
		return ErrInvalidAccessCheck
	}

	if ac.ObjectID == "" {
		return ErrInvalidAccessCheck
	}

	return nil
}
