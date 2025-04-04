package fgax

import (
	"context"

	ofgaclient "github.com/openfga/go-sdk/client"
	"github.com/rs/zerolog/log"
	"github.com/theopenlane/utils/ulids"
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
	// Context is the context of the request used for conditional relationships
	Context *map[string]any
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
	// Context is the context of the request used for conditional relationships
	Context *map[string]any
}

// BatchCheckObjectAccess checks if the user has access to the list of objects with the given relation
// It returns a list of objects (type:id, e.g. organization:01JPWNAGM9S61G57DS364MFKGX) that the user has access to
func (c *Client) BatchCheckObjectAccess(ctx context.Context, checks []AccessCheck) ([]string, error) {
	if len(checks) == 0 {
		return []string{}, nil
	}

	checkRequests := []ofgaclient.ClientBatchCheckItem{}
	for _, ac := range checks {
		check, err := toBatchCheckItem(ac)
		if err != nil {
			return nil, err
		}

		checkRequests = append(checkRequests, *check)
	}

	results, err := c.Ofga.BatchCheck(ctx).Body(
		ofgaclient.ClientBatchCheckRequest{
			Checks: checkRequests,
		}).Execute()
	if err != nil || results == nil {
		return nil, err
	}

	allowedObjects := []string{}

	for id, result := range *results.Result {
		if result.HasError() {
			err := result.GetError()
			log.Error().Str("error", err.GetMessage()).Interface("accessCheck", id).Msg("error checking access")

			continue
		}

		if result.GetAllowed() {
			// get id from the correlation ID
			check, ok := getCheckItemByCorrelationID(id, checkRequests)
			if !ok {
				log.Error().Str("correlationID", id).Msg("correlation ID not found in checks")

				continue
			}

			obj, err := ParseEntity(check.Object)
			if err != nil {
				log.Error().Err(err).Str("object", check.Object).Msg("error parsing object")

				return nil, err
			}

			allowedObjects = append(allowedObjects, obj.Identifier)
		}

	}

	return allowedObjects, nil
}

// BatchGetAllowedIDs checks if the user has access to the list of objects with the given relation
// and returns a list of objects; it assumes the checks are for all the same object types (or the user knows the object type from the id)
func (c *Client) BatchGetAllowedIDs(ctx context.Context, checks []AccessCheck) ([]string, error) {
	res, err := c.BatchCheckObjectAccess(ctx, checks)
	if err != nil {
		return nil, err
	}

	allowedObjectIDs := []string{}

	for _, r := range res {
		entity, err := ParseEntity(r)
		if err != nil {
			return nil, err
		}

		allowedObjectIDs = append(allowedObjectIDs, entity.Identifier)
	}

	return allowedObjectIDs, nil
}

// CheckAccess checks if the user has access to the object type with the given relation
func (c *Client) CheckAccess(ctx context.Context, ac AccessCheck) (bool, error) {
	checkReq, err := toCheckRequest(ac)
	if err != nil {
		return false, err
	}

	return c.checkTuple(ctx, *checkReq)
}

func toBatchCheckItem(ac AccessCheck) (*ofgaclient.ClientBatchCheckItem, error) {
	if err := validateAccessCheck(ac); err != nil {
		log.Error().Err(err).Interface("accessCheck", ac).Msg("invalid access check")

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

	return &ofgaclient.ClientBatchCheckItem{
		User:          sub.String(),
		Relation:      ac.Relation,
		Object:        obj.String(),
		Context:       ac.Context,
		CorrelationId: ulids.New().String(), // generate a new correlation ID for each check
	}, nil
}

// toCheckRequest converts an AccessCheck to a ClientCheckRequest
func toCheckRequest(ac AccessCheck) (*ofgaclient.ClientCheckRequest, error) {
	if err := validateAccessCheck(ac); err != nil {
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

	return &ofgaclient.ClientCheckRequest{
		User:     sub.String(),
		Relation: ac.Relation,
		Object:   obj.String(),
		Context:  ac.Context,
	}, nil
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

	checks := []ofgaclient.ClientBatchCheckItem{}

	for _, rel := range ac.Relations {
		check := ofgaclient.ClientBatchCheckItem{
			User:          sub.String(),
			Relation:      rel,
			Object:        obj.String(),
			Context:       ac.Context,
			CorrelationId: ulids.New().String(), // generate a new correlation ID for each check
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
		log.Error().Err(err).Interface("tuple", check).Msg("error checking tuple")

		return false, err
	}

	return *data.Allowed, nil
}

// batchCheckTuples checks the openFGA store for provided relationship tuples and returns the allowed relations
func (c *Client) batchCheckTuples(ctx context.Context, checks []ofgaclient.ClientBatchCheckItem) ([]string, error) {
	res, err := c.Ofga.BatchCheck(ctx).Body(
		ofgaclient.ClientBatchCheckRequest{
			Checks: checks,
		}).Execute()
	if err != nil || res == nil {
		return nil, err
	}

	relations := []string{}

	for i, r := range *res.Result {
		if r.GetAllowed() {
			// get id from the correlation ID
			check, ok := getCheckItemByCorrelationID(i, checks)
			if !ok {
				log.Error().Str("correlationID", i).Msg("correlation ID not found in checks")

				continue
			}

			relations = append(relations, check.Relation)
		}
	}

	return relations, nil
}

// getCheckItemByCorrelationID retrieves the check by correlation ID from the list of checks
func getCheckItemByCorrelationID(correlationID string, checks []ofgaclient.ClientBatchCheckItem) (ofgaclient.ClientBatchCheckItem, bool) {
	for _, check := range checks {
		if check.CorrelationId == correlationID {
			return check, true
		}
	}

	return ofgaclient.ClientBatchCheckItem{}, false
}

// CheckSystemAdminRole checks if the user has system admin access
func (c *Client) CheckSystemAdminRole(ctx context.Context, userID string) (bool, error) {
	ac := AccessCheck{
		ObjectType:  roleObject,
		ObjectID:    SystemAdminRelation,
		Relation:    AssigneeRelation,
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
