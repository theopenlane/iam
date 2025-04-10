// Code generated by entfga, DO NOT EDIT.
package ent

import (
	"context"
	"errors"

	"entgo.io/ent/privacy"
	"github.com/99designs/gqlgen/graphql"
	"github.com/rs/zerolog/log"

	"github.com/theopenlane/iam/auth"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/orgmembership"
	"github.com/theopenlane/iam/fgax"
)

var (
	ErrPermissionDenied = errors.New("you are not authorized to perform this action")
)

func (q *OrgMembershipQuery) CheckAccess(ctx context.Context) error {
	gCtx := graphql.GetFieldContext(ctx)

	if gCtx == nil {
		// Skip to the next privacy rule (equivalent to return nil)
		// if this is not a graphql request
		return privacy.Skipf("not a graphql request, no context to check")
	}

	subjectID, err := auth.GetSubjectIDFromContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("unable to get user id from context")

		return err
	}

	var objectID string

	// check id from graphql arg context
	// when all objects are requested, the interceptor will check object access
	// check the where input first
	whereArg := gCtx.Args["where"]
	if whereArg != nil {
		where, ok := whereArg.(*OrgMembershipWhereInput)
		if ok && where != nil && where.OrganizationID != nil {
			objectID = *where.OrganizationID
		}
	}

	// if that doesn't work, check for the id in the request args
	if objectID == "" {
		objectID, _ = gCtx.Args["organizationid"].(string)
	}

	// if we still don't have an object id, run the query and grab the object ID
	// from the result
	// this happens on join tables where we have the join ID (for updates and deletes)
	// and not the actual object id
	if objectID == "" {
		// allow this query to run
		reqCtx := privacy.DecisionContext(ctx, privacy.Allow)

		ob, err := q.Clone().Only(reqCtx)
		if err != nil {
			return privacy.Allowf("nil request, bypassing auth check")
		}

		objectID = ob.OrganizationID
	}

	// request is for a list objects, will get filtered in interceptors
	if objectID == "" {
		return privacy.Allowf("nil request, bypassing auth check")
	}

	// check if the user has access to the object requested
	ac := fgax.AccessCheck{
		Relation:    fgax.CanView,
		ObjectType:  "organization",
		SubjectType: auth.GetAuthzSubjectType(ctx),
		SubjectID:   subjectID,
		ObjectID:    objectID,
	}

	access, err := q.Authz.CheckAccess(ctx, ac)
	if err == nil && access {
		return privacy.Allow
	}

	// Skip to the next privacy rule (equivalent to return nil)
	return privacy.Skip
}

func (m *OrgMembershipMutation) CheckAccessForEdit(ctx context.Context) error {
	var objectID string

	gCtx := graphql.GetFieldContext(ctx)
	if gCtx == nil {
		// Skip to the next privacy rule (equivalent to return nil)
		// if this is not a graphql request
		return privacy.Skipf("not a graphql request, no context to check")
	}

	// get the input from the context
	gInput := gCtx.Args["input"]

	// check if the input is a CreateOrgMembershipInput
	input, ok := gInput.(CreateOrgMembershipInput)
	if ok {
		objectID = input.OrganizationID

	}

	// check the id from the args
	if objectID == "" {
		objectID, _ = gCtx.Args["organizationid"].(string)
	}
	// if this is still empty, we need to query the object to get the object id
	// this happens on join tables where we have the join ID (for updates and deletes)
	if objectID == "" {
		id, ok := gCtx.Args["id"].(string)
		if ok {
			// allow this query to run
			reqCtx := privacy.DecisionContext(ctx, privacy.Allow)
			ob, err := m.Client().OrgMembership.Query().Where(orgmembership.ID(id)).Only(reqCtx)
			if err != nil {
				return privacy.Skipf("nil request, skipping auth check")
			}
			objectID = ob.OrganizationID
		}
	}

	// request is for a list objects, will get filtered in interceptors
	if objectID == "" {
		return privacy.Allowf("nil request, bypassing auth check")
	}

	subjectID, err := auth.GetSubjectIDFromContext(ctx)
	if err != nil {
		return err
	}

	ac := fgax.AccessCheck{
		Relation:    fgax.CanEdit,
		ObjectType:  "organization",
		ObjectID:    objectID,
		SubjectType: auth.GetAuthzSubjectType(ctx),
		SubjectID:   subjectID,
	}

	log.Debug().Interface("access_check", ac).Msg("checking relationship tuples")

	access, err := m.Authz.CheckAccess(ctx, ac)
	if err == nil && access {
		return privacy.Allow
	}

	log.Error().Interface("access_check", ac).Bool("access_result", access).Msg("access denied")

	// return error if the action is not allowed
	return ErrPermissionDenied
}

func (m *OrgMembershipMutation) CheckAccessForDelete(ctx context.Context) error {
	gCtx := graphql.GetFieldContext(ctx)
	if gCtx == nil {
		// Skip to the next privacy rule (equivalent to return nil)
		// if this is not a graphql request
		return privacy.Skipf("not a graphql request, no context to check")
	}

	objectID, ok := gCtx.Args["id"].(string)
	if !ok {
		log.Info().Msg("no id found in args, skipping auth check, will be filtered in hooks")

		return privacy.Allowf("nil request, bypassing auth check")
	}

	subjectID, err := auth.GetSubjectIDFromContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("unable to get user id from context")

		return err
	}

	ac := fgax.AccessCheck{
		Relation:    fgax.CanDelete,
		ObjectType:  "organization",
		ObjectID:    objectID,
		SubjectType: auth.GetAuthzSubjectType(ctx),
		SubjectID:   subjectID,
	}

	log.Debug().Interface("access_check", ac).Msg("checking relationship tuples")

	access, err := m.Authz.CheckAccess(ctx, ac)
	if err == nil && access {
		return privacy.Allow
	}

	log.Error().Interface("access_check", ac).Bool("access_result", access).Msg("access denied")

	// return error if the action is not allowed
	return ErrPermissionDenied
}

func (q *OrganizationQuery) CheckAccess(ctx context.Context) error {
	gCtx := graphql.GetFieldContext(ctx)

	if gCtx == nil {
		// Skip to the next privacy rule (equivalent to return nil)
		// if this is not a graphql request
		return privacy.Skipf("not a graphql request, no context to check")
	}

	subjectID, err := auth.GetSubjectIDFromContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("unable to get user id from context")

		return err
	}

	var objectID string

	// check id from graphql arg context
	// when all objects are requested, the interceptor will check object access
	// check the where input first
	whereArg := gCtx.Args["where"]
	if whereArg != nil {
		where, ok := whereArg.(*OrganizationWhereInput)
		if ok && where != nil && where.ID != nil {
			objectID = *where.ID
		}
	}

	// if that doesn't work, check for the id in the request args
	if objectID == "" {
		objectID, _ = gCtx.Args["id"].(string)
	}

	// request is for a list objects, will get filtered in interceptors
	if objectID == "" {
		return privacy.Allowf("nil request, bypassing auth check")
	}

	// check if the user has access to the object requested
	ac := fgax.AccessCheck{
		Relation:    fgax.CanView,
		ObjectType:  "organization",
		SubjectType: auth.GetAuthzSubjectType(ctx),
		SubjectID:   subjectID,
		ObjectID:    objectID,
	}

	access, err := q.Authz.CheckAccess(ctx, ac)
	if err == nil && access {
		return privacy.Allow
	}

	// Skip to the next privacy rule (equivalent to return nil)
	return privacy.Skip
}

func (m *OrganizationMutation) CheckAccessForEdit(ctx context.Context) error {
	var objectID string

	gCtx := graphql.GetFieldContext(ctx)
	if gCtx == nil {
		// Skip to the next privacy rule (equivalent to return nil)
		// if this is not a graphql request
		return privacy.Skipf("not a graphql request, no context to check")
	}

	// check the id from the args
	if objectID == "" {
		objectID, _ = gCtx.Args["id"].(string)
	}

	// request is for a list objects, will get filtered in interceptors
	if objectID == "" {
		return privacy.Allowf("nil request, bypassing auth check")
	}

	subjectID, err := auth.GetSubjectIDFromContext(ctx)
	if err != nil {
		return err
	}

	ac := fgax.AccessCheck{
		Relation:    fgax.CanEdit,
		ObjectType:  "organization",
		ObjectID:    objectID,
		SubjectType: auth.GetAuthzSubjectType(ctx),
		SubjectID:   subjectID,
	}

	log.Debug().Interface("access_check", ac).Msg("checking relationship tuples")

	access, err := m.Authz.CheckAccess(ctx, ac)
	if err == nil && access {
		return privacy.Allow
	}

	log.Error().Interface("access_check", ac).Bool("access_result", access).Msg("access denied")

	// return error if the action is not allowed
	return ErrPermissionDenied
}

func (m *OrganizationMutation) CheckAccessForDelete(ctx context.Context) error {
	gCtx := graphql.GetFieldContext(ctx)
	if gCtx == nil {
		// Skip to the next privacy rule (equivalent to return nil)
		// if this is not a graphql request
		return privacy.Skipf("not a graphql request, no context to check")
	}

	objectID, ok := gCtx.Args["id"].(string)
	if !ok {
		log.Info().Msg("no id found in args, skipping auth check, will be filtered in hooks")

		return privacy.Allowf("nil request, bypassing auth check")
	}

	subjectID, err := auth.GetSubjectIDFromContext(ctx)
	if err != nil {
		log.Error().Err(err).Msg("unable to get user id from context")

		return err
	}

	ac := fgax.AccessCheck{
		Relation:    fgax.CanDelete,
		ObjectType:  "organization",
		ObjectID:    objectID,
		SubjectType: auth.GetAuthzSubjectType(ctx),
		SubjectID:   subjectID,
	}

	log.Debug().Interface("access_check", ac).Msg("checking relationship tuples")

	access, err := m.Authz.CheckAccess(ctx, ac)
	if err == nil && access {
		return privacy.Allow
	}

	log.Error().Interface("access_check", ac).Bool("access_result", access).Msg("access denied")

	// return error if the action is not allowed
	return ErrPermissionDenied
}
