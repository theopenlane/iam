// Code generated by entfga, DO NOT EDIT.

// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/theopenlane/iam/entfga"
	"github.com/theopenlane/iam/fgax"
)

func (m *OrgMembershipMutation) CreateTuplesFromCreate(ctx context.Context) error {

	// Get fields for tuple creation
	userID, _ := m.UserID()
	objectID, _ := m.OrganizationID()
	role, _ := m.Role()

	// get tuple key
	req := fgax.TupleRequest{
		SubjectID:   userID,
		SubjectType: "user",
		ObjectID:    objectID,
		ObjectType:  "organization",
		Relation:    role.String(),
	}

	tuple := fgax.GetTupleKey(req)

	if _, err := m.Authz.WriteTupleKeys(ctx, []fgax.TupleKey{tuple}, nil); err != nil {
		log.Error().Err(err).Interface("writes", tuple).Msg("failed to create relationship tuple")

		return err
	}

	log.Debug().Interface("tuple_request", tuple).Msg("created relationship tuple")

	return nil
}

func (m *OrgMembershipMutation) CreateTuplesFromUpdate(ctx context.Context) error {

	// get ids that will be updated
	ids, err := m.IDs(ctx)
	if err != nil {
		return err
	}

	var (
		writes  []fgax.TupleKey
		deletes []fgax.TupleKey
	)

	oldRole, err := m.OldRole(ctx)
	if err != nil {
		return err
	}

	newRole, exists := m.Role()
	if !exists {
		return entfga.ErrMissingRole
	}

	if oldRole == newRole {
		log.Debug().
			Str("old_role", oldRole.String()).
			Str("new_role", newRole.String()).
			Msg("nothing to update, roles are the same")

		return nil
	}

	// User the IDs of the memberships and delete all related tuples
	for _, id := range ids {
		member, err := m.Client().OrgMembership.Get(ctx, id)
		if err != nil {
			return err
		}

		req := fgax.TupleRequest{
			SubjectID:   member.UserID,
			SubjectType: "user",
			ObjectID:    member.OrganizationID,
			ObjectType:  "organization",
			Relation:    oldRole.String(),
		}

		d := fgax.GetTupleKey(req)
		deletes = append(deletes, d)

		req.Relation = newRole.String()

		w := fgax.GetTupleKey(req)
		writes = append(writes, w)

		if len(writes) == 0 && len(deletes) == 0 {
			log.Debug().Msg("no relationships to create or delete")

			return nil
		}

		if _, err := m.Authz.WriteTupleKeys(ctx, writes, deletes); err != nil {
			log.Error().Err(err).Interface("writes", writes).Interface("deletes", deletes).Msg("failed to update relationship tuple")

			return err
		}
	}

	return nil
}

func (m *OrgMembershipMutation) CreateTuplesFromDelete(ctx context.Context) error {

	// get ids that will be deleted
	ids, err := m.IDs(ctx)
	if err != nil {
		return err
	}

	tuples := []fgax.TupleKey{}

	// User the IDs of the memberships and delete all related tuples
	for _, id := range ids {
		// this wont work with soft deletes
		members, err := m.Client().OrgMembership.Get(ctx, id)
		if err != nil {
			return err
		}

		req := fgax.TupleRequest{
			SubjectID:   members.UserID,
			SubjectType: "user",
			ObjectID:    members.OrganizationID,
			ObjectType:  "organization",
			Relation:    members.Role.String(),
		}

		t := fgax.GetTupleKey(req)
		tuples = append(tuples, t)
	}

	if len(tuples) > 0 {
		if _, err := m.Authz.WriteTupleKeys(ctx, nil, tuples); err != nil {
			log.Error().Err(err).Interface("deletes", tuples).Msg("failed to delete relationship tuple")

			return err
		}

		log.Debug().Msg("deleted relationship tuples")
	}

	return nil
}
