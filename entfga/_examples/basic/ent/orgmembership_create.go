// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/enums"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/organization"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/orgmembership"
)

// OrgMembershipCreate is the builder for creating a OrgMembership entity.
type OrgMembershipCreate struct {
	config
	mutation *OrgMembershipMutation
	hooks    []Hook
}

// SetRole sets the "role" field.
func (omc *OrgMembershipCreate) SetRole(e enums.Role) *OrgMembershipCreate {
	omc.mutation.SetRole(e)
	return omc
}

// SetNillableRole sets the "role" field if the given value is not nil.
func (omc *OrgMembershipCreate) SetNillableRole(e *enums.Role) *OrgMembershipCreate {
	if e != nil {
		omc.SetRole(*e)
	}
	return omc
}

// SetOrganizationID sets the "organization_id" field.
func (omc *OrgMembershipCreate) SetOrganizationID(s string) *OrgMembershipCreate {
	omc.mutation.SetOrganizationID(s)
	return omc
}

// SetUserID sets the "user_id" field.
func (omc *OrgMembershipCreate) SetUserID(s string) *OrgMembershipCreate {
	omc.mutation.SetUserID(s)
	return omc
}

// SetID sets the "id" field.
func (omc *OrgMembershipCreate) SetID(s string) *OrgMembershipCreate {
	omc.mutation.SetID(s)
	return omc
}

// SetOrganization sets the "organization" edge to the Organization entity.
func (omc *OrgMembershipCreate) SetOrganization(o *Organization) *OrgMembershipCreate {
	return omc.SetOrganizationID(o.ID)
}

// Mutation returns the OrgMembershipMutation object of the builder.
func (omc *OrgMembershipCreate) Mutation() *OrgMembershipMutation {
	return omc.mutation
}

// Save creates the OrgMembership in the database.
func (omc *OrgMembershipCreate) Save(ctx context.Context) (*OrgMembership, error) {
	if err := omc.defaults(); err != nil {
		return nil, err
	}
	return withHooks(ctx, omc.sqlSave, omc.mutation, omc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (omc *OrgMembershipCreate) SaveX(ctx context.Context) *OrgMembership {
	v, err := omc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (omc *OrgMembershipCreate) Exec(ctx context.Context) error {
	_, err := omc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (omc *OrgMembershipCreate) ExecX(ctx context.Context) {
	if err := omc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (omc *OrgMembershipCreate) defaults() error {
	if _, ok := omc.mutation.Role(); !ok {
		v := orgmembership.DefaultRole
		omc.mutation.SetRole(v)
	}
	return nil
}

// check runs all checks and user-defined validators on the builder.
func (omc *OrgMembershipCreate) check() error {
	if _, ok := omc.mutation.Role(); !ok {
		return &ValidationError{Name: "role", err: errors.New(`ent: missing required field "OrgMembership.role"`)}
	}
	if v, ok := omc.mutation.Role(); ok {
		if err := orgmembership.RoleValidator(v); err != nil {
			return &ValidationError{Name: "role", err: fmt.Errorf(`ent: validator failed for field "OrgMembership.role": %w`, err)}
		}
	}
	if _, ok := omc.mutation.OrganizationID(); !ok {
		return &ValidationError{Name: "organization_id", err: errors.New(`ent: missing required field "OrgMembership.organization_id"`)}
	}
	if _, ok := omc.mutation.UserID(); !ok {
		return &ValidationError{Name: "user_id", err: errors.New(`ent: missing required field "OrgMembership.user_id"`)}
	}
	if _, ok := omc.mutation.OrganizationID(); !ok {
		return &ValidationError{Name: "organization", err: errors.New(`ent: missing required edge "OrgMembership.organization"`)}
	}
	return nil
}

func (omc *OrgMembershipCreate) sqlSave(ctx context.Context) (*OrgMembership, error) {
	if err := omc.check(); err != nil {
		return nil, err
	}
	_node, _spec := omc.createSpec()
	if err := sqlgraph.CreateNode(ctx, omc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(string); ok {
			_node.ID = id
		} else {
			return nil, fmt.Errorf("unexpected OrgMembership.ID type: %T", _spec.ID.Value)
		}
	}
	omc.mutation.id = &_node.ID
	omc.mutation.done = true
	return _node, nil
}

func (omc *OrgMembershipCreate) createSpec() (*OrgMembership, *sqlgraph.CreateSpec) {
	var (
		_node = &OrgMembership{config: omc.config}
		_spec = sqlgraph.NewCreateSpec(orgmembership.Table, sqlgraph.NewFieldSpec(orgmembership.FieldID, field.TypeString))
	)
	if id, ok := omc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = id
	}
	if value, ok := omc.mutation.Role(); ok {
		_spec.SetField(orgmembership.FieldRole, field.TypeEnum, value)
		_node.Role = value
	}
	if value, ok := omc.mutation.UserID(); ok {
		_spec.SetField(orgmembership.FieldUserID, field.TypeString, value)
		_node.UserID = value
	}
	if nodes := omc.mutation.OrganizationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   orgmembership.OrganizationTable,
			Columns: []string{orgmembership.OrganizationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(organization.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.OrganizationID = nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OrgMembershipCreateBulk is the builder for creating many OrgMembership entities in bulk.
type OrgMembershipCreateBulk struct {
	config
	err      error
	builders []*OrgMembershipCreate
}

// Save creates the OrgMembership entities in the database.
func (omcb *OrgMembershipCreateBulk) Save(ctx context.Context) ([]*OrgMembership, error) {
	if omcb.err != nil {
		return nil, omcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(omcb.builders))
	nodes := make([]*OrgMembership, len(omcb.builders))
	mutators := make([]Mutator, len(omcb.builders))
	for i := range omcb.builders {
		func(i int, root context.Context) {
			builder := omcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*OrgMembershipMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, omcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, omcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, omcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (omcb *OrgMembershipCreateBulk) SaveX(ctx context.Context) []*OrgMembership {
	v, err := omcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (omcb *OrgMembershipCreateBulk) Exec(ctx context.Context) error {
	_, err := omcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (omcb *OrgMembershipCreateBulk) ExecX(ctx context.Context) {
	if err := omcb.Exec(ctx); err != nil {
		panic(err)
	}
}
