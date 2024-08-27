// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/organization"
	"github.com/theopenlane/iam/entfga/_examples/basic/ent/orgmembership"
)

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (om *OrgMembershipQuery) CollectFields(ctx context.Context, satisfies ...string) (*OrgMembershipQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return om, nil
	}
	if err := om.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return om, nil
}

func (om *OrgMembershipQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(orgmembership.Columns))
		selectedFields = []string{orgmembership.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {

		case "organization":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = (&OrganizationClient{config: om.config}).Query()
			)
			if err := query.collectField(ctx, oneNode, opCtx, field, path, mayAddCondition(satisfies, organizationImplementors)...); err != nil {
				return err
			}
			om.withOrganization = query
			if _, ok := fieldSeen[orgmembership.FieldOrganizationID]; !ok {
				selectedFields = append(selectedFields, orgmembership.FieldOrganizationID)
				fieldSeen[orgmembership.FieldOrganizationID] = struct{}{}
			}
		case "role":
			if _, ok := fieldSeen[orgmembership.FieldRole]; !ok {
				selectedFields = append(selectedFields, orgmembership.FieldRole)
				fieldSeen[orgmembership.FieldRole] = struct{}{}
			}
		case "organizationID":
			if _, ok := fieldSeen[orgmembership.FieldOrganizationID]; !ok {
				selectedFields = append(selectedFields, orgmembership.FieldOrganizationID)
				fieldSeen[orgmembership.FieldOrganizationID] = struct{}{}
			}
		case "userID":
			if _, ok := fieldSeen[orgmembership.FieldUserID]; !ok {
				selectedFields = append(selectedFields, orgmembership.FieldUserID)
				fieldSeen[orgmembership.FieldUserID] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		om.Select(selectedFields...)
	}
	return nil
}

type orgmembershipPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OrgMembershipPaginateOption
}

func newOrgMembershipPaginateArgs(rv map[string]any) *orgmembershipPaginateArgs {
	args := &orgmembershipPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*OrgMembershipWhereInput); ok {
		args.opts = append(args.opts, WithOrgMembershipFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (o *OrganizationQuery) CollectFields(ctx context.Context, satisfies ...string) (*OrganizationQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return o, nil
	}
	if err := o.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return o, nil
}

func (o *OrganizationQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(organization.Columns))
		selectedFields = []string{organization.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "name":
			if _, ok := fieldSeen[organization.FieldName]; !ok {
				selectedFields = append(selectedFields, organization.FieldName)
				fieldSeen[organization.FieldName] = struct{}{}
			}
		case "description":
			if _, ok := fieldSeen[organization.FieldDescription]; !ok {
				selectedFields = append(selectedFields, organization.FieldDescription)
				fieldSeen[organization.FieldDescription] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		o.Select(selectedFields...)
	}
	return nil
}

type organizationPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OrganizationPaginateOption
}

func newOrganizationPaginateArgs(rv map[string]any) *organizationPaginateArgs {
	args := &organizationPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*OrganizationWhereInput); ok {
		args.opts = append(args.opts, WithOrganizationFilter(v.Filter))
	}
	return args
}

const (
	afterField     = "after"
	firstField     = "first"
	beforeField    = "before"
	lastField      = "last"
	orderByField   = "orderBy"
	directionField = "direction"
	fieldField     = "field"
	whereField     = "where"
)

func fieldArgs(ctx context.Context, whereInput any, path ...string) map[string]any {
	field := collectedField(ctx, path...)
	if field == nil || field.Arguments == nil {
		return nil
	}
	oc := graphql.GetOperationContext(ctx)
	args := field.ArgumentMap(oc.Variables)
	return unmarshalArgs(ctx, whereInput, args)
}

// unmarshalArgs allows extracting the field arguments from their raw representation.
func unmarshalArgs(ctx context.Context, whereInput any, args map[string]any) map[string]any {
	for _, k := range []string{firstField, lastField} {
		v, ok := args[k]
		if !ok {
			continue
		}
		i, err := graphql.UnmarshalInt(v)
		if err == nil {
			args[k] = &i
		}
	}
	for _, k := range []string{beforeField, afterField} {
		v, ok := args[k]
		if !ok {
			continue
		}
		c := &Cursor{}
		if c.UnmarshalGQL(v) == nil {
			args[k] = c
		}
	}
	if v, ok := args[whereField]; ok && whereInput != nil {
		if err := graphql.UnmarshalInputFromContext(ctx, v, whereInput); err == nil {
			args[whereField] = whereInput
		}
	}

	return args
}

// mayAddCondition appends another type condition to the satisfies list
// if it does not exist in the list.
func mayAddCondition(satisfies []string, typeCond []string) []string {
Cond:
	for _, c := range typeCond {
		for _, s := range satisfies {
			if c == s {
				continue Cond
			}
		}
		satisfies = append(satisfies, c)
	}
	return satisfies
}
