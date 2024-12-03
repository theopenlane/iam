package entfga

import (
	"context"

	"entgo.io/ent"
	"entgo.io/ent/privacy"
)

// CheckReadAccess checks if the requestor has access to read the object
// for the provided Query type
func CheckReadAccess[T Query]() privacy.QueryRule {
	return QueryRuleFunc(func(ctx context.Context, q ent.Query) error {
		return q.(T).CheckAccess(ctx)
	})
}

// CheckEditAccess checks if the requestor has access to edit the object
// for the provided Mutation type, this can be used for update and delete operations
// if specific delete access is required, use CheckEditAndDeleteAccess instead
func CheckEditAccess[T Mutation]() privacy.MutationRule {
	return privacy.MutationRuleFunc(func(ctx context.Context, m ent.Mutation) error {
		return m.(T).CheckAccessForEdit(ctx)
	})
}

// CheckDeleteAccess checks if the requestor has access to delete the object
// for the provided Mutation type
func CheckDeleteAccess[T Mutation]() privacy.MutationRule {
	return privacy.MutationRuleFunc(func(ctx context.Context, m ent.Mutation) error {
		return m.(T).CheckAccessForDelete(ctx)
	})
}

// CheckEditAndDeleteAccess checks if the requestor has access to edit the object
// on update operations and access to delete the object on delete operations
// for the provided Mutation type
func CheckEditAndDeleteAccess[T Mutation]() privacy.MutationRule {
	editRule := privacy.OnMutationOperation(
		CheckEditAccess[T](),
		ent.OpUpdate|ent.OpUpdateOne,
	)

	deleteRule := privacy.OnMutationOperation(
		CheckDeleteAccess[T](),
		ent.OpDelete|ent.OpDeleteOne,
	)

	return privacy.MutationPolicy{
		editRule,
		deleteRule,
	}
}
