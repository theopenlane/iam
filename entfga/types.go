package entfga

import (
	"context"

	"entgo.io/ent"
	"github.com/theopenlane/entx"
)

// DeleteTuplesFirstKey is a key for the context to indicate that the the tuples should be deleted first
// this is useful for delete operations where the policy should be checked before the tuples are deleted
// of if its part of a bulk delete operation and the tuples should be deleted first
type DeleteTuplesFirstKey struct{}

// Mutation interface that all generated Mutation types must implement
type Mutation interface {
	// CheckAccessForEdit checks if the user has access to edit the object type
	CheckAccessForEdit(ctx context.Context) error
	// CheckAccessForDelete checks if the user has access to delete the object type
	CheckAccessForDelete(ctx context.Context) error
}

// MutationForHooks interface that all generated Mutation that use hooks types must implement
// With the exception of Op() all other methods are created by the entfga generator
type MutationForHooks interface {
	// Op is the ent operation being taken on the Mutation (Create, Update, UpdateOne, Delete, DeleteOne)
	Op() ent.Op
	// CreateTuplesFromCreate creates tuple relationships for the user/object type on Create Mutations
	CreateTuplesFromCreate(ctx context.Context) error
	// CreateTuplesFromUpdate creates new and deletes old tuple relationships for the user/object type on Update Mutations
	CreateTuplesFromUpdate(ctx context.Context) error
	// CreateTuplesFromDelete deletes tuple relationships for the user/object type on Delete Mutations
	CreateTuplesFromDelete(ctx context.Context) error
}

// Query interface that all generated Query types must implement
type Query interface {
	// CheckAccess checks if the user has read access to the object type
	CheckAccess(ctx context.Context) error
}

// QueryRuleFunc type is an adapter which allows the use of
// ordinary functions as mutation rules.
type QueryRuleFunc func(context.Context, ent.Query) error

// Eval returns f(ctx, q).
func (f QueryRuleFunc) EvalQuery(ctx context.Context, q ent.Query) error {
	return f(ctx, q)
}

// Mutator is an interface thats defines a method for mutating a generic ent value based on a given mutation.
// This is used as a generic interface that ent generated Mutations will implement
type Mutator interface {
	Mutate(context.Context, Mutation) (ent.Value, error)
}

// Querier is an interface thats defines a method for querying a generic ent value based on a given query.
// This is used as a generic interface that ent generated Query will implement
type Querier interface {
	Query(context.Context, Query) (ent.Value, error)
}

// On will execute the appropriate hook based on the ent operation
func On(hk ent.Hook, op ent.Op) ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			// if the operation is the one we are looking for, execute the hook
			// exclude the Update and UpdateOne operations if the object is soft delete
			// otherwise the operation ends up running twice
			if m.Op().Is(op) && (!op.Is(ent.OpUpdate|ent.OpUpdateOne) || !entx.CheckIsSoftDeleteType(ctx, m.Type())) {
				return hk(next).Mutate(ctx, m)
			}

			return next.Mutate(ctx, m)
		})
	}
}
