package entfga

import (
	"context"

	"entgo.io/ent"
	"github.com/theopenlane/utils/contextx"
)

// AuthzHooks returns a list of authorization hooks for create, update, and delete
// operations on a specific type of mutation.
func AuthzHooks[T MutationForHooks]() []ent.Hook {
	return []ent.Hook{
		On(authzHookCreate[T](), ent.OpCreate),
		On(authzHookUpdate[T](), ent.OpUpdate|ent.OpUpdateOne),
		On(authzHookDelete[T](), ent.OpDelete|ent.OpDeleteOne),
	}
}

// authzHookCreate creates tuple relations in FGA after the mutation is executed
func authzHookCreate[T MutationForHooks]() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			retVal, err := next.Mutate(ctx, m)
			if err != nil {
				return nil, err
			}

			if err = m.(T).CreateTuplesFromCreate(ctx); err != nil {
				return nil, err
			}

			return retVal, nil
		})
	}
}

// authzHookUpdate updates (involving a delete and create) tuple relations in FGA after the mutation is executed
func authzHookUpdate[T MutationForHooks]() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			retVal, err := next.Mutate(ctx, m)
			if err != nil {
				return nil, err
			}

			if err = m.(T).CreateTuplesFromUpdate(ctx); err != nil {
				return nil, err
			}

			return retVal, err
		})
	}
}

// authzHookDelete removes tuple relations in FGA after the mutation is executed
func authzHookDelete[T MutationForHooks]() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if _, allowDelete := contextx.From[DeleteTuplesFirstKey](ctx); !allowDelete {
				// if we don't have the DeleteTuplesFirstKey, we need to delete the object first
				// and then delete the tuples
				// this allows the policy to be checked before the tuples are deleted
				retVal, err := next.Mutate(ctx, m)
				if err != nil {
					return nil, err
				}

				if err = m.(T).CreateTuplesFromDelete(ctx); err != nil {
					return nil, err
				}

				return retVal, nil
			}

			// if we have the DeleteTuplesFirstKey, we can delete the tuples first
			// and then delete the object
			if err := m.(T).CreateTuplesFromDelete(ctx); err != nil {
				return nil, err
			}

			retVal, err := next.Mutate(ctx, m)
			if err != nil {
				return nil, err
			}

			return retVal, nil
		})
	}
}
