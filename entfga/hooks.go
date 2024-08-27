package entfga

import (
	"context"

	"entgo.io/ent"
)

// AuthzHooks returns a list of authorization hooks for create, update, and delete
// operations on a specific type of mutation.
func AuthzHooks[T Mutation]() []ent.Hook {
	return []ent.Hook{
		On(authzHookCreate[T](), ent.OpCreate),
		On(authzHookUpdate[T](), ent.OpUpdate|ent.OpUpdateOne),
		On(authzHookDelete[T](), ent.OpDelete|ent.OpDeleteOne),
	}
}

// authzHookCreate creates tuple relations in FGA after the mutation is executed
func authzHookCreate[T Mutation]() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			mutation, err := getTypedMutation[T](m)
			if err != nil {
				return nil, err
			}

			value, err := next.Mutate(ctx, m)
			if err != nil {
				return nil, err
			}

			err = mutation.CreateTuplesFromCreate(ctx)
			if err != nil {
				return nil, err
			}

			return value, nil
		})
	}
}

// authzHookUpdate updates (involving a delete and create) tuple relations in FGA after the mutation is executed
func authzHookUpdate[T Mutation]() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			mutation, err := getTypedMutation[T](m)
			if err != nil {
				return nil, err
			}

			if err = mutation.CreateTuplesFromUpdate(ctx); err != nil {
				return nil, err
			}

			return next.Mutate(ctx, m)
		})
	}
}

// authzHookDelete removes tuple relations in FGA after the mutation is executed
func authzHookDelete[T Mutation]() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			mutation, err := getTypedMutation[T](m)
			if err != nil {
				return nil, err
			}

			if err = mutation.CreateTuplesFromDelete(ctx); err != nil {
				return nil, err
			}

			return next.Mutate(ctx, m)
		})
	}
}
