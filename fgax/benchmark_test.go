//go:build integration

package fgax_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/fgax"
	"github.com/theopenlane/iam/fgax/testutils"
)

const benchmarkModelDSL = `
model
  schema 1.1

type user

type organization
  relations
    define member: [user]
    define admin: [user]
    define owner: [user]
`

func setupIntegrationBenchmark(b *testing.B) (*fgax.Client, context.Context, func()) {
	b.Helper()

	ctx := context.Background()

	tmpModelFile := b.TempDir() + "/model.fga"
	err := os.WriteFile(tmpModelFile, []byte(benchmarkModelDSL), 0644)
	require.NoError(b, err)

	container := testutils.NewFGATestcontainer(ctx,
		testutils.WithStoreName("benchmark-store"),
		testutils.WithReuse(true),
		testutils.WithContainerName("fga-benchmark"),
		testutils.WithModelFile(tmpModelFile),
	)

	client, err := container.NewFgaClient(ctx)
	require.NoError(b, err)

	return client, ctx, func() {
		container.TeardownFixture()
	}
}

func makeTuples(b *testing.B, client *fgax.Client, ctx context.Context, totalTuples, targetTuples int, targetObject string) {
	b.Helper()

	var writes []fgax.TupleKey

	for i := 0; i < targetTuples; i++ {
		writes = append(writes, fgax.TupleKey{
			Subject: fgax.Entity{
				Kind:       "user",
				Identifier: fmt.Sprintf("target-user-%d", i),
			},
			Relation: "member",
			Object: fgax.Entity{
				Kind:       "organization",
				Identifier: targetObject,
			},
		})
	}

	for i := 0; i < totalTuples-targetTuples; i++ {
		writes = append(writes, fgax.TupleKey{
			Subject: fgax.Entity{
				Kind:       "user",
				Identifier: fmt.Sprintf("other-user-%d", i),
			},
			Relation: "member",
			Object: fgax.Entity{
				Kind:       "organization",
				Identifier: fmt.Sprintf("other-org-%d", i),
			},
		})
	}

	maxWrites := 10
	for i := 0; i < len(writes); i += maxWrites {
		end := i + maxWrites
		if end > len(writes) {
			end = len(writes)
		}

		batch := writes[i:end]
		_, err := client.WriteTupleKeys(ctx, batch, []fgax.TupleKey{})
		require.NoError(b, err)
	}
}

func cleanupTuples(b *testing.B, client *fgax.Client, ctx context.Context) {
	b.Helper()

	allTuples, err := client.GetAllTuples(ctx)
	if err != nil {
		b.Logf("Warning: failed to get tuples for cleanup: %v", err)
		return
	}

	if len(allTuples) == 0 {
		return
	}

	var deletes []fgax.TupleKey
	for _, tuple := range allTuples {
		subject, _ := fgax.ParseEntity(tuple.Key.User)
		object, _ := fgax.ParseEntity(tuple.Key.Object)

		deletes = append(deletes, fgax.TupleKey{
			Subject:  subject,
			Relation: fgax.Relation(tuple.Key.Relation),
			Object:   object,
		})
	}

	maxWrites := 10
	for i := 0; i < len(deletes); i += maxWrites {
		end := i + maxWrites
		if end > len(deletes) {
			end = len(deletes)
		}

		batch := deletes[i:end]
		_, err := client.WriteTupleKeys(ctx, []fgax.TupleKey{}, batch)
		if err != nil {
			b.Logf("Warning: failed to delete tuples in cleanup: %v", err)
		}
	}
}

func BenchmarkDeleteAllObjectRelations_Small(b *testing.B) {
	client, ctx, cleanup := setupIntegrationBenchmark(b)
	defer cleanup()

	targetObject := "target-org-small"
	totalTuples := 100
	targetTuples := 10

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		makeTuples(b, client, ctx, totalTuples, targetTuples, targetObject)
		b.StartTimer()

		err := client.DeleteAllObjectRelations(ctx, fmt.Sprintf("organization:%s", targetObject), []string{})
		require.NoError(b, err)
	}
}

func BenchmarkDeleteAllObjectRelations_Medium(b *testing.B) {
	client, ctx, cleanup := setupIntegrationBenchmark(b)
	defer cleanup()

	targetObject := "target-org-medium"
	totalTuples := 1000
	targetTuples := 10

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		makeTuples(b, client, ctx, totalTuples, targetTuples, targetObject)
		b.StartTimer()

		err := client.DeleteAllObjectRelations(ctx, fmt.Sprintf("organization:%s", targetObject), []string{})
		require.NoError(b, err)
	}
}

func BenchmarkDeleteAllObjectRelations_Large(b *testing.B) {
	client, ctx, cleanup := setupIntegrationBenchmark(b)
	defer cleanup()

	targetObject := "target-org-large"
	totalTuples := 5000
	targetTuples := 20

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		makeTuples(b, client, ctx, totalTuples, targetTuples, targetObject)
		b.StartTimer()

		err := client.DeleteAllObjectRelations(ctx, fmt.Sprintf("organization:%s", targetObject), []string{})
		require.NoError(b, err)
	}
}

func BenchmarkGetTuplesForObject(b *testing.B) {
	client, ctx, cleanup := setupIntegrationBenchmark(b)
	defer cleanup()

	testCases := []struct {
		name         string
		totalTuples  int
		targetTuples int
	}{
		{"Small", 100, 10},
		{"Medium", 1000, 10},
		{"Large", 5000, 20},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			targetObject := fmt.Sprintf("target-org-%s", tc.name)

			makeTuples(b, client, ctx, tc.totalTuples, tc.targetTuples, targetObject)
			defer cleanupTuples(b, client, ctx)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := client.GetTuplesForObject(ctx, fmt.Sprintf("organization:%s", targetObject))
				require.NoError(b, err)
			}
		})
	}
}

func BenchmarkGetAllTuples(b *testing.B) {
	client, ctx, cleanup := setupIntegrationBenchmark(b)
	defer cleanup()

	testCases := []struct {
		name        string
		totalTuples int
	}{
		{"Small", 100},
		{"Medium", 1000},
		{"Large", 5000},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			targetObject := fmt.Sprintf("any-org-%s", tc.name)

			makeTuples(b, client, ctx, tc.totalTuples, 10, targetObject)
			defer cleanupTuples(b, client, ctx)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := client.GetAllTuples(ctx)
				require.NoError(b, err)
			}
		})
	}
}
