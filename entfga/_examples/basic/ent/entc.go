//go:build ignore

package main

import (
	"log"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/entc/gen"
	"github.com/theopenlane/iam/entfga"
	"github.com/theopenlane/iam/fgax"
	"go.uber.org/zap"

	"entgo.io/ent/entc"
)

func main() {
	gqlExt, err := entgql.NewExtension(
		// Tell Ent to generate a GraphQL schema for
		// the Ent schema in a file named ent.graphql.
		entgql.WithSchemaGenerator(),
		entgql.WithSchemaPath("../schema/ent.graphql"),
		entgql.WithConfigPath("../gqlgen.yml"),
		entgql.WithWhereInputs(true),
	)
	if err != nil {
		log.Fatalf("creating entgql extension: %v", err)
	}

	entfgaExt := entfga.New(
		entfga.WithSchemaPath("./schema"),
		entfga.WithGeneratedPath("."),
		entfga.WithGeneratedPkg("ent"),
	)

	if err := entfgaExt.GenerateAuthzChecks(); err != nil {
		log.Fatalf("generating authz checks: %v", err)
	}

	if err := entc.Generate("./schema",
		&gen.Config{
			Features: []gen.Feature{gen.FeaturePrivacy},
		},
		entc.Dependency(
			entc.DependencyName("Authz"),
			entc.DependencyType(fgax.Client{}),
		),
		entc.Dependency(
			entc.DependencyName("Logger"),
			entc.DependencyType(zap.SugaredLogger{}),
		),
		entc.Extensions(
			gqlExt,
			entfgaExt,
		),
	); err != nil {
		log.Fatal("running ent codegen:", err)
	}
}
