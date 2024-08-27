# entfga

`entfga` is an [ent extension](https://entgo.io/docs/extensions/) to create relationship tuples using [ent Hooks](https://entgo.io/docs/hooks/)

## install

You can install `entfga` by running the following command:

```shell
go get github.com/theopenlane/iam/entfga@latest
```

In addition to installing `entfga`, you need to create two files in your `ent` directory: `entc.go` and `generate.go`.
The `entc.go` file should contain the following code:

```go
//go:build ignore

package main

import (
	"log"
	"github.com/theopenlane/iam/entfga"
	"entgo.io/ent/entc"
)

func main() {
	// initialize the entfga extension
	entfgaExt := entfga.New(
		entfga.WithSoftDeletes(),
		entfga.WithSchemaPath(schemaPath),
	)

	// generate authz checks if you are using ent policies
	if err := entfgaExt.Config.GenerateAuthzChecks(); err != nil {
		log.Fatalf("generating authz checks: %v", err)
	}

	if err := entc.Generate("./schema",
		&gen.Config{},
		entc.Extensions(
            entfgaExt,
		),
	); err != nil {
		log.Fatal("running ent codegen:", err)
	}
}
```

The `generate.go` file should contain the following code:

```go
package ent

//go:generate go run -mod=mod entc.go
```

### Usage

When creating the `*ent.Client` add the following to enable the authz hooks and policies:

```
	client.WithAuthz()
```

The `privacy` feature **must** be turned on:

```
	Features: []gen.Feature{gen.FeaturePrivacy},
```

## Generate Hooks and Policies

In the `ent` schema, provide the following annotation:

```go
// Annotations of the OrgMembership
func (OrgMembership) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entfga.Annotations{
			ObjectType:   "organization",
			IncludeHooks: true,
			IDField:      "OrganizationID", // Defaults to ID, override to object ID field
		},
	}
}
```

The `ObjectType` **must** be the same between the ID field name in the schema and the object type in the FGA relationship. In the example above
the field in the schema is `OrganizationID` and the object in FGA is `organization`.

If the `ID` field is `Optional()`, you'll need to set `NillableIDField: true,` on the annotation to ensure the `string` value is used instead of the `pointer` on the `CreateInput`.


## Generate Policies Only

In the `ent` schema, provide the following annotation:

```go
// Annotations of the Organization
func (Organization) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entfga.Annotations{
			ObjectType:   "organization",
			IncludeHooks: false,
		},
	}
}
```

## Using Policies

A policy check function will be created per mutation and query type when the annotation is used, these can be set on the policy of the schema.
They must be wrapped in the `privacy` `MutationRuleFunc`, as seen the example below:

```go
// Policy of the Organization
func (Organization) Policy() ent.Policy {
	return privacy.Policy{
		Mutation: privacy.MutationPolicy{
			rule.DenyIfNoSubject(),
			privacy.OrganizationMutationRuleFunc(func(ctx context.Context, m *generated.OrganizationMutation) error {
				return m.CheckAccessForEdit(ctx)
			}),
			// Add a separate delete policy if permissions for delete of the object differ from normal edit permissions
			privacy.OrganizationMutationRuleFunc(func(ctx context.Context, m *generated.OrganizationMutation) error {
				return m.CheckAccessForDelete(ctx)
			}),
			privacy.AlwaysDenyRule(),
		},
		Query: privacy.QueryPolicy{
			privacy.OrganizationQueryRuleFunc(func(ctx context.Context, q *generated.OrganizationQuery) error {
				return q.CheckAccess(ctx)
			}),
			privacy.AlwaysDenyRule(),
		},
	}
}
```

**NOTE**: These policies can only be added after an initial run of `entc` with the `Annotations`. This is what creates the `CheckAccess`, etc functions that are referenced in the policy above.

## Contributing

Please read the [contributing](.github/CONTRIBUTING.md) guide as well as the [Developer Certificate of Origin](https://developercertificate.org/). You will be required to sign all commits to the OpenLane project, so if you're unfamiliar with how to set that up, see [github's documentation](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).

## Security

We take the security of our software products and services seriously, including all of the open source code repositories managed through our Github Organizations, such as [theopenlane](https://github.com/theopenlane). If you believe you have found a security vulnerability in any of our repositories, please report it to us through coordinated disclosure.

**Please do NOT report security vulnerabilities through public github issues, discussions, or pull requests!**

Instead, please send an email to `security@theopenlane.io` with as much information as possible to best help us understand and resolve the issues. See the security policy attached to this repository for more details.

## Questions?

Open a github issue on this repository and we'll respond as soon as we're able!
