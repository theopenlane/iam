[![Build status](https://badge.buildkite.com/3346f9d3732a143a78c4da3eb9dcb8f4e9616a64bebd0cbfbd.svg)](https://buildkite.com/theopenlane/iam)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=theopenlane_iam&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=theopenlane_iam)
[![Go Report Card](https://goreportcard.com/badge/github.com/theopenlane/iam)](https://goreportcard.com/report/github.com/theopenlane/iam)
[![Go Reference](https://pkg.go.dev/badge/github.com/theopenlane/iam.svg)](https://pkg.go.dev/github.com/theopenlane/iam)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache2.0-brightgreen.svg)](https://opensource.org/licenses/Apache-2.0)

# Identity and Access Management (IAM)

A go library for interacting with [OpenFGA](https://openfga.dev/) - it is comprised of 2 packages, `fgax` and `entfga`.
- fgax: wrapper to interact with the [OpenFGA go-sdk](https://github.com/openfga/go-sdk) and client libraries
- entfga: an [ent extension](https://entgo.io/docs/extensions/) to create relationship tuples using [ent Hooks](https://entgo.io/docs/hooks/)

## install

You can install `iam` by running the following command:

```shell
go get github.com/theopenlane/iam@latest
```

## iam/fgax

This package includes helper functions used heavily in [Openlane Core](https://github.com/theopenlane/core/).

For example, you can easily check for `Read` access of an organization using

```go
	// create client
	fgaClient, err := fgax.Client("https://fga-host.example.com")
	if err != nil {
		return false
	}

	// create access check
	req := fgax.AccessCheck{
		SubjectID:   "user-id",
		SubjectType: "user",
		ObjectID:    "organization-id",
	}

	allow, err := fgaClient.CheckOrgReadAccess(ctx, req)
	if err != nil {
		return false
	}
```

## entfga

See the [README](./entfga/README.md) for details

## Contributing

Please read the [contributing](.github/CONTRIBUTING.md) guide.
