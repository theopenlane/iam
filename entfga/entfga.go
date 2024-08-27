package entfga

import (
	"embed"
	"fmt"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

var (
	//go:embed templates/*
	_templates embed.FS
)

const (
	defaultGeneratedPkg  = "generated"
	defaultGeneratedPath = "internal/ent/generated"
	defaultSchemaPath    = "./internal/ent/schema"
)

type Config struct {
	// SoftDeletes is used to determine if the schema uses soft deletes
	SoftDeletes bool
	// SchemaPath is the path to the schema directory
	SchemaPath string
	// GeneratedPath is the path to the generated directory
	GeneratedPath string
	// GeneratedPkg is the package that the generated code will be placed in
	GeneratedPkg string
}

func (c Config) Name() string {
	return "AuthzConfig"
}

// AuthzExtension implements entc.Extension.
type AuthzExtension struct {
	entc.DefaultExtension
	config *Config
}

type ConfigOption = func(*Config)

// New creates a new fga extension with the provided config options
func New(opts ...ConfigOption) *AuthzExtension {
	extension := &AuthzExtension{
		// Set configuration defaults that can get overridden with ConfigOption
		config: &Config{
			SoftDeletes:   false,
			GeneratedPkg:  defaultGeneratedPkg,
			GeneratedPath: defaultGeneratedPath,
			SchemaPath:    defaultSchemaPath,
		},
	}

	// update the config with the options
	for _, opt := range opts {
		opt(extension.config)
	}

	return extension
}

// WithSoftDeletes ensure the delete hook is still used even when soft deletes
// change the Op to Update
func WithSoftDeletes() ConfigOption {
	return func(c *Config) {
		c.SoftDeletes = true
	}
}

// WithSchemaPath allows you to set an alternative schemaPath
// Defaults to "./schema"
func WithSchemaPath(schemaPath string) ConfigOption {
	return func(c *Config) {
		c.SchemaPath = schemaPath
	}
}

// WithGeneratedPath allows you to set an alternative ent generated path
// Defaults to "internal/ent/generated"
func WithGeneratedPath(generatedPath string) ConfigOption {
	return func(c *Config) {
		c.GeneratedPath = generatedPath
	}
}

// WithGeneratedPkg allows you to set an alternative generated package
// Defaults to "generated"
func WithGeneratedPkg(generatedPkg string) ConfigOption {
	return func(c *Config) {
		c.GeneratedPkg = generatedPkg
	}
}

// GenerateAuthzChecks generates the authz checks for the ent schema
// this is separate to allow the function to be called outside the entc generation
// due to dependencies between the ent policies and the authz checks
func (e *AuthzExtension) GenerateAuthzChecks() error {
	graph, err := entc.LoadGraph(e.config.SchemaPath, &gen.Config{})
	if err != nil {
		return fmt.Errorf("%w: failed loading ent graph: %v", ErrFailedToGenerateTemplate, err)
	}

	info := templateInfo{
		Graph:         *graph,
		GeneratedPkg:  e.config.GeneratedPkg,
		GeneratedPath: e.config.GeneratedPath,
	}

	return parseAuthzChecksTemplate(info)
}

// Templates returns the generated templates which include the client and authz from mutation
func (e *AuthzExtension) Templates() []*gen.Template {
	templates := []*gen.Template{
		parseTemplate("authzFromMutation", "templates/authzFromMutation.tmpl"),
		parseTemplate("client", "templates/client.tmpl"),
	}

	return templates
}

// Annotations of the AuthzExtension
func (e *AuthzExtension) Annotations() []entc.Annotation {
	return []entc.Annotation{
		e.config,
	}
}
