package entfga

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"

	"entgo.io/ent/entc/gen"
	"github.com/stoewer/go-strcase"
	"golang.org/x/tools/imports"
)

const (
	templateDir = "templates"
)

// extractObjectType gets the key that is used for the object type
func extractObjectType(val any) string {
	objectType, ok := val.(string)
	if !ok {
		return ""
	}

	return objectType
}

// extractIDField gets the key that is used for the id field
func extractIDField(val any) string {
	idField, ok := val.(string)
	if !ok {
		return ""
	}

	if idField == "" {
		return "ID"
	}

	return idField
}

// extractNillableIDField gets the key that is used for the nillable id field
func extractNillableIDField(val any) bool {
	nillable, ok := val.(bool)
	if !ok {
		return false
	}

	return nillable
}

// extractOrgOwnedField gets the key that is used for the org owned field
func extractOrgOwnedField(val any) bool {
	orgOwned, ok := val.(bool)
	if !ok {
		return false
	}

	return orgOwned
}

// hasCreateID checks if the input would have the ID to check permissions
func hasCreateID(val any) bool {
	idField, ok := val.(string)
	if !ok {
		return false
	}

	if idField == "" || idField == "ID" {
		return false
	}

	return true
}

// hasMutationInputSet checks if the annotation for MutationInputs is set on the schema
// this annotation would look like:
// `entgql.Mutations(entgql.MutationCreate(), entgql.MutationUpdate()),`
// on an ent schema
func hasMutationInputSet(val any) bool {
	annotation, ok := val.(map[string]interface{})
	if !ok {
		return false
	}

	if res, ok := annotation["MutationInputs"]; ok && res != nil {
		return true
	}

	return false
}

// extractIncludeHooks gets the key that is used to determine if the hooks should be included
func extractIncludeHooks(val any) bool {
	includeHooks, ok := val.(bool)
	if !ok {
		return true
	}

	return includeHooks
}

// useSoftDeletes checks the config properties for the Soft Delete setting
func useSoftDeletes(config Config) bool {
	return config.SoftDeletes
}

// parseTemplate parses the template and sets values in the template
func parseTemplate(name, path string) *gen.Template {
	t := gen.NewTemplate(name)
	t.Funcs(template.FuncMap{
		"extractObjectType":      extractObjectType,
		"extractIDField":         extractIDField,
		"extractNillableIDField": extractNillableIDField,
		"extractOrgOwnedField":   extractOrgOwnedField,
		"hasCreateID":            hasCreateID,
		"hasMutationInputSet":    hasMutationInputSet,
		"extractIncludeHooks":    extractIncludeHooks,
		"useSoftDeletes":         useSoftDeletes,
		"ToUpperCamel":           strcase.UpperCamelCase,
		"ToLower":                strings.ToLower,
	})

	return gen.MustParse(t.ParseFS(_templates, path))
}

// templateInfo is the information needed to parse the template
// for the authz checks
type templateInfo struct {
	// Graph holds the nodes/entities of the loaded graph schema
	Graph gen.Graph
	// GeneratedPkg is the package name for the generated files by ent
	GeneratedPkg string
	// GeneratedPath is the path to the generated files by ent
	GeneratedPath string
}

// parseAuthzChecksTemplate parses the template and sets values in the template
func parseAuthzChecksTemplate(info templateInfo) error {
	name := "authzChecks"
	templateName := fmt.Sprintf("%s.tmpl", name)

	t := template.New(name)
	t.Funcs(template.FuncMap{
		"extractObjectType":      extractObjectType,
		"extractIDField":         extractIDField,
		"extractOrgOwnedField":   extractOrgOwnedField,
		"extractNillableIDField": extractNillableIDField,
		"hasCreateID":            hasCreateID,
		"hasMutationInputSet":    hasMutationInputSet,
		"ToLower":                strings.ToLower,
	})

	// parse the template
	template.Must(t.ParseFS(_templates, fmt.Sprintf("%s/%s", templateDir, templateName)))

	// execute the template into a buffer
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, templateName, info); err != nil {
		return err
	}

	// create the output file
	outputPath := fmt.Sprintf("%s/%s.go", info.GeneratedPath, strcase.SnakeCase(name))

	return writeAndFormatFile(buf, outputPath)
}

// writeAndFormatFile formats the bytes using gofmt and goimports and writes them to the output file
func writeAndFormatFile(buf bytes.Buffer, outputPath string) error {
	// run gofmt and goimports on the file contents
	formatted, err := imports.Process(outputPath, buf.Bytes(), nil)
	if err != nil {
		return fmt.Errorf("%w: failed to format file: %v", ErrFailedToWriteTemplate, err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("%w: failed to create file: %v", ErrFailedToWriteTemplate, err)
	}

	// write the formatted source to the file
	if _, err := file.Write(formatted); err != nil {
		return fmt.Errorf("%w: failed to write to file: %v", ErrFailedToWriteTemplate, err)
	}

	return nil
}
