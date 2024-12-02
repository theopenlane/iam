package entfga

import (
	"strings"

	"github.com/stoewer/go-strcase"
)

// Annotations of the fga extension
// Annotations can be added to a schema using the struct directly
// or by using the helper functions provided in this package
type Annotations struct {
	ObjectType      string `yaml:"ObjectType,omitempty"`      // Object type for the fga relationship
	IncludeHooks    bool   `yaml:"includeHooks,omitempty"`    // Include hooks for the fga extension to add tuples to FGA
	IDField         string `yaml:"idField,omitempty"`         // ID field for the object type
	NillableIDField bool   `yaml:"nillableIDField,omitempty"` // NillableIDField set to true if the id is optional field in the ent schema
	OrgOwnedField   bool   `yaml:"orgOwnedField,omitempty"`   // OrgOwnedField set to true if the field is an org owned field and org automatically set by the system
}

// Name of the annotation
func (Annotations) Name() string {
	return "Authz"
}

// SelfAccessChecks returns an empty annotation
// the schema will use the the schema name as the object type
// in all fga checks, e.g. the OrganizationSchema will use "organization"
// as the object type
func SelfAccessChecks() Annotations {
	return Annotations{}
}

// OrgInheritedChecks returns an annotation with the object type set to organization
// and the org owned field set to true
func OrganizationInheritedChecks() Annotations {
	return Annotations{
		ObjectType:      "organization",
		NillableIDField: true,
		OrgOwnedField:   true,
		IDField:         "OwnerID",
	}
}

// MembershipChecks returns an annotation for checks based on a membership table
// commonly used on through tables, e.g. organization members, group members, etc
// This will enable the hooks to create tuples on object mutations
func MembershipChecks(object string) Annotations {
	objectType := strings.ToLower(object)
	idField := strcase.UpperCamelCase(object) + "ID"

	return Annotations{
		ObjectType:   objectType,
		IncludeHooks: true,
		IDField:      idField,
	}
}

// SettingsChecks returns an annotation for permission checks
// on settings schemas, which typically inherit their permission from their
// parent object (e.g. group settings would inherit from group)
func SettingsChecks(object string) Annotations {
	objectType := strings.ToLower(object)
	idField := strcase.UpperCamelCase(object) + "ID"

	return Annotations{
		ObjectType:      objectType,
		IDField:         idField,
		NillableIDField: true,
	}
}

// HistorySchemaChecks returns an annotation for permission checks
// on history schemas which inherit their permissions from the main schema
// for example the UserHistorySchema would inherit from the UserSchema (object type: user)
func HistorySchemaChecks() Annotations {
	return Annotations{
		IDField: "Ref",
	}
}
