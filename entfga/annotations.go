package entfga

// Annotations of the fga extension
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
