package tokens

import (
	"slices"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/oklog/ulid/v2"

	"github.com/theopenlane/utils/ulids"
)

// PermissionScopes represents a set of objects that can be accessed for each permission level
type PermissionScopes struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
	Admin []string `json:"admin,omitempty"`
}

// Claims implements custom claims and extends the `jwt.RegisteredClaims` struct; we will store user-related elements here (and thus in the JWT Token) for reference / validation
type Claims struct {
	jwt.RegisteredClaims
	// UserID is the internal generated mapping ID for the user
	UserID string `json:"user_id,omitempty"`
	// OrgID is the internal generated mapping ID for the organization the JWT token is valid for
	OrgID string `json:"org,omitempty"`
	// Scopes lists objects that can be accessed for each permission level
	Scopes PermissionScopes `json:"scopes,omitempty"`

	// TrustCenterID is the internal generated mapping ID for the trust center the JWT token is valid for
	TrustCenterID string `json:"trust_center_id,omitempty"`

	// Modules is a list of modules that are enabled for the user in their current organization
	Modules []string `json:"modules,omitempty"`

	// Email is the email address of the user
	Email string `json:"email,omitempty"`

	// AssessmentID is the id of the questionnaire to fill
	AssessmentID string `json:"assessment_id,omitempty"`
}

// ParseUserID returns the ID of the user from the Subject of the claims
func (c Claims) ParseUserID() ulid.ULID {
	userID, err := ulid.Parse(c.UserID)
	if err != nil {
		return ulids.Null
	}

	return userID
}

// ParseOrgID parses and return the organization ID from the `OrgID` field of the claims
func (c Claims) ParseOrgID() ulid.ULID {
	orgID, err := ulid.Parse(c.OrgID)
	if err != nil {
		return ulids.Null
	}

	return orgID
}

// HasScope returns true if the token grants the given permission level on the provided object name
func (c Claims) HasScope(level, object string) bool {
	var list []string

	switch level {
	case "read":
		list = c.Scopes.Read
	case "write":
		list = c.Scopes.Write
	case "admin":
		list = c.Scopes.Admin
	default:
		return false
	}

	return slices.Contains(list, object)
}

// HasModule returns true if the token grants access to the provided module
func (c Claims) HasModule(module string) bool {
	return slices.Contains(c.Modules, module)
}

// GetModules returns the list of modules assigned to the user in their current organization
func (c Claims) GetModules() []string {
	slices.Sort(c.Modules)

	return c.Modules
}
