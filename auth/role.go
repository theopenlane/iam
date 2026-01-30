package auth

import "github.com/stoewer/go-strcase"

// OrganizationRoleType represents the role of the user in the organization
type OrganizationRoleType string

const (
	// AdminRole is the admin role in the organization - with general read and creation access, this does not guarantee write access to all resources
	AdminRole OrganizationRoleType = "admin"
	// SuperAdminRole is the super admin role in the organization - with full access to all resources, similar to owner but without ownership transfer capabilities
	SuperAdminRole OrganizationRoleType = "super_admin"
	// OwnerRole is the owner role in the organization - with full access to all resources including ownership transfer capabilities
	OwnerRole OrganizationRoleType = "owner"
	// MemberRole is the member role in the organization - with limited read access and no creation or write access by default
	MemberRole OrganizationRoleType = "member"
	// AuditorRole is the auditor role in the organization - with read-only access to resources for auditing purposes and limited write access for commenting, notes, etc.
	AuditorRole OrganizationRoleType = "auditor"
	// AnonymousRole is used for anonymous users with minimal access for public resources such as trust center and questionnaires
	AnonymousRole OrganizationRoleType = "anonymous"
)

// String returns the string representation of the OrganizationRoleType
func (ort OrganizationRoleType) String() string {
	return string(ort)
}

// IsValid checks if the OrganizationRoleType is valid
func (ort OrganizationRoleType) IsValid() bool {
	switch ort {
	case AdminRole, SuperAdminRole, OwnerRole, MemberRole, AuditorRole, AnonymousRole:
		return true
	default:
		return false
	}
}

// ToOrganizationRoleType converts a string to an OrganizationRoleType
func ToOrganizationRoleType(role string) (OrganizationRoleType, bool) {
	// convert to lower snake case to match the constants
	role = strcase.SnakeCase(role)

	ort := OrganizationRoleType(role)
	if !ort.IsValid() {
		return "", false
	}

	return ort, true
}
