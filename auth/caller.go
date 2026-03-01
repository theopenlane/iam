package auth

import "slices"

// Capability is a set of flags describing what a Caller is allowed to bypass.
// Values are explicit powers of two so they remain stable if constants are
// reordered, which matters when Caller is serialized by gala.
type Capability uint64

const (
	// CapBypassOrgFilter skips org-scoped interceptor filtering
	CapBypassOrgFilter Capability = 1 << 0
	// CapBypassFeatureCheck skips feature-flag checks
	CapBypassFeatureCheck Capability = 1 << 1
	// CapBypassFGA skips OpenFGA authorization checks
	CapBypassFGA Capability = 1 << 2
	// CapBypassManagedGroup bypasses managed-group mutation guards
	CapBypassManagedGroup Capability = 1 << 3
	// CapBypassAuditLog suppresses audit log emission
	CapBypassAuditLog Capability = 1 << 4
	// CapInternalOperation marks the caller as a trusted internal service operation
	CapInternalOperation Capability = 1 << 5
	// CapBypassSubscriptionCheck skips subscription validation
	CapBypassSubscriptionCheck Capability = 1 << 6
	// CapSystemAdmin grants global system-administrator privileges
	CapSystemAdmin Capability = 1 << 7
)

// Caller holds the identity and capabilities for any request actor —
// authenticated users, anonymous visitors, internal service calls, etc.
type Caller struct {
	// SubjectID is the unique identifier for this actor
	SubjectID string `json:"subject_id,omitempty"`
	// SubjectName is the display name of the actor
	SubjectName string `json:"subject_name,omitempty"`
	// SubjectEmail is the email address of the actor
	SubjectEmail string `json:"subject_email,omitempty"`
	// OrganizationID is the active org for this request; set for JWT callers
	OrganizationID string `json:"organization_id,omitempty"`
	// OrganizationName is the display name of the active org
	OrganizationName string `json:"organization_name,omitempty"`
	// OrganizationIDs is the set of orgs this actor is authorized to access; set for token callers
	OrganizationIDs []string `json:"organization_ids,omitempty"`
	// AuthenticationType describes how this actor was authenticated
	AuthenticationType AuthenticationType `json:"authentication_type,omitempty"`
	// OrganizationRole is the actor's role within the active org
	OrganizationRole OrganizationRoleType `json:"organization_role,omitempty"`
	// ActiveSubscription reports whether the active org has a current subscription
	ActiveSubscription bool `json:"active_subscription,omitempty"`
	// Capabilities is the set of bypass flags granted to this caller
	Capabilities Capability `json:"capabilities,omitempty"`
	// Impersonation is set when this Caller is acting on behalf of another user
	Impersonation *ImpersonationContext `json:"impersonation,omitempty"`
	// OriginalSystemAdmin is set when a system admin is executing as another caller.
	// This keeps caller lineage in one root identity tree instead of a parallel context key.
	OriginalSystemAdmin *Caller `json:"original_system_admin,omitempty"`
}

// Has reports whether the Caller holds all of the specified capabilities
func (c *Caller) Has(caps Capability) bool {
	return c.Capabilities&caps == caps
}

// HasInLineage reports whether the Caller or its original system-admin lineage
// holds all of the specified capabilities
func (c *Caller) HasInLineage(caps Capability) bool {
	if c == nil {
		return false
	}

	if c.Has(caps) {
		return true
	}

	if c.OriginalSystemAdmin == nil {
		return false
	}

	return c.OriginalSystemAdmin.HasInLineage(caps)
}

// ActiveOrg returns OrganizationID if set, or the single entry in OrganizationIDs
// if exactly one is present. Returns ("", false) otherwise.
func (c *Caller) ActiveOrg() (string, bool) {
	if c.OrganizationID != "" {
		return c.OrganizationID, true
	}

	if len(c.OrganizationIDs) == 1 && c.OrganizationIDs[0] != "" {
		return c.OrganizationIDs[0], true
	}

	return "", false
}

// OrgIDs returns the org IDs this caller is authorized to access
func (c *Caller) OrgIDs() []string {
	if len(c.OrganizationIDs) > 0 {
		return c.OrganizationIDs
	}

	if c.OrganizationID != "" {
		return []string{c.OrganizationID}
	}

	return nil
}

// CanAccessOrg reports whether the caller is authorized to access orgID
func (c *Caller) CanAccessOrg(orgID string) bool {
	return slices.Contains(c.OrgIDs(), orgID)
}

// SubjectType returns the FGA subject type for this caller based on the authentication type.
// Returns UserSubjectType for JWT/PAT callers and ServiceSubjectType for API token callers.
func (c *Caller) SubjectType() string {
	switch c.AuthenticationType {
	case JWTAuthentication, PATAuthentication:
		return UserSubjectType
	case APITokenAuthentication:
		return ServiceSubjectType
	default:
		return ""
	}
}

// IsImpersonated reports whether this Caller is acting on behalf of another user
func (c *Caller) IsImpersonated() bool {
	return c.Impersonation != nil
}

// IsAnonymous reports whether this Caller is an anonymous user (trust center visitor,
// questionnaire respondent, etc.) with no standard authentication type
func (c *Caller) IsAnonymous() bool {
	return c.OrganizationRole == AnonymousRole
}

// WithCapabilities returns a copy of the Caller with the given capabilities added
func (c *Caller) WithCapabilities(caps Capability) *Caller {
	cp := *c
	cp.Capabilities |= caps

	return &cp
}

// WithoutCapabilities returns a copy of the Caller with the given capabilities removed
func (c *Caller) WithoutCapabilities(caps Capability) *Caller {
	cp := *c
	cp.Capabilities &^= caps

	return &cp
}

// NewWebhookCaller returns a Caller for an inbound webhook delivery.
// Bypasses org-filter and FGA checks.
func NewWebhookCaller(orgID string) *Caller {
	return &Caller{
		OrganizationID: orgID,
		Capabilities:   CapBypassOrgFilter | CapBypassFGA | CapInternalOperation,
	}
}

// NewAcmeSolverCaller returns a Caller for an ACME challenge solver request.
// Bypasses org-filter and FGA checks but not feature-flag enforcement.
func NewAcmeSolverCaller(orgID string) *Caller {
	return &Caller{
		OrganizationID: orgID,
		Capabilities:   CapBypassOrgFilter | CapBypassFGA | CapInternalOperation,
	}
}

// newAnonymousCaller constructs an anonymous Caller (trust center, questionnaire, etc.)
// with AnonymousRole and the standard anonymous capability set
func newAnonymousCaller(orgID, subjectID, subjectName, subjectEmail string) *Caller {
	return &Caller{
		SubjectID:        subjectID,
		SubjectName:      subjectName,
		SubjectEmail:     subjectEmail,
		OrganizationID:   orgID,
		OrganizationRole: AnonymousRole,
		Capabilities:     CapBypassOrgFilter | CapBypassFGA | CapBypassSubscriptionCheck,
	}
}

// NewTrustCenterBootstrapCaller returns a Caller for trust center initialization
// before a subject identity is known. Bypasses org-filter and subscription checks.
func NewTrustCenterBootstrapCaller(orgID string) *Caller {
	return newAnonymousCaller(orgID, "", "", "")
}

// NewTrustCenterCaller returns a Caller for an anonymous trust center viewer
// with a resolved identity. Bypasses org-filter, FGA, and subscription checks.
func NewTrustCenterCaller(orgID, subjectID, subjectName, subjectEmail string) *Caller {
	return newAnonymousCaller(orgID, subjectID, subjectName, subjectEmail)
}

// NewQuestionnaireCaller returns a Caller for an anonymous questionnaire respondent.
// Bypasses org-filter, FGA, and subscription checks.
func NewQuestionnaireCaller(orgID, subjectID, subjectName, subjectEmail string) *Caller {
	return newAnonymousCaller(orgID, subjectID, subjectName, subjectEmail)
}

// NewKeystoreCaller returns a Caller for keystore operations.
// Bypasses org-filter, FGA, and feature-flag checks.
func NewKeystoreCaller() *Caller {
	return &Caller{
		Capabilities: CapBypassOrgFilter | CapBypassFGA | CapBypassFeatureCheck | CapInternalOperation,
	}
}

// NewSystemAdminCaller returns a Caller for a system administrator.
// Bypasses org-filter, FGA, and feature-flag checks.
func NewSystemAdminCaller(subjectID, subjectName, subjectEmail string) *Caller {
	return &Caller{
		SubjectID:          subjectID,
		SubjectName:        subjectName,
		SubjectEmail:       subjectEmail,
		AuthenticationType: JWTAuthentication,
		Capabilities:       CapBypassOrgFilter | CapBypassFGA | CapBypassFeatureCheck | CapInternalOperation | CapSystemAdmin,
	}
}
