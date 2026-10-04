package auth

import (
	"context"
	"slices"
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

// IsImpersonatedCallerContext reports whether the caller in context is acting on behalf of another user and returns the user ID doing the impersonation
func IsImpersonatedCallerContext(ctx context.Context) (string, bool) {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return "", false
	}

	if c.Impersonation == nil {
		return "", false
	}

	return c.Impersonation.ImpersonatorID, true
}

// IsAnonymous reports whether this Caller is an anonymous user (trust center visitor,
// questionnaire respondent, etc.) with no standard authentication type
func (c *Caller) IsAnonymous() bool {
	return c.OrganizationRole == AnonymousRole
}

// IsTrustCenter reports whether this Caller is an anonymous trust center visitor
func (c *Caller) IsTrustCenter() bool {
	return c.IsAnonymous() && c.Has(CapTrustCenterAnonymous)
}

// IsQuestionnaire reports whether this Caller is an anonymous questionnaire respondent
func (c *Caller) IsQuestionnaire() bool {
	return c.IsAnonymous() && c.Has(CapQuestionnaireAnonymous)
}

// newAnonymousCaller constructs an anonymous Caller (trust center, questionnaire, etc.)
// with AnonymousRole and the standard anonymous capability set
func newAnonymousCaller(orgID, subjectID, subjectName, subjectEmail string, additionalCaps ...Capability) *Caller {
	additionalCaps = append(additionalCaps, CapBypassFeatureCheck)

	return &Caller{
		SubjectID:        subjectID,
		SubjectName:      subjectName,
		SubjectEmail:     subjectEmail,
		OrganizationID:   orgID,
		OrganizationRole: AnonymousRole,
		Capabilities:     mergeCapabilities(additionalCaps),
	}
}

// NewOrgInternalCaller returns a new caller with no user, one org, and internal operation:
// skips privacy, FGA, module, and edge checks, reads only that org's rows, and new rows are owned by that org
func NewOrgInternalCaller(orgID string) *Caller {
	return &Caller{
		OrganizationID: orgID,
		Capabilities:   CapInternalOperation,
	}
}

// NewTrustCenterBootstrapCaller returns a Caller for trust center initialization
// before a subject identity is known. Bypasses subscription checks.
func NewTrustCenterBootstrapCaller(orgID string) *Caller {
	return newAnonymousCaller(orgID, "", "", "", CapTrustCenterAnonymous)
}

// NewAnonBootstrapCallerOrgBypass returns an anon caller
// with org bypass and subscription bypass that can be used
// for anon callers before authorization to issue the JWT
func NewAnonBootstrapCallerOrgBypass() *Caller {
	return newAnonymousCaller("", "", "", "", CapBypassOrgFilter)
}

// NewTrustCenterCaller returns a Caller for an anonymous trust center viewer
// with a resolved identity. Bypasses subscription checks.
func NewTrustCenterCaller(orgID, subjectID, subjectName, subjectEmail string) *Caller {
	return newAnonymousCaller(orgID, subjectID, subjectName, subjectEmail, CapTrustCenterAnonymous)
}

// NewQuestionnaireCaller returns a Caller for an anonymous questionnaire respondent.
// Bypasses subscription checks.
func NewQuestionnaireCaller(orgID, subjectID, subjectName, subjectEmail string) *Caller {
	return newAnonymousCaller(orgID, subjectID, subjectName, subjectEmail, CapQuestionnaireAnonymous)
}

// NewOrgSupportCaller returns a Caller for an org-scoped support session within orgID.
// Keeps the org filter and owner assignment; bypasses feature-flag and subscription checks.
func NewOrgSupportCaller(orgID, subjectID, subjectName, subjectEmail string) *Caller {
	return &Caller{
		SubjectID:          subjectID,
		SubjectName:        subjectName,
		SubjectEmail:       subjectEmail,
		OrganizationID:     orgID,
		OrganizationIDs:    []string{orgID},
		AuthenticationType: JWTAuthentication,
		Capabilities:       CapabilitiesForSupportCaller(),
	}
}

// NewSystemAdminCaller returns a Caller for a system administrator.
// Capabilities match CapabilitiesForSystemAdmin
func NewSystemAdminCaller(subjectID, subjectName, subjectEmail string) *Caller {
	return &Caller{
		SubjectID:          subjectID,
		SubjectName:        subjectName,
		SubjectEmail:       subjectEmail,
		AuthenticationType: JWTAuthentication,
		Capabilities:       CapabilitiesForSystemAdmin(true),
	}
}

// NewKeystoreCaller returns a Caller for keystore operations.
// Bypasses org-filter, FGA, and feature-flag checks.
//
// Deprecated: will be removed in a future PR
func NewKeystoreCaller() *Caller {
	return &Caller{
		Capabilities: CapBypassOrgFilter | CapBypassFeatureCheck | CapInternalOperation,
	}
}

// NewWebhookCaller returns a Caller for an inbound webhook delivery.
// Bypasses org-filter and FGA checks.
//
// Deprecated: will be removed in a future PR
func NewWebhookCaller(orgID string) *Caller {
	return &Caller{
		OrganizationID: orgID,
		Capabilities:   CapBypassOrgFilter | CapInternalOperation,
	}
}

// NewAcmeSolverCaller returns a Caller for an ACME challenge solver request.
// Bypasses org-filter and FGA checks but not feature-flag enforcement.
//
// Deprecated: will be removed in a future PR
func NewAcmeSolverCaller(orgID string) *Caller {
	return &Caller{
		OrganizationID: orgID,
		Capabilities:   CapBypassOrgFilter | CapInternalOperation,
	}
}
