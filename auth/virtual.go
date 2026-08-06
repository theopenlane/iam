package auth

import "context"

// Stable, statically assigned virtual identities used for record attribution when no real user performs an action
const (
	// SupportSubjectID is the stable subject id of the virtual support identity
	SupportSubjectID = "01JSPPRT000000000000000000"
	// SupportDisplayName is the display name of the virtual support identity
	SupportDisplayName = "Openlane Support"
	// SupportEmail is the email of the virtual support identity
	SupportEmail = "support@theopenlane.io"

	// IntegrationSubjectID is the stable subject id of the virtual integration actor
	IntegrationSubjectID = "01JNTGACTR0000000000000000"
	// IntegrationDisplayName is the display name of the virtual integration actor
	IntegrationDisplayName = "Openlane Integrations"
	// IntegrationEmail is the email of the virtual integration actor
	IntegrationEmail = "integrations@theopenlane.io"
)

// EnsureCallerOrg returns ctx with orgID as the caller's active organization when the caller has none
func EnsureCallerOrg(ctx context.Context, orgID string) context.Context {
	if orgID == "" {
		return ctx
	}

	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ctx
	}

	if _, hasOrg := caller.ActiveOrg(); hasOrg {
		return ctx
	}

	scoped := *caller
	scoped.OrganizationID = orgID
	scoped.OrganizationIDs = append([]string{orgID}, caller.OrgIDs()...)

	return WithCaller(ctx, &scoped)
}

// NewIntegrationCaller returns a Caller for the virtual integration user
func NewIntegrationCaller(orgID string) *Caller {
	return &Caller{
		SubjectID:      IntegrationSubjectID,
		SubjectName:    IntegrationDisplayName,
		SubjectEmail:   IntegrationEmail,
		OrganizationID: orgID,
		Capabilities:   CapIntegrationActor | CapBypassOrgFilter | CapBypassFGA | CapInternalOperation | CapBypassAuditLog,
	}
}

// EnsureIntegrationCaller fills the integration actor identity on subject-less callers, retaining attributed ones, granting audit-log bypass either way so integration-driven
// writes skip history tables
func EnsureIntegrationCaller(ctx context.Context, orgID string) context.Context {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return WithCaller(ctx, NewIntegrationCaller(orgID))
	}

	if caller.SubjectID != "" {
		attributed := *caller
		attributed.Capabilities |= CapBypassAuditLog

		return EnsureCallerOrg(WithCaller(ctx, &attributed), orgID)
	}

	attributed := *caller
	attributed.SubjectID = IntegrationSubjectID
	attributed.SubjectName = IntegrationDisplayName
	attributed.SubjectEmail = IntegrationEmail
	attributed.Capabilities |= CapIntegrationActor | CapBypassAuditLog

	return EnsureCallerOrg(WithCaller(ctx, &attributed), orgID)
}
