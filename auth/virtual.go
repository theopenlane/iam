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
	if !ok {
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

// WithCallerScopedToOrg returns ctx with a copy of the caller scoped to orgID as its only organization
// it does not verify membership, callers must check the subject belongs to orgID first
func WithCallerScopedToOrg(ctx context.Context, orgID string) context.Context {
	caller, ok := CallerFromContext(ctx)
	if !ok || orgID == "" {
		return ctx
	}

	scoped := *caller
	scoped.OrganizationID = orgID
	scoped.OrganizationIDs = []string{orgID}

	return WithCaller(ctx, &scoped)
}

// NewIntegrationCaller returns a Caller for the virtual integration user
func NewIntegrationCaller(orgID string) *Caller {
	return &Caller{
		SubjectID:      IntegrationSubjectID,
		SubjectName:    IntegrationDisplayName,
		SubjectEmail:   IntegrationEmail,
		OrganizationID: orgID,
		Capabilities:   CapIntegrationActor | CapBypassOrgFilter | CapInternalOperation | CapBypassAuditLog,
	}
}

// EnsureIntegrationCaller replaces the caller with the integration actor pinned to orgID so integration runs never act with a user's identity or role,
// granting audit-log bypass so integration-driven writes skip history tables
func EnsureIntegrationCaller(ctx context.Context, orgID string) context.Context {
	caller, ok := CallerFromContext(ctx)
	if !ok {
		return WithCaller(ctx, NewIntegrationCaller(orgID))
	}

	attributed := *caller
	attributed.SubjectID = IntegrationSubjectID
	attributed.SubjectName = IntegrationDisplayName
	attributed.SubjectEmail = IntegrationEmail

	// clear organization role from original caller
	attributed.OrganizationRole = ""

	// because we are acting on behalf of the org and not as a user, we need to set CapInternalOperation
	attributed.Capabilities |= CapIntegrationActor | CapInternalOperation | CapBypassAuditLog

	if orgID != "" {
		attributed.OrganizationID = orgID
		attributed.OrganizationIDs = []string{orgID}
	}

	return WithCaller(ctx, &attributed)
}
