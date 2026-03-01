package auth

import (
	"context"
	"slices"

	echo "github.com/theopenlane/echox"
	"github.com/theopenlane/utils/ulids"
)

const (
	// UserSubjectType is the subject type for user accounts
	UserSubjectType = "user"
	// ServiceSubjectType is the subject type for service accounts
	ServiceSubjectType = "service"
)

// GetAuthzSubjectType returns the subject type based on the authentication type
func GetAuthzSubjectType(ctx context.Context) string {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ""
	}

	return caller.SubjectType()
}

// GetSubjectIDFromContext returns the actor subject from the context
// In most cases this will be the user ID, but in the case of an API token it will be the token ID
func GetSubjectIDFromContext(ctx context.Context) (string, error) {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return "", ErrNoAuthUser
	}

	uid, err := ulids.Parse(caller.SubjectID)
	if err != nil {
		return "", err
	}

	if ulids.IsZero(uid) {
		return "", ErrNoAuthUser
	}

	return caller.SubjectID, nil
}

// GetOrganizationIDFromContext returns the organization ID from context
func GetOrganizationIDFromContext(ctx context.Context) (string, error) {
	var orgID string

	if caller, ok := CallerFromContext(ctx); ok && caller != nil {
		id, orgOk := caller.ActiveOrg()
		if !orgOk {
			return "", ErrNoAuthUser
		}

		orgID = id
	} else {
		return "", ErrNoAuthUser
	}

	oID, err := ulids.Parse(orgID)
	if err != nil {
		return "", err
	}

	if ulids.IsZero(oID) {
		return "", ErrNoAuthUser
	}

	return orgID, nil
}

// GetOrganizationIDsFromContext returns the organization IDs from context
func GetOrganizationIDsFromContext(ctx context.Context) ([]string, error) {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return []string{}, ErrNoAuthUser
	}

	orgIDs := caller.OrgIDs()
	valid := make([]string, 0, len(orgIDs))

	for _, orgID := range orgIDs {
		oID, err := ulids.Parse(orgID)
		if err != nil {
			return []string{}, err
		}

		if !ulids.IsZero(oID) {
			valid = append(valid, orgID)
		}
	}

	return valid, nil
}

// GetAuthTypeFromContext retrieves the authentication type from the context if it was set
func GetAuthTypeFromContext(ctx context.Context) AuthenticationType {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ""
	}

	return caller.AuthenticationType
}

// GetAuthTypeFromEchoContext retrieves the authentication type from the echo context
func GetAuthTypeFromEchoContext(ctx echo.Context) AuthenticationType {
	caller, ok := CallerFromContext(ctx.Request().Context())
	if !ok || caller == nil {
		return ""
	}

	return caller.AuthenticationType
}

// IsAPITokenAuthentication returns true if the authentication type is API token
// this is used to determine if the request is from a service account
func IsAPITokenAuthentication(ctx context.Context) bool {
	return GetAuthTypeFromContext(ctx) == APITokenAuthentication
}

// SetOrganizationIDInAuthContext sets the organization ID in the auth context
// this should only be used when creating a new organization and subsequent updates
// need to happen in the context of the new organization
func SetOrganizationIDInAuthContext(ctx context.Context, orgID string) (context.Context, error) {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ctx, ErrNoAuthUser
	}

	caller.OrganizationID = orgID

	return WithCaller(ctx, caller), nil
}

// ResolveOrganizationForContext resolves and sets the active organization ID in the context.
// If inputOrgID is nil, it falls back to the single authorized org (e.g., for API tokens with one org).
// Returns ErrNoOrganizationID if no org can be resolved, or ErrUnauthorizedOrg if the
// provided org is not in the caller's authorized list.
func ResolveOrganizationForContext(ctx context.Context, inputOrgID *string) (context.Context, error) {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ctx, ErrNoAuthUser
	}

	if inputOrgID == nil {
		orgIDs := caller.OrgIDs()
		if len(orgIDs) != 1 || orgIDs[0] == "" {
			return ctx, ErrNoOrganizationID
		}

		caller.OrganizationID = orgIDs[0]

		return WithCaller(ctx, caller), nil
	}

	if !slices.Contains(caller.OrgIDs(), *inputOrgID) {
		return ctx, ErrUnauthorizedOrg
	}

	caller.OrganizationID = *inputOrgID

	return WithCaller(ctx, caller), nil
}

// AddOrganizationIDToContext appends an authorized organization ID to the context.
// This generally should not be used, as the authorized organization should be
// determined by the claims or the token. This is only used in cases where the
// a user is newly authorized to an organization and the organization ID is not
// in the token claims
func AddOrganizationIDToContext(ctx context.Context, orgID string) (context.Context, error) {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ctx, ErrNoAuthUser
	}

	caller.OrganizationIDs = append(caller.OrganizationIDs, orgID)

	return WithCaller(ctx, caller), nil
}

// GetSubscriptionFromContext returns the active subscription from the context
func GetSubscriptionFromContext(ctx context.Context) bool {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return false
	}

	return caller.ActiveSubscription
}

// IsSystemAdminFromContext checks if the user is a system admin
func IsSystemAdminFromContext(ctx context.Context) bool {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return false
	}

	return caller.Has(CapSystemAdmin)
}

// HasFullOrgWriteAccessFromContext checks if the user has full write access to the organization
// This is true for owners and super admins; admins will have limited write access depending on the resource
// so authorization checks should be done at the resource level as needed
func HasFullOrgWriteAccessFromContext(ctx context.Context) bool {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return false
	}

	return caller.OrganizationRole.HasFullWriteAccess()
}
