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
	} else if anon, ok := ContextValue(ctx, AnonymousTrustCenterUserKey); ok {
		orgID = anon.OrganizationID
	} else if anon, ok := ContextValue(ctx, AnonymousQuestionnaireUserKey); ok {
		orgID = anon.OrganizationID
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
	var orgIDs []string
	if caller, ok := CallerFromContext(ctx); ok && caller != nil {
		orgIDs = caller.OrgIDs()
	} else if anon, ok := ContextValue(ctx, AnonymousTrustCenterUserKey); ok {
		orgIDs = []string{anon.OrganizationID}
	} else if anon, ok := ContextValue(ctx, AnonymousQuestionnaireUserKey); ok {
		orgIDs = []string{anon.OrganizationID}
	} else {
		return []string{}, ErrNoAuthUser
	}

	for _, orgID := range orgIDs {
		oID, err := ulids.Parse(orgID)
		if err != nil {
			return []string{}, err
		}

		if ulids.IsZero(oID) {
			orgIDs = slices.DeleteFunc(orgIDs, func(s string) bool {
				return s == orgID
			})
		}
	}

	return orgIDs, nil
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
func SetOrganizationIDInAuthContext(ctx context.Context, orgID string) error {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ErrNoAuthUser
	}

	caller.OrganizationID = orgID

	WithCaller(ctx, caller)

	return nil
}

// AddOrganizationIDToContext appends an authorized organization ID to the context.
// This generally should not be used, as the authorized organization should be
// determined by the claims or the token. This is only used in cases where the
// a user is newly authorized to an organization and the organization ID is not
// in the token claims
func AddOrganizationIDToContext(ctx context.Context, orgID string) error {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ErrNoAuthUser
	}

	caller.OrganizationIDs = append(caller.OrganizationIDs, orgID)

	WithCaller(ctx, caller)

	return nil
}

// AddSubscriptionToContext appends a subscription to the context
func AddSubscriptionToContext(ctx context.Context, subscription bool) error {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ErrNoAuthUser
	}

	caller.ActiveSubscription = subscription

	WithCaller(ctx, caller)

	return nil
}

// GetSubscriptionFromContext returns the active subscription from the context
func GetSubscriptionFromContext(ctx context.Context) bool {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return false
	}

	return caller.ActiveSubscription
}

// SetSystemAdminInContext sets the system admin flag in the context
func SetSystemAdminInContext(ctx context.Context, isAdmin bool) error {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ErrNoAuthUser
	}

	if isAdmin {
		caller.Capabilities |= CapSystemAdmin
	} else {
		caller.Capabilities &^= CapSystemAdmin
	}

	WithCaller(ctx, caller)

	return nil
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

	return caller.OrganizationRole == OwnerRole || caller.OrganizationRole == SuperAdminRole
}

// GetRoleFromContext returns the organization role from the context
func GetRoleFromContext(ctx context.Context) OrganizationRoleType {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ""
	}

	return caller.OrganizationRole
}

// SetOrganizationRoleInContext sets the organization role in the context
func SetOrganizationRoleInContext(ctx context.Context, role OrganizationRoleType) error {
	caller, ok := CallerFromContext(ctx)
	if !ok || caller == nil {
		return ErrNoAuthUser
	}

	caller.OrganizationRole = role

	WithCaller(ctx, caller)

	return nil
}
