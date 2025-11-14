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

// GetAuthenticatedUserFromContext attempts to retrieve the authenticated user from the context
// and will return an error if the user is not found
func GetAuthenticatedUserFromContext(ctx context.Context) (*AuthenticatedUser, error) {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return nil, ErrNoAuthUser
	}

	return au, nil
}

// GetAuthzSubjectType returns the subject type based on the authentication type
func GetAuthzSubjectType(ctx context.Context) string {
	switch GetAuthTypeFromContext(ctx) {
	case JWTAuthentication, PATAuthentication:
		return UserSubjectType
	case APITokenAuthentication:
		return ServiceSubjectType
	default:
		// if there is no authenticated user an empty string is returned
		return ""
	}
}

// GetSubjectIDFromContext returns the actor subject from the context
// In most cases this will be the user ID, but in the case of an API token it will be the token ID
func GetSubjectIDFromContext(ctx context.Context) (string, error) {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return "", ErrNoAuthUser
	}

	uid, err := ulids.Parse(au.SubjectID)
	if err != nil {
		return "", err
	}

	if ulids.IsZero(uid) {
		return "", ErrNoAuthUser
	}

	return au.SubjectID, nil
}

// GetOrganizationIDFromContext returns the organization ID from context
func GetOrganizationIDFromContext(ctx context.Context) (string, error) {
	var orgID string
	if anon, ok := AnonymousTrustCenterUserFromContext(ctx); ok {
		orgID = anon.OrganizationID
	} else if anon, ok := AnonymousQuestionnaireUserFromContext(ctx); ok {
		orgID = anon.OrganizationID
	} else {
		au, ok := AuthenticatedUserFromContext(ctx)
		if !ok || au == nil {
			return "", ErrNoAuthUser
		}

		orgID = au.OrganizationID
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

// GetOrganizationIDFromContext returns the organization ID from context
func GetOrganizationIDsFromContext(ctx context.Context) ([]string, error) {
	var orgIDs []string
	if anon, ok := AnonymousTrustCenterUserFromContext(ctx); ok {
		orgIDs = []string{anon.OrganizationID}
	} else if anon, ok := AnonymousQuestionnaireUserFromContext(ctx); ok {
		orgIDs = []string{anon.OrganizationID}
	} else {
		au, ok := AuthenticatedUserFromContext(ctx)
		if !ok || au == nil {
			return []string{}, ErrNoAuthUser
		}

		orgIDs = au.OrganizationIDs
	}

	// validate the organization IDs
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

// GetAuthTypeFromEchoContext retrieves the authentication type from the context if it was set
func GetAuthTypeFromContext(ctx context.Context) AuthenticationType {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return ""
	}

	return au.AuthenticationType
}

// GetAuthTypeFromEchoContext retrieves the authentication type from the context
func GetAuthTypeFromEchoContext(ctx echo.Context) AuthenticationType {
	au, ok := AuthenticatedUserFromContext(ctx.Request().Context())
	if !ok || au == nil {
		return ""
	}

	return au.AuthenticationType
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
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return ErrNoAuthUser
	}

	au.OrganizationID = orgID

	WithAuthenticatedUser(ctx, au)

	return nil
}

// AddOrganizationIDToContext appends an authorized organization ID to the context.
// This generally should not be used, as the authorized organization should be
// determined by the claims or the token. This is only used in cases where the
// a user is newly authorized to an organization and the organization ID is not
// in the token claims
func AddOrganizationIDToContext(ctx context.Context, orgID string) error {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return ErrNoAuthUser
	}

	// append the organization ID to the list of organization IDs
	au.OrganizationIDs = append(au.OrganizationIDs, orgID)

	WithAuthenticatedUser(ctx, au)

	return nil
}

// AddSubscriptionToContext appends a subscription to the context
func AddSubscriptionToContext(ctx context.Context, subscription bool) error {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return ErrNoAuthUser
	}

	au.ActiveSubscription = subscription

	WithAuthenticatedUser(ctx, au)

	return nil
}

// GetSubscriptionFromContext returns the active subscription from the context
func GetSubscriptionFromContext(ctx context.Context) bool {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return false
	}

	return au.ActiveSubscription
}

// SetSystemAdminInContext sets the system admin flag in the context
func SetSystemAdminInContext(ctx context.Context, isAdmin bool) error {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return ErrNoAuthUser
	}

	au.IsSystemAdmin = isAdmin

	WithAuthenticatedUser(ctx, au)

	return nil
}

// IsSystemAdminFromContext checks if the user is a system admin
func IsSystemAdminFromContext(ctx context.Context) bool {
	au, ok := AuthenticatedUserFromContext(ctx)
	if !ok || au == nil {
		return false
	}

	return au.IsSystemAdmin
}
