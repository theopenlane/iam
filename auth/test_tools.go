package auth

import (
	"context"

	"github.com/theopenlane/echox/middleware/echocontext"
	"github.com/theopenlane/utils/contextx"
	"github.com/theopenlane/utils/ulids"
)

// CallerOption configures a Caller built for use in test contexts.
type CallerOption func(*Caller)

// WithOrganizationRole sets the OrganizationRole on the test Caller.
func WithOrganizationRole(role OrganizationRoleType) CallerOption {
	return func(c *Caller) {
		c.OrganizationRole = role
	}
}

// WithCapabilities adds the given capabilities to the test Caller.
func WithCapabilities(caps Capability) CallerOption {
	return func(c *Caller) {
		c.Capabilities |= caps
	}
}

// WithActiveSubscription sets the ActiveSubscription flag on the test Caller.
func WithActiveSubscription(active bool) CallerOption {
	return func(c *Caller) {
		c.ActiveSubscription = active
	}
}

// NewTestContextWithOrgID creates a context with the given subject and org ID for testing purposes only.
// Optional CallerOption values are applied after the base Caller is constructed, allowing callers to
// set OrganizationRole, Capabilities, ActiveSubscription, or any other Caller field.
func NewTestContextWithOrgID(sub, orgID string, opts ...CallerOption) context.Context {
	ec := echocontext.NewTestEchoContext()

	caller := &Caller{
		SubjectID:          sub,
		OrganizationID:     orgID,
		OrganizationIDs:    []string{orgID},
		AuthenticationType: JWTAuthentication,
	}

	for _, opt := range opts {
		opt(caller)
	}

	ctx := WithCaller(ec.Request().Context(), caller)
	ctx = contextx.With(ctx, ec)

	ec.SetRequest(ec.Request().WithContext(ctx))

	return ctx
}

// NewTestContextWithValidUser creates a context with a fixed org placeholder for testing purposes only.
// It is equivalent to NewTestContextWithOrgID(subject, "ulid_id_of_org", opts...).
func NewTestContextWithValidUser(subject string, opts ...CallerOption) context.Context {
	return NewTestContextWithOrgID(subject, "ulid_id_of_org", opts...)
}

// NewTestContextForSystemAdmin creates a context with system admin capabilities set for testing purposes only.
// Capabilities match NewSystemAdminCaller: CapBypassOrgFilter, CapBypassFGA, CapBypassFeatureCheck, CapInternalOperation, CapSystemAdmin.
func NewTestContextForSystemAdmin(sub, orgID string, opts ...CallerOption) context.Context {
	caps := CapBypassOrgFilter | CapBypassFGA | CapBypassFeatureCheck | CapInternalOperation | CapSystemAdmin
	return NewTestContextWithOrgID(sub, orgID, append([]CallerOption{WithCapabilities(caps)}, opts...)...)
}

// NewTestContextWithSubscription creates a context with random subject/org IDs and the given
// ActiveSubscription value for testing purposes only.
func NewTestContextWithSubscription(subscription bool, opts ...CallerOption) context.Context {
	return NewTestContextWithOrgID(
		ulids.New().String(),
		ulids.New().String(),
		append([]CallerOption{WithActiveSubscription(subscription)}, opts...)...,
	)
}
