package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/auth"
)

func TestCallerHasAny(t *testing.T) {
	c := &auth.Caller{Capabilities: auth.CapBypassOrgFilter}

	assert.True(t, c.HasAny(auth.CapBypassOrgFilter|auth.CapSystemAdmin))
	assert.False(t, c.HasAny(auth.CapSystemAdmin|auth.CapBypassFGA))
}

func TestCallerHasInLineage(t *testing.T) {
	tests := []struct {
		name   string
		caller *auth.Caller
		want   bool
	}{
		{name: "nil caller", caller: nil, want: false},
		{name: "held directly", caller: &auth.Caller{Capabilities: auth.CapSystemAdmin}, want: true},
		{name: "held by original system admin", caller: &auth.Caller{OriginalSystemAdmin: &auth.Caller{Capabilities: auth.CapSystemAdmin}}, want: true},
		{name: "not held", caller: &auth.Caller{Capabilities: auth.CapBypassFGA}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.caller.HasInLineage(auth.CapSystemAdmin))
		})
	}
}

func TestWithCapabilitiesReturnsCopy(t *testing.T) {
	original := &auth.Caller{SubjectID: "user-1", Capabilities: auth.CapBypassFGA}

	updated := original.WithCapabilities(auth.CapInternalOperation)

	assert.False(t, original.Has(auth.CapInternalOperation))
	assert.True(t, updated.Has(auth.CapBypassFGA|auth.CapInternalOperation))
	assert.Equal(t, "user-1", updated.SubjectID)
}

func TestWithoutCapabilitiesReturnsCopy(t *testing.T) {
	original := &auth.Caller{Capabilities: auth.CapBypassFGA | auth.CapInternalOperation}

	updated := original.WithoutCapabilities(auth.CapInternalOperation)

	assert.True(t, original.Has(auth.CapInternalOperation))
	assert.False(t, updated.Has(auth.CapInternalOperation))
	assert.True(t, updated.Has(auth.CapBypassFGA))
}

func TestWithCallerCapabilitiesCreatesCallerWhenMissing(t *testing.T) {
	c, ok := auth.CallerFromContext(auth.WithCallerCapabilities(context.Background(), auth.CapInternalOperation))
	require.True(t, ok)

	assert.True(t, c.Has(auth.CapInternalOperation))
	assert.Empty(t, c.SubjectID)
}

func TestWithInternalOperationContextKeepsCallerIdentity(t *testing.T) {
	original := &auth.Caller{SubjectID: "user-1", OrganizationID: "org-1", OrganizationIDs: []string{"org-1"}}

	c, ok := auth.CallerFromContext(auth.WithInternalOperationContext(auth.WithCaller(context.Background(), original)))
	require.True(t, ok)

	assert.Equal(t, "user-1", c.SubjectID)
	assert.Equal(t, "org-1", c.OrganizationID)
	assert.True(t, c.Has(auth.CapInternalOperation))
	assert.False(t, c.Has(auth.CapBypassOrgFilter))
	assert.False(t, original.Has(auth.CapInternalOperation))
}

func TestWithInternalCrossOrgContext(t *testing.T) {
	c, ok := auth.CallerFromContext(auth.WithInternalCrossOrgContext(auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "user-1"})))
	require.True(t, ok)

	assert.True(t, c.Has(auth.CapInternalOperation|auth.CapBypassOrgFilter))
}

func TestWithCallerReplacesCapabilities(t *testing.T) {
	ctx := auth.WithInternalOperationContext(context.Background())
	ctx = auth.WithCaller(ctx, &auth.Caller{SubjectID: "user-1"})

	assert.False(t, auth.IsInternalRequest(ctx))
}

func TestWithOrganizationBootstrapCapabilities(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		wantSubject string
	}{
		{name: "no caller", ctx: context.Background(), wantSubject: ""},
		{name: "existing caller", ctx: auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "user-1"}), wantSubject: "user-1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, ok := auth.CallerFromContext(auth.WithOrganizationBootstrapCapabilities(tc.ctx))
			require.True(t, ok)

			assert.True(t, c.Has(auth.CapabilitiesForOrgBootstrap()))
			assert.Equal(t, tc.wantSubject, c.SubjectID)
		})
	}
}

func TestWithOrgInternalCallerDropsUser(t *testing.T) {
	ctx := auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "user-1", Capabilities: auth.CapSystemAdmin})

	c, ok := auth.CallerFromContext(auth.WithOrgInternalCaller(ctx, "org-1"))
	require.True(t, ok)

	assert.Empty(t, c.SubjectID)
	assert.Equal(t, "org-1", c.OrganizationID)
	assert.Equal(t, auth.CapInternalOperation, c.Capabilities)
}

func TestWithSystemSweepContext(t *testing.T) {
	c, ok := auth.CallerFromContext(auth.WithSystemSweepContext(context.Background()))
	require.True(t, ok)

	assert.Equal(t, auth.CapSystemSweep, c.Capabilities)
}

func TestCapabilitiesForSystemAdmin(t *testing.T) {
	assert.Equal(t, auth.CapSystemAdmin|auth.CapBypassOrgFilter, auth.CapabilitiesForSystemAdmin(true))
	assert.Equal(t, auth.Capability(0), auth.CapabilitiesForSystemAdmin(false))
}

func TestContextCapabilityChecks(t *testing.T) {
	tests := []struct {
		name             string
		ctx              context.Context
		wantInternal     bool
		wantCrossOrg     bool
		wantFullSystem   bool
		wantLineageAdmin bool
	}{
		{
			name: "no caller",
			ctx:  context.Background(),
		},
		{
			name:         "internal operation",
			ctx:          auth.WithCaller(context.Background(), &auth.Caller{Capabilities: auth.CapInternalOperation}),
			wantInternal: true,
		},
		{
			name:         "org filter bypass",
			ctx:          auth.WithCaller(context.Background(), &auth.Caller{Capabilities: auth.CapBypassOrgFilter}),
			wantCrossOrg: true,
		},
		{
			name:             "system admin",
			ctx:              auth.WithCaller(context.Background(), &auth.Caller{Capabilities: auth.CapSystemAdmin}),
			wantCrossOrg:     true,
			wantLineageAdmin: true,
		},
		{
			name:           "system sweep",
			ctx:            auth.WithSystemSweepContext(context.Background()),
			wantInternal:   true,
			wantCrossOrg:   true,
			wantFullSystem: true,
		},
		{
			name:             "impersonating system admin",
			ctx:              auth.WithCaller(context.Background(), &auth.Caller{OriginalSystemAdmin: &auth.Caller{Capabilities: auth.CapSystemAdmin}}),
			wantLineageAdmin: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantInternal, auth.IsInternalRequest(tc.ctx))
			assert.Equal(t, tc.wantCrossOrg, auth.HasCrossOrgCapabilities(tc.ctx))
			assert.Equal(t, tc.wantFullSystem, auth.HasFullSystemCapabilities(tc.ctx))
			assert.Equal(t, tc.wantLineageAdmin, auth.HasInLineageContextCaller(tc.ctx, auth.CapSystemAdmin))
		})
	}
}

func TestIsInternalRequestDoesNotCreateCaller(t *testing.T) {
	ctx := context.Background()

	auth.IsInternalRequest(ctx)

	_, ok := auth.CallerFromContext(ctx)
	assert.False(t, ok)
}

func TestFromContextOrNew(t *testing.T) {
	empty := auth.FromContextOrNew(context.Background())
	require.NotNil(t, empty)
	assert.Empty(t, empty.SubjectID)

	existing := &auth.Caller{SubjectID: "user-1"}
	assert.Same(t, existing, auth.FromContextOrNew(auth.WithCaller(context.Background(), existing)))
}

func TestCallerFromContextNilCaller(t *testing.T) {
	_, ok := auth.CallerFromContext(auth.WithCaller(context.Background(), nil))

	assert.False(t, ok)
}

func TestWithCallerScopedToOrg(t *testing.T) {
	original := &auth.Caller{SubjectID: "user-1", OrganizationID: "org-1", OrganizationIDs: []string{"org-1", "org-2"}}
	ctx := auth.WithCaller(context.Background(), original)

	scoped, ok := auth.CallerFromContext(auth.WithCallerScopedToOrg(ctx, "org-2"))
	require.True(t, ok)

	assert.Equal(t, "user-1", scoped.SubjectID)
	assert.Equal(t, "org-2", scoped.OrganizationID)
	assert.Equal(t, []string{"org-2"}, scoped.OrganizationIDs)

	assert.Equal(t, "org-1", original.OrganizationID)
	assert.Len(t, original.OrganizationIDs, 2)

	assert.Equal(t, ctx, auth.WithCallerScopedToOrg(ctx, ""))

	_, ok = auth.CallerFromContext(auth.WithCallerScopedToOrg(context.Background(), "org-1"))
	assert.False(t, ok)
}

func TestIsTrustCenterUserCaller(t *testing.T) {
	visitor := auth.NewTrustCenterCaller("org-1", "anon-1", "Visitor", "visitor@example.com")

	tests := []struct {
		name   string
		ctx    context.Context
		wantOK bool
		wantTC string
	}{
		{
			name:   "valid visitor",
			ctx:    auth.ActiveTrustCenterIDKey.Set(auth.WithCaller(context.Background(), visitor), "tc-1"),
			wantOK: true,
			wantTC: "tc-1",
		},
		{
			name: "missing trust center id",
			ctx:  auth.WithCaller(context.Background(), visitor),
		},
		{
			name: "missing email",
			ctx:  auth.ActiveTrustCenterIDKey.Set(auth.WithCaller(context.Background(), auth.NewTrustCenterCaller("org-1", "anon-1", "Visitor", "")), "tc-1"),
		},
		{
			name: "missing org",
			ctx:  auth.ActiveTrustCenterIDKey.Set(auth.WithCaller(context.Background(), auth.NewTrustCenterCaller("", "anon-1", "Visitor", "visitor@example.com")), "tc-1"),
		},
		{
			name: "not a trust center caller",
			ctx:  auth.ActiveTrustCenterIDKey.Set(auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "user-1", SubjectEmail: "user@example.com", OrganizationID: "org-1"}), "tc-1"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, tcID, ok := auth.IsTrustCenterUserCaller(tc.ctx)

			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantTC, tcID)

			if tc.wantOK {
				assert.NotNil(t, c)
			}
		})
	}
}

func TestGetTrustCenterUserCaller(t *testing.T) {
	visitor := auth.NewTrustCenterCaller("org-1", "anon-1", "Visitor", "visitor@example.com")
	ctx := auth.ActiveTrustCenterIDKey.Set(auth.WithCaller(context.Background(), visitor), "tc-1")

	_, ok := auth.GetTrustCenterUserCaller(ctx, "tc-1")
	assert.True(t, ok)

	_, ok = auth.GetTrustCenterUserCaller(ctx, "tc-2")
	assert.False(t, ok)
}

func TestHasOrgAdminAccess(t *testing.T) {
	tests := []struct {
		role auth.OrganizationRoleType
		want bool
	}{
		{role: auth.OwnerRole, want: true},
		{role: auth.SuperAdminRole, want: true},
		{role: auth.AdminRole, want: true},
		{role: auth.MemberRole, want: false},
		{role: auth.AnonymousRole, want: false},
	}

	for _, tc := range tests {
		t.Run(string(tc.role), func(t *testing.T) {
			assert.Equal(t, tc.want, tc.role.HasOrgAdminAccess())
		})
	}
}

func TestIsUserlessContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{name: "no caller", ctx: context.Background(), want: false},
		{name: "user", ctx: auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "user-1", AuthenticationType: auth.JWTAuthentication}), want: false},
		{name: "api token", ctx: auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "token-1", AuthenticationType: auth.APITokenAuthentication}), want: true},
		{name: "org support", ctx: auth.WithCaller(context.Background(), auth.NewOrgSupportCaller("org-1", "support-1", "Support", "support@example.com")), want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, auth.IsUserlessContext(tc.ctx))
		})
	}
}

func TestIsImpersonatedCallerContext(t *testing.T) {
	impersonated := &auth.Caller{SubjectID: "user-1", Impersonation: &auth.ImpersonationContext{ImpersonatorID: "admin-1"}}

	id, ok := auth.IsImpersonatedCallerContext(auth.WithCaller(context.Background(), impersonated))
	assert.True(t, ok)
	assert.Equal(t, "admin-1", id)

	_, ok = auth.IsImpersonatedCallerContext(auth.WithCaller(context.Background(), &auth.Caller{SubjectID: "user-1"}))
	assert.False(t, ok)

	_, ok = auth.IsImpersonatedCallerContext(context.Background())
	assert.False(t, ok)
}
