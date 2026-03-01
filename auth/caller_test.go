package auth

import (
	"context"
	"testing"
)

// TestCallerHasSingleCap verifies that Has returns true for a cap that is set
// and false for one that is not.
func TestCallerHasSingleCap(t *testing.T) {
	c := &Caller{Capabilities: CapBypassOrgFilter}

	if !c.Has(CapBypassOrgFilter) {
		t.Error("expected CapBypassOrgFilter to be set")
	}

	if c.Has(CapBypassFGA) {
		t.Error("expected CapBypassFGA to be absent")
	}
}

// TestCallerHasMultipleCaps verifies that Has requires all bits in the mask to
// be set, returning false when any one is missing.
func TestCallerHasMultipleCaps(t *testing.T) {
	c := &Caller{Capabilities: CapBypassOrgFilter | CapBypassFGA}

	if !c.Has(CapBypassOrgFilter | CapBypassFGA) {
		t.Error("expected combined check to pass when both caps are set")
	}

	if c.Has(CapBypassOrgFilter | CapBypassFeatureCheck) {
		t.Error("expected combined check to fail when one cap is absent")
	}
}

// TestCallerActiveOrgFromOrganizationID verifies that ActiveOrg returns the
// set OrganizationID when present.
func TestCallerActiveOrgFromOrganizationID(t *testing.T) {
	c := &Caller{OrganizationID: "org-1"}

	got, ok := c.ActiveOrg()
	if !ok {
		t.Fatal("expected ok=true when OrganizationID is set")
	}

	if got != "org-1" {
		t.Errorf("want org-1, got %s", got)
	}
}

// TestCallerActiveOrgFallsBackToSoleOrgID verifies that ActiveOrg returns the
// single entry from OrganizationIDs when OrganizationID is not set.
func TestCallerActiveOrgFallsBackToSoleOrgID(t *testing.T) {
	c := &Caller{OrganizationIDs: []string{"org-1"}}

	got, ok := c.ActiveOrg()
	if !ok {
		t.Fatal("expected ok=true when OrganizationIDs has one entry")
	}

	if got != "org-1" {
		t.Errorf("want org-1, got %s", got)
	}
}

// TestCallerActiveOrgMultipleOrgIDsNoSelection verifies that ActiveOrg returns
// false when OrganizationID is not set and OrganizationIDs has more than one entry.
func TestCallerActiveOrgMultipleOrgIDsNoSelection(t *testing.T) {
	c := &Caller{OrganizationIDs: []string{"org-1", "org-2"}}

	_, ok := c.ActiveOrg()
	if ok {
		t.Error("expected ok=false when multiple OrganizationIDs and no active OrganizationID")
	}
}

// TestCallerActiveOrgEmpty verifies that ActiveOrg returns false for a zero-value Caller.
func TestCallerActiveOrgEmpty(t *testing.T) {
	_, ok := (&Caller{}).ActiveOrg()
	if ok {
		t.Error("expected ok=false for zero-value Caller")
	}
}

// TestCallerOrgIDsFromOrganizationIDs verifies that OrgIDs returns OrganizationIDs
// when set.
func TestCallerOrgIDsFromOrganizationIDs(t *testing.T) {
	c := &Caller{OrganizationIDs: []string{"org-1", "org-2"}}

	got := c.OrgIDs()
	if len(got) != 2 || got[0] != "org-1" || got[1] != "org-2" {
		t.Errorf("want [org-1 org-2], got %v", got)
	}
}

// TestCallerOrgIDsFallsBackToOrganizationID verifies that OrgIDs wraps
// OrganizationID in a slice when OrganizationIDs is empty.
func TestCallerOrgIDsFallsBackToOrganizationID(t *testing.T) {
	c := &Caller{OrganizationID: "org-1"}

	got := c.OrgIDs()
	if len(got) != 1 || got[0] != "org-1" {
		t.Errorf("want [org-1], got %v", got)
	}
}

// TestCallerOrgIDsEmpty verifies that OrgIDs returns nil for a zero-value Caller.
func TestCallerOrgIDsEmpty(t *testing.T) {
	if got := (&Caller{}).OrgIDs(); got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

// TestCallerCanAccessOrgPresent verifies that CanAccessOrg returns true when
// the org is in the caller's authorized set.
func TestCallerCanAccessOrgPresent(t *testing.T) {
	c := &Caller{OrganizationIDs: []string{"org-1", "org-2"}}

	if !c.CanAccessOrg("org-1") {
		t.Error("expected CanAccessOrg=true for org-1")
	}
}

// TestCallerCanAccessOrgAbsent verifies that CanAccessOrg returns false when
// the org is not in the caller's authorized set.
func TestCallerCanAccessOrgAbsent(t *testing.T) {
	c := &Caller{OrganizationIDs: []string{"org-1"}}

	if c.CanAccessOrg("org-2") {
		t.Error("expected CanAccessOrg=false for org-2")
	}
}

// TestCallerCanAccessOrgViaSingleOrganizationID verifies that CanAccessOrg
// works when the org is set only via OrganizationID.
func TestCallerCanAccessOrgViaSingleOrganizationID(t *testing.T) {
	c := &Caller{OrganizationID: "org-1"}

	if !c.CanAccessOrg("org-1") {
		t.Error("expected CanAccessOrg=true when org matches OrganizationID")
	}
}

// TestCallerIsImpersonatedAbsent verifies that IsImpersonated returns false
// when the Impersonation field is nil.
func TestCallerIsImpersonatedAbsent(t *testing.T) {
	if (&Caller{}).IsImpersonated() {
		t.Error("expected IsImpersonated=false when Impersonation is nil")
	}
}

// TestCallerIsImpersonatedPresent verifies that IsImpersonated returns true
// when an ImpersonationContext is attached to the Caller.
func TestCallerIsImpersonatedPresent(t *testing.T) {
	c := &Caller{Impersonation: &ImpersonationContext{}}
	if !c.IsImpersonated() {
		t.Error("expected IsImpersonated=true when Impersonation is set")
	}
}

// TestCallerWithCapabilitiesAdds verifies that WithCapabilities returns a new
// Caller with the additional cap set while leaving the original unchanged.
func TestCallerWithCapabilitiesAdds(t *testing.T) {
	base := &Caller{Capabilities: CapBypassOrgFilter}
	updated := base.WithCapabilities(CapBypassFGA)

	if base.Has(CapBypassFGA) {
		t.Error("WithCapabilities must not mutate the original")
	}

	if !updated.Has(CapBypassOrgFilter) {
		t.Error("WithCapabilities must preserve existing caps")
	}

	if !updated.Has(CapBypassFGA) {
		t.Error("WithCapabilities must add the new cap")
	}
}

// TestCallerWithCapabilitiesIdempotent verifies that applying a cap that is
// already set does not change the Capabilities value.
func TestCallerWithCapabilitiesIdempotent(t *testing.T) {
	base := &Caller{Capabilities: CapBypassOrgFilter}
	updated := base.WithCapabilities(CapBypassOrgFilter)

	if updated.Capabilities != CapBypassOrgFilter {
		t.Errorf("adding an already-set cap must be idempotent, got %d", updated.Capabilities)
	}
}

// TestCallerWithCapabilitiesZero verifies that WithCapabilities(0) returns a
// copy with Capabilities unchanged.
func TestCallerWithCapabilitiesZero(t *testing.T) {
	base := &Caller{Capabilities: CapBypassOrgFilter}
	updated := base.WithCapabilities(0)

	if updated.Capabilities != CapBypassOrgFilter {
		t.Errorf("WithCapabilities(0) must not change caps, got %d", updated.Capabilities)
	}
}

// TestCallerWithCapabilitiesPreservesOtherFields verifies that WithCapabilities
// copies all non-Capabilities fields from the original.
func TestCallerWithCapabilitiesPreservesOtherFields(t *testing.T) {
	base := &Caller{
		SubjectID:      "u1",
		OrganizationID: "org-1",
		Capabilities:   CapBypassOrgFilter | CapSystemAdmin,
	}
	updated := base.WithCapabilities(CapBypassFGA)

	if updated.SubjectID != base.SubjectID {
		t.Errorf("SubjectID: want %s, got %s", base.SubjectID, updated.SubjectID)
	}

	if updated.OrganizationID != base.OrganizationID {
		t.Errorf("OrganizationID: want %s, got %s", base.OrganizationID, updated.OrganizationID)
	}

	if !updated.Has(CapSystemAdmin) {
		t.Error("WithCapabilities must preserve CapSystemAdmin")
	}
}

// TestCallerWithoutCapabilitiesRemoves verifies that WithoutCapabilities returns
// a copy with the specified caps cleared and others preserved.
func TestCallerWithoutCapabilitiesRemoves(t *testing.T) {
	base := &Caller{Capabilities: CapBypassOrgFilter | CapBypassFGA}
	updated := base.WithoutCapabilities(CapBypassFGA)

	if base.Capabilities != CapBypassOrgFilter|CapBypassFGA {
		t.Error("WithoutCapabilities must not mutate the original")
	}

	if updated.Has(CapBypassFGA) {
		t.Error("WithoutCapabilities must remove the specified cap")
	}

	if !updated.Has(CapBypassOrgFilter) {
		t.Error("WithoutCapabilities must preserve other caps")
	}
}

// TestCallerWithoutCapabilitiesIdempotent verifies that removing an absent cap
// leaves Capabilities unchanged.
func TestCallerWithoutCapabilitiesIdempotent(t *testing.T) {
	base := &Caller{Capabilities: CapBypassOrgFilter}
	updated := base.WithoutCapabilities(CapBypassFGA)

	if updated.Capabilities != CapBypassOrgFilter {
		t.Errorf("removing absent cap must be idempotent, got %d", updated.Capabilities)
	}
}

// TestWithCallerAndCallerFromContext verifies that CallerFromContext returns the
// exact pointer stored by WithCaller.
func TestWithCallerAndCallerFromContext(t *testing.T) {
	original := &Caller{SubjectID: "u1", OrganizationID: "org-1"}
	ctx := WithCaller(context.Background(), original)

	got, ok := CallerFromContext(ctx)
	if !ok {
		t.Fatal("expected Caller to be present in context")
	}

	if got != original {
		t.Error("CallerFromContext must return the same pointer that was stored")
	}
}

// TestCallerFromContextAllFields verifies that every field on a Caller survives
// a WithCaller / CallerFromContext round-trip.
func TestCallerFromContextAllFields(t *testing.T) {
	c := &Caller{
		SubjectID:          "u1",
		SubjectName:        "Alice",
		SubjectEmail:       "alice@example.com",
		OrganizationID:     "org-1",
		OrganizationName:   "Acme",
		OrganizationIDs:    []string{"org-1", "org-2"},
		AuthenticationType: JWTAuthentication,
		OrganizationRole:   MemberRole,
		ActiveSubscription: true,
		Capabilities:       CapBypassOrgFilter,
	}

	got, ok := CallerFromContext(WithCaller(context.Background(), c))
	if !ok {
		t.Fatal("expected Caller to be present in context")
	}

	if got.SubjectID != c.SubjectID {
		t.Errorf("SubjectID: want %s, got %s", c.SubjectID, got.SubjectID)
	}

	if got.SubjectName != c.SubjectName {
		t.Errorf("SubjectName: want %s, got %s", c.SubjectName, got.SubjectName)
	}

	if got.SubjectEmail != c.SubjectEmail {
		t.Errorf("SubjectEmail: want %s, got %s", c.SubjectEmail, got.SubjectEmail)
	}

	if got.OrganizationID != c.OrganizationID {
		t.Errorf("OrganizationID: want %s, got %s", c.OrganizationID, got.OrganizationID)
	}

	if got.OrganizationName != c.OrganizationName {
		t.Errorf("OrganizationName: want %s, got %s", c.OrganizationName, got.OrganizationName)
	}

	if len(got.OrganizationIDs) != len(c.OrganizationIDs) {
		t.Errorf("OrganizationIDs length: want %d, got %d", len(c.OrganizationIDs), len(got.OrganizationIDs))
	}

	if got.AuthenticationType != c.AuthenticationType {
		t.Errorf("AuthenticationType: want %s, got %s", c.AuthenticationType, got.AuthenticationType)
	}

	if got.OrganizationRole != c.OrganizationRole {
		t.Errorf("OrganizationRole: want %s, got %s", c.OrganizationRole, got.OrganizationRole)
	}

	if got.ActiveSubscription != c.ActiveSubscription {
		t.Errorf("ActiveSubscription: want %v, got %v", c.ActiveSubscription, got.ActiveSubscription)
	}

	if got.Capabilities != c.Capabilities {
		t.Errorf("Capabilities: want %d, got %d", c.Capabilities, got.Capabilities)
	}
}

// TestWithCallerOverwritesPreviousValue verifies that calling WithCaller a
// second time replaces the previously stored Caller.
func TestWithCallerOverwritesPreviousValue(t *testing.T) {
	first := &Caller{SubjectID: "first"}
	second := &Caller{SubjectID: "second"}

	ctx := WithCaller(context.Background(), first)
	ctx = WithCaller(ctx, second)

	got, ok := CallerFromContext(ctx)
	if !ok {
		t.Fatal("expected Caller to be present in context")
	}

	if got.SubjectID != "second" {
		t.Errorf("expected second Caller to win, got SubjectID=%s", got.SubjectID)
	}
}

// TestCallerFromContextAbsent verifies that CallerFromContext returns false
// when no Caller has been stored in the context.
func TestCallerFromContextAbsent(t *testing.T) {
	_, ok := CallerFromContext(context.Background())
	if ok {
		t.Error("expected ok=false when no Caller is in context")
	}
}

// TestMustCallerFromContextPresent verifies that MustCallerFromContext returns
// the stored Caller without panicking when one is present.
func TestMustCallerFromContextPresent(t *testing.T) {
	c := &Caller{SubjectID: "u1"}
	got := MustCallerFromContext(WithCaller(context.Background(), c))

	if got.SubjectID != "u1" {
		t.Errorf("expected u1, got %s", got.SubjectID)
	}
}

// TestMustCallerFromContextPanicsWhenAbsent verifies that MustCallerFromContext
// panics when no Caller is present in the context.
func TestMustCallerFromContextPanicsWhenAbsent(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when no Caller is in context")
		}
	}()

	MustCallerFromContext(context.Background())
}

// TestWithOriginalSystemAdminCallerRoundTrip verifies storing/retrieving the
// original system admin caller works.
func TestWithOriginalSystemAdminCallerRoundTrip(t *testing.T) {
	original := &Caller{SubjectID: "admin-1", Capabilities: CapSystemAdmin}
	ctx := WithOriginalSystemAdminCaller(context.Background(), original)

	got, ok := OriginalSystemAdminCallerFromContext(ctx)
	if !ok {
		t.Fatal("expected original system admin caller to be present")
	}

	if got != original {
		t.Error("OriginalSystemAdminCallerFromContext must return the same pointer that was stored")
	}
}

// TestOriginalSystemAdminCallerFromContextAbsent verifies false is returned
// when no original admin caller is stored.
func TestOriginalSystemAdminCallerFromContextAbsent(t *testing.T) {
	_, ok := OriginalSystemAdminCallerFromContext(context.Background())
	if ok {
		t.Error("expected ok=false when no original system admin caller is in context")
	}
}

// TestWithOriginalSystemAdminCallerPreservesActiveCaller verifies attaching the
// original admin caller does not replace the active caller identity.
func TestWithOriginalSystemAdminCallerPreservesActiveCaller(t *testing.T) {
	active := &Caller{SubjectID: "user-1"}
	original := &Caller{SubjectID: "admin-1", Capabilities: CapSystemAdmin}

	ctx := WithCaller(context.Background(), active)
	ctx = WithOriginalSystemAdminCaller(ctx, original)

	got, ok := CallerFromContext(ctx)
	if !ok || got == nil {
		t.Fatal("expected active caller to be present")
	}

	if got.SubjectID != "user-1" {
		t.Fatalf("expected active caller subject user-1, got %s", got.SubjectID)
	}

	if !got.HasInLineage(CapSystemAdmin) {
		t.Fatal("expected lineage to include system admin capability")
	}

	if got.Has(CapSystemAdmin) {
		t.Fatal("expected active caller capabilities to remain unchanged")
	}
}

// TestNewWebhookCaller verifies the org scope, required capabilities, and
// explicitly absent capabilities for webhook callers.
func TestNewWebhookCaller(t *testing.T) {
	c := NewWebhookCaller("org-1")

	if c.OrganizationID != "org-1" {
		t.Errorf("OrganizationID: want org-1, got %s", c.OrganizationID)
	}

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapInternalOperation} {
		if !c.Has(cap) {
			t.Errorf("NewWebhookCaller must have cap %d", cap)
		}
	}

	for _, cap := range []Capability{CapBypassFeatureCheck, CapBypassSubscriptionCheck, CapBypassAuditLog, CapBypassManagedGroup} {
		if c.Has(cap) {
			t.Errorf("NewWebhookCaller must not have cap %d", cap)
		}
	}
}

// TestNewAcmeSolverCaller verifies the org scope, required capabilities, and
// that feature-flag enforcement is not bypassed.
func TestNewAcmeSolverCaller(t *testing.T) {
	c := NewAcmeSolverCaller("org-2")

	if c.OrganizationID != "org-2" {
		t.Errorf("OrganizationID: want org-2, got %s", c.OrganizationID)
	}

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapInternalOperation} {
		if !c.Has(cap) {
			t.Errorf("NewAcmeSolverCaller must have cap %d", cap)
		}
	}

	if c.Has(CapBypassFeatureCheck) {
		t.Error("NewAcmeSolverCaller must not have CapBypassFeatureCheck")
	}
}

// TestNewTrustCenterBootstrapCaller verifies the org scope, anonymous role,
// required caps, and absence of CapInternalOperation for pre-identity bootstrap.
func TestNewTrustCenterBootstrapCaller(t *testing.T) {
	c := NewTrustCenterBootstrapCaller("org-3")

	if c.OrganizationID != "org-3" {
		t.Errorf("OrganizationID: want org-3, got %s", c.OrganizationID)
	}

	if c.OrganizationRole != AnonymousRole {
		t.Errorf("OrganizationRole: want %s, got %s", AnonymousRole, c.OrganizationRole)
	}

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapBypassSubscriptionCheck} {
		if !c.Has(cap) {
			t.Errorf("NewTrustCenterBootstrapCaller must have cap %d", cap)
		}
	}

	if c.Has(CapInternalOperation) {
		t.Error("NewTrustCenterBootstrapCaller must not have CapInternalOperation")
	}
}

// TestNewTrustCenterCaller verifies that all identity fields are populated and
// the correct anonymous role and caps are set for a resolved trust center viewer.
func TestNewTrustCenterCaller(t *testing.T) {
	c := NewTrustCenterCaller("org-4", "sub-1", "Carol", "carol@example.com")

	if c.OrganizationID != "org-4" {
		t.Errorf("OrganizationID: want org-4, got %s", c.OrganizationID)
	}

	if c.SubjectID != "sub-1" {
		t.Errorf("SubjectID: want sub-1, got %s", c.SubjectID)
	}

	if c.SubjectName != "Carol" {
		t.Errorf("SubjectName: want Carol, got %s", c.SubjectName)
	}

	if c.SubjectEmail != "carol@example.com" {
		t.Errorf("SubjectEmail: want carol@example.com, got %s", c.SubjectEmail)
	}

	if c.OrganizationRole != AnonymousRole {
		t.Errorf("OrganizationRole: want %s, got %s", AnonymousRole, c.OrganizationRole)
	}

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapBypassSubscriptionCheck} {
		if !c.Has(cap) {
			t.Errorf("NewTrustCenterCaller must have cap %d", cap)
		}
	}
}

// TestNewQuestionnaireCaller verifies that all identity fields are populated and
// the correct anonymous role and caps are set for a questionnaire respondent.
func TestNewQuestionnaireCaller(t *testing.T) {
	c := NewQuestionnaireCaller("org-5", "sub-2", "Dave", "dave@example.com")

	if c.OrganizationID != "org-5" {
		t.Errorf("OrganizationID: want org-5, got %s", c.OrganizationID)
	}

	if c.SubjectID != "sub-2" {
		t.Errorf("SubjectID: want sub-2, got %s", c.SubjectID)
	}

	if c.SubjectName != "Dave" {
		t.Errorf("SubjectName: want Dave, got %s", c.SubjectName)
	}

	if c.SubjectEmail != "dave@example.com" {
		t.Errorf("SubjectEmail: want dave@example.com, got %s", c.SubjectEmail)
	}

	if c.OrganizationRole != AnonymousRole {
		t.Errorf("OrganizationRole: want %s, got %s", AnonymousRole, c.OrganizationRole)
	}

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapBypassSubscriptionCheck} {
		if !c.Has(cap) {
			t.Errorf("NewQuestionnaireCaller must have cap %d", cap)
		}
	}
}

// TestNewKeystoreCaller verifies that the keystore caller has the expected caps
// and is not scoped to any organization.
func TestNewKeystoreCaller(t *testing.T) {
	c := NewKeystoreCaller()

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapBypassFeatureCheck, CapInternalOperation} {
		if !c.Has(cap) {
			t.Errorf("NewKeystoreCaller must have cap %d", cap)
		}
	}

	if _, ok := c.ActiveOrg(); ok {
		t.Error("NewKeystoreCaller must not have an OrganizationID")
	}
}

// TestNewSystemAdminCaller verifies that identity fields, CapSystemAdmin, and
// full bypass caps are set correctly.
func TestNewSystemAdminCaller(t *testing.T) {
	c := NewSystemAdminCaller("u-admin", "Admin User", "admin@example.com")

	if c.SubjectID != "u-admin" {
		t.Errorf("SubjectID: want u-admin, got %s", c.SubjectID)
	}

	if c.SubjectName != "Admin User" {
		t.Errorf("SubjectName: want Admin User, got %s", c.SubjectName)
	}

	if c.SubjectEmail != "admin@example.com" {
		t.Errorf("SubjectEmail: want admin@example.com, got %s", c.SubjectEmail)
	}

	if c.AuthenticationType != JWTAuthentication {
		t.Errorf("AuthenticationType: want %s, got %s", JWTAuthentication, c.AuthenticationType)
	}

	for _, cap := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapBypassFeatureCheck, CapInternalOperation, CapSystemAdmin} {
		if !c.Has(cap) {
			t.Errorf("NewSystemAdminCaller must have cap %d", cap)
		}
	}
}

// TestCapabilityConstantsAreDistinctPowersOfTwo verifies that every Capability
// constant is non-zero, a power of two, and unique — ensuring the bitfield
// remains stable and collision-free across gala JSON snapshots.
func TestCapabilityConstantsAreDistinctPowersOfTwo(t *testing.T) {
	all := []Capability{
		CapBypassOrgFilter,
		CapBypassFeatureCheck,
		CapBypassFGA,
		CapBypassManagedGroup,
		CapBypassAuditLog,
		CapInternalOperation,
		CapBypassSubscriptionCheck,
		CapSystemAdmin,
	}

	seen := make(map[Capability]bool, len(all))

	for _, cap := range all {
		if cap == 0 {
			t.Errorf("capability constant must be non-zero")
		}

		if cap&(cap-1) != 0 {
			t.Errorf("capability %d is not a power of two", cap)
		}

		if seen[cap] {
			t.Errorf("duplicate capability value: %d", cap)
		}

		seen[cap] = true
	}
}
