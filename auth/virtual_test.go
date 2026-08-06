package auth

import (
	"context"
	"testing"
)

// TestEnsureCallerOrg verifies the org is filled only when the caller has none
func TestEnsureCallerOrg(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func() context.Context
		orgID   string
		wantOrg string
		wantCap Capability
	}{
		{
			name:  "sets org on caller without one",
			orgID: "org-123",
			ctx: func() context.Context {
				return WithCaller(context.Background(), &Caller{
					Capabilities: CapBypassOrgFilter | CapInternalOperation,
				})
			},
			wantOrg: "org-123",
			wantCap: CapBypassOrgFilter | CapInternalOperation,
		},
		{
			name:  "preserves existing org",
			orgID: "org-override",
			ctx: func() context.Context {
				return WithCaller(context.Background(), &Caller{
					OrganizationID: "org-original",
					Capabilities:   CapInternalOperation,
				})
			},
			wantOrg: "org-original",
			wantCap: CapInternalOperation,
		},
		{
			name:  "preserves org from OrganizationIDs",
			orgID: "org-override",
			ctx: func() context.Context {
				return WithCaller(context.Background(), &Caller{
					OrganizationIDs: []string{"org-from-ids"},
				})
			},
			wantOrg: "org-from-ids",
		},
		{
			name:  "no-op for empty orgID",
			orgID: "",
			ctx: func() context.Context {
				return WithCaller(context.Background(), &Caller{
					Capabilities: CapInternalOperation,
				})
			},
		},
		{
			name:  "no-op when no caller in context",
			orgID: "org-123",
			ctx:   context.Background,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := EnsureCallerOrg(tc.ctx(), tc.orgID)
			caller, ok := CallerFromContext(result)

			if tc.wantOrg == "" {
				if ok && caller != nil {
					if orgID, has := caller.ActiveOrg(); has && orgID != "" {
						t.Errorf("expected no org, got %q", orgID)
					}
				}

				return
			}

			if !ok || caller == nil {
				t.Fatal("expected caller in context")
			}

			orgID, hasOrg := caller.ActiveOrg()
			if !hasOrg {
				t.Fatal("expected caller to have active org")
			}

			if orgID != tc.wantOrg {
				t.Errorf("org: want %s, got %s", tc.wantOrg, orgID)
			}

			if tc.wantCap != 0 && !caller.Has(tc.wantCap) {
				t.Error("expected capabilities to be preserved")
			}
		})
	}
}

// TestNewIntegrationCaller verifies the identity, org scope, and capability set
func TestNewIntegrationCaller(t *testing.T) {
	c := NewIntegrationCaller("org-1")

	if c.SubjectID != IntegrationSubjectID || c.SubjectName != IntegrationDisplayName || c.SubjectEmail != IntegrationEmail {
		t.Errorf("identity: got %s / %s / %s", c.SubjectID, c.SubjectName, c.SubjectEmail)
	}

	if c.OrganizationID != "org-1" {
		t.Errorf("OrganizationID: want org-1, got %s", c.OrganizationID)
	}

	for _, cap := range []Capability{CapIntegrationActor, CapBypassOrgFilter, CapBypassFGA, CapInternalOperation, CapBypassAuditLog} {
		if !c.Has(cap) {
			t.Errorf("NewIntegrationCaller must have cap %d", cap)
		}
	}

	for _, cap := range []Capability{CapBypassFeatureCheck, CapBypassSubscriptionCheck, CapSystemAdmin} {
		if c.Has(cap) {
			t.Errorf("NewIntegrationCaller must not have cap %d", cap)
		}
	}
}

// TestEnsureIntegrationCaller verifies identity is filled only when no attributed caller is present
func TestEnsureIntegrationCaller(t *testing.T) {
	t.Run("no caller sets the full integration caller", func(t *testing.T) {
		got, ok := CallerFromContext(EnsureIntegrationCaller(context.Background(), "org-1"))
		if !ok || got == nil {
			t.Fatal("expected integration caller to be set")
		}

		if got.SubjectID != IntegrationSubjectID || got.OrganizationID != "org-1" {
			t.Errorf("want %s in org-1, got %s in %s", IntegrationSubjectID, got.SubjectID, got.OrganizationID)
		}
	})

	t.Run("caller with subject is retained aside from org", func(t *testing.T) {
		ctx := WithCaller(context.Background(), &Caller{
			SubjectID:    "user-1",
			SubjectName:  "Real User",
			Capabilities: CapBypassFeatureCheck,
		})
		got, _ := CallerFromContext(EnsureIntegrationCaller(ctx, "org-1"))

		if got.SubjectID != "user-1" || got.SubjectName != "Real User" {
			t.Errorf("subject identity must be retained, got %s / %s", got.SubjectID, got.SubjectName)
		}

		if got.Has(CapIntegrationActor) {
			t.Error("capabilities of an authenticated caller must not be expanded")
		}

		if got.OrganizationID != "org-1" {
			t.Errorf("OrganizationID: want org-1, got %s", got.OrganizationID)
		}
	})

	t.Run("subject-less caller gains integration actor identity", func(t *testing.T) {
		original := NewWebhookCaller("org-1")
		ctx := WithCaller(context.Background(), original)
		got, _ := CallerFromContext(EnsureIntegrationCaller(ctx, "org-1"))

		if got.SubjectID != IntegrationSubjectID {
			t.Errorf("SubjectID: want %s, got %s", IntegrationSubjectID, got.SubjectID)
		}

		if got.SubjectName != IntegrationDisplayName || got.SubjectEmail != IntegrationEmail {
			t.Errorf("identity: want %s / %s, got %s / %s", IntegrationDisplayName, IntegrationEmail, got.SubjectName, got.SubjectEmail)
		}

		if got.OrganizationID != "org-1" {
			t.Errorf("OrganizationID: want org-1, got %s", got.OrganizationID)
		}

		if !got.Has(CapIntegrationActor) {
			t.Error("expected CapIntegrationActor to be added")
		}

		for _, c := range []Capability{CapBypassOrgFilter, CapBypassFGA, CapInternalOperation} {
			if !got.Has(c) {
				t.Errorf("existing capability %d must be retained", c)
			}
		}

		if original.SubjectID != "" {
			t.Error("original caller must not be mutated")
		}
	})
}
