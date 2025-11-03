package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theopenlane/utils/ulids"
)

func TestImpersonationContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  *ImpersonationContext
		want bool
	}{
		{
			name: "not expired",
			ctx: &ImpersonationContext{
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			want: false,
		},
		{
			name: "expired",
			ctx: &ImpersonationContext{
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ctx.IsExpired())
		})
	}
}

func TestImpersonationContext_HasScope(t *testing.T) {
	tests := []struct {
		name  string
		ctx   *ImpersonationContext
		scope string
		want  bool
	}{
		{
			name: "has exact scope",
			ctx: &ImpersonationContext{
				Scopes: []string{"read", "write", "export"},
			},
			scope: "write",
			want:  true,
		},
		{
			name: "has wildcard scope",
			ctx: &ImpersonationContext{
				Scopes: []string{"*"},
			},
			scope: "anything",
			want:  true,
		},
		{
			name: "missing scope",
			ctx: &ImpersonationContext{
				Scopes: []string{"read"},
			},
			scope: "write",
			want:  false,
		},
		{
			name: "empty scopes",
			ctx: &ImpersonationContext{
				Scopes: []string{},
			},
			scope: "read",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ctx.HasScope(tt.scope))
		})
	}
}

func TestImpersonatedUser(t *testing.T) {
	t.Run("IsImpersonated", func(t *testing.T) {
		// Not impersonated
		user := &ImpersonatedUser{
			AuthenticatedUser: &AuthenticatedUser{
				SubjectID: "user123",
			},
			ImpersonationContext: nil,
		}
		assert.False(t, user.IsImpersonated())

		// Impersonated
		user.ImpersonationContext = &ImpersonationContext{
			Type: SupportImpersonation,
		}
		assert.True(t, user.IsImpersonated())
	})

	t.Run("CanPerformAction", func(t *testing.T) {
		tests := []struct {
			name   string
			user   *ImpersonatedUser
			action string
			want   bool
		}{
			{
				name: "not impersonated - always allowed",
				user: &ImpersonatedUser{
					AuthenticatedUser:    &AuthenticatedUser{},
					ImpersonationContext: nil,
				},
				action: "anything",
				want:   true,
			},
			{
				name: "impersonated with expired context",
				user: &ImpersonatedUser{
					AuthenticatedUser: &AuthenticatedUser{},
					ImpersonationContext: &ImpersonationContext{
						ExpiresAt: time.Now().Add(-1 * time.Hour),
						Scopes:    []string{"*"},
					},
				},
				action: "read",
				want:   false,
			},
			{
				name: "impersonated with valid scope",
				user: &ImpersonatedUser{
					AuthenticatedUser: &AuthenticatedUser{},
					ImpersonationContext: &ImpersonationContext{
						ExpiresAt: time.Now().Add(1 * time.Hour),
						Scopes:    []string{"read", "export"},
					},
				},
				action: "export",
				want:   true,
			},
			{
				name: "impersonated without required scope",
				user: &ImpersonatedUser{
					AuthenticatedUser: &AuthenticatedUser{},
					ImpersonationContext: &ImpersonationContext{
						ExpiresAt: time.Now().Add(1 * time.Hour),
						Scopes:    []string{"read"},
					},
				},
				action: "write",
				want:   false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, tt.user.CanPerformAction(tt.action))
			})
		}
	})
}

func TestWithImpersonatedUser(t *testing.T) {
	ctx := context.Background()
	user := &ImpersonatedUser{
		AuthenticatedUser: &AuthenticatedUser{
			SubjectID:    "user123",
			SubjectEmail: "user@example.com",
		},
		ImpersonationContext: &ImpersonationContext{
			Type:              SupportImpersonation,
			ImpersonatorID:    "support123",
			ImpersonatorEmail: "support@example.com",
			TargetUserID:      "user123",
			TargetUserEmail:   "user@example.com",
			Reason:            "debugging issue",
			StartedAt:         time.Now(),
			ExpiresAt:         time.Now().Add(1 * time.Hour),
			SessionID:         ulids.New().String(),
			Scopes:            []string{"read", "debug"},
		},
		OriginalUser: &AuthenticatedUser{
			SubjectID:    "support123",
			SubjectEmail: "support@example.com",
		},
	}

	// Set user in context
	ctx = WithImpersonatedUser(ctx, user)

	// Retrieve user from context
	retrieved, ok := ImpersonatedUserFromContext(ctx)
	assert.True(t, ok)
	assert.Equal(t, user, retrieved)

	// Test MustImpersonatedUserFromContext
	assert.NotPanics(t, func() {
		mustUser := MustImpersonatedUserFromContext(ctx)
		assert.Equal(t, user, mustUser)
	})

	// Test with empty context
	emptyCtx := context.Background()
	_, ok = ImpersonatedUserFromContext(emptyCtx)
	assert.False(t, ok)

	// Test MustImpersonatedUserFromContext panics with empty context
	assert.Panics(t, func() {
		_ = MustImpersonatedUserFromContext(emptyCtx)
	})
}

func TestGetEffectiveUser(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantUser *AuthenticatedUser
		wantOk   bool
	}{
		{
			name: "impersonated user context",
			setupCtx: func() context.Context {
				ctx := context.Background()
				impUser := &ImpersonatedUser{
					AuthenticatedUser: &AuthenticatedUser{
						SubjectID:    "target123",
						SubjectEmail: "target@example.com",
					},
					ImpersonationContext: &ImpersonationContext{
						Type: SupportImpersonation,
					},
					OriginalUser: &AuthenticatedUser{
						SubjectID:    "support123",
						SubjectEmail: "support@example.com",
					},
				}

				return WithImpersonatedUser(ctx, impUser)
			},
			wantUser: &AuthenticatedUser{
				SubjectID:    "target123",
				SubjectEmail: "target@example.com",
			},
			wantOk: true,
		},
		{
			name: "regular authenticated user context",
			setupCtx: func() context.Context {
				ctx := context.Background()
				user := &AuthenticatedUser{
					SubjectID:    "user123",
					SubjectEmail: "user@example.com",
				}

				return WithAuthenticatedUser(ctx, user)
			},
			wantUser: &AuthenticatedUser{
				SubjectID:    "user123",
				SubjectEmail: "user@example.com",
			},
			wantOk: true,
		},
		{
			name:     "no user in context",
			setupCtx: context.Background,
			wantUser: nil,
			wantOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			user, ok := GetEffectiveUser(ctx)
			assert.Equal(t, tt.wantOk, ok)

			if tt.wantOk {
				assert.Equal(t, tt.wantUser.SubjectID, user.SubjectID)
				assert.Equal(t, tt.wantUser.SubjectEmail, user.SubjectEmail)
			}
		})
	}
}

func TestImpersonationAuditLog(t *testing.T) {
	// Test creating an audit log entry
	auditLog := &ImpersonationAuditLog{
		SessionID:         ulids.New().String(),
		Type:              SupportImpersonation,
		ImpersonatorID:    "support123",
		ImpersonatorEmail: "support@example.com",
		TargetUserID:      "user123",
		TargetUserEmail:   "user@example.com",
		Action:            "start",
		Reason:            "debugging user issue",
		Timestamp:         time.Now(),
		IPAddress:         "192.168.1.1",
		UserAgent:         "Mozilla/5.0",
		OrganizationID:    "org123",
		Scopes:            []string{"read", "debug"},
		AdditionalData: map[string]any{
			"ticket_id": "TICKET-123",
		},
	}

	// Verify all fields are set correctly
	assert.NotEmpty(t, auditLog.SessionID)
	assert.Equal(t, SupportImpersonation, auditLog.Type)
	assert.Equal(t, "support123", auditLog.ImpersonatorID)
	assert.Equal(t, "support@example.com", auditLog.ImpersonatorEmail)
	assert.Equal(t, "user123", auditLog.TargetUserID)
	assert.Equal(t, "user@example.com", auditLog.TargetUserEmail)
	assert.Equal(t, "start", auditLog.Action)
	assert.Equal(t, "debugging user issue", auditLog.Reason)
	assert.NotZero(t, auditLog.Timestamp)
	assert.Equal(t, "192.168.1.1", auditLog.IPAddress)
	assert.Equal(t, "Mozilla/5.0", auditLog.UserAgent)
	assert.Equal(t, "org123", auditLog.OrganizationID)
	assert.Equal(t, []string{"read", "debug"}, auditLog.Scopes)
	assert.Equal(t, "TICKET-123", auditLog.AdditionalData["ticket_id"])
}
