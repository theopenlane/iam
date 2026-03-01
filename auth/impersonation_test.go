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
				ExpiresAt: time.Now().Add(time.Hour),
			},
			want: false,
		},
		{
			name: "expired",
			ctx: &ImpersonationContext{
				ExpiresAt: time.Now().Add(-time.Hour),
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

func TestImpersonationContextHasScope(t *testing.T) {
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

func TestCallerCanPerformAction(t *testing.T) {
	tests := []struct {
		name   string
		caller *Caller
		action string
		want   bool
	}{
		{
			name: "not impersonated caller is always allowed",
			caller: &Caller{
				SubjectID: "user123",
			},
			action: "anything",
			want:   true,
		},
		{
			name: "expired impersonation denies",
			caller: &Caller{
				Impersonation: &ImpersonationContext{
					ExpiresAt: time.Now().Add(-time.Hour),
					Scopes:    []string{"*"},
				},
			},
			action: "read",
			want:   false,
		},
		{
			name: "valid impersonation scope allows",
			caller: &Caller{
				Impersonation: &ImpersonationContext{
					ExpiresAt: time.Now().Add(time.Hour),
					Scopes:    []string{"read", "export"},
				},
			},
			action: "export",
			want:   true,
		},
		{
			name: "valid impersonation missing scope denies",
			caller: &Caller{
				Impersonation: &ImpersonationContext{
					ExpiresAt: time.Now().Add(time.Hour),
					Scopes:    []string{"read"},
				},
			},
			action: "write",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.caller.CanPerformAction(tt.action))
		})
	}
}

func TestCallerFromContextWithImpersonation(t *testing.T) {
	tests := []struct {
		name     string
		setupCtx func() context.Context
		wantUser *Caller
		wantOk   bool
	}{
		{
			name: "caller in context",
			setupCtx: func() context.Context {
				ctx := context.Background()
				caller := &Caller{
					SubjectID:    "target123",
					SubjectEmail: "target@example.com",
					Impersonation: &ImpersonationContext{
						Type: SupportImpersonation,
					},
				}

				return WithCaller(ctx, caller)
			},
			wantUser: &Caller{
				SubjectID:    "target123",
				SubjectEmail: "target@example.com",
			},
			wantOk: true,
		},
		{
			name:     "no caller in context",
			setupCtx: context.Background,
			wantUser: nil,
			wantOk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupCtx()
			user, ok := CallerFromContext(ctx)
			assert.Equal(t, tt.wantOk, ok)

			if tt.wantOk {
				assert.Equal(t, tt.wantUser.SubjectID, user.SubjectID)
				assert.Equal(t, tt.wantUser.SubjectEmail, user.SubjectEmail)
			}
		})
	}
}

func TestImpersonationAuditLog(t *testing.T) {
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
