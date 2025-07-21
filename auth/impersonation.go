package auth

import (
	"context"
	"time"

	"github.com/theopenlane/utils/contextx"
)

// ImpersonationType represents the type of impersonation being performed
type ImpersonationType string

const (
	// SupportImpersonation is for support staff helping users debug issues
	SupportImpersonation ImpersonationType = "support"
	// JobImpersonation is for async jobs running with user context
	JobImpersonation ImpersonationType = "job"
	// AdminImpersonation is for admin operations that need to act as a user
	AdminImpersonation ImpersonationType = "admin"
)

// ImpersonationContext contains information about an active impersonation session
type ImpersonationContext struct {
	// Type indicates what kind of impersonation this is
	Type ImpersonationType
	// ImpersonatorID is the user ID of the person doing the impersonation
	ImpersonatorID string
	// ImpersonatorEmail is the email of the person doing the impersonation
	ImpersonatorEmail string
	// TargetUserID is the user being impersonated
	TargetUserID string
	// TargetUserEmail is the email of the user being impersonated
	TargetUserEmail string
	// Reason is the justification for the impersonation
	Reason string
	// StartedAt is when the impersonation session began
	StartedAt time.Time
	// ExpiresAt is when the impersonation session expires
	ExpiresAt time.Time
	// SessionID is a unique identifier for this impersonation session
	SessionID string
	// Scopes defines what actions are allowed during impersonation
	Scopes []string
}

// IsExpired checks if the impersonation session has expired
func (i *ImpersonationContext) IsExpired() bool {
	return time.Now().After(i.ExpiresAt)
}

// HasScope checks if the impersonation session allows a specific scope
func (i *ImpersonationContext) HasScope(scope string) bool {
	for _, s := range i.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// ImpersonatedUser extends AuthenticatedUser with impersonation information
type ImpersonatedUser struct {
	*AuthenticatedUser
	// ImpersonationContext contains details about the active impersonation
	ImpersonationContext *ImpersonationContext
	// OriginalUser is the user who initiated the impersonation (support staff, etc.)
	OriginalUser *AuthenticatedUser
}

// IsImpersonated returns true if this user is being impersonated
func (i *ImpersonatedUser) IsImpersonated() bool {
	return i.ImpersonationContext != nil
}

// CanPerformAction checks if the current impersonation allows a specific action
func (i *ImpersonatedUser) CanPerformAction(scope string) bool {
	if !i.IsImpersonated() {
		return true // Not impersonated, normal user permissions apply
	}

	if i.ImpersonationContext.IsExpired() {
		return false // Impersonation has expired
	}

	return i.ImpersonationContext.HasScope(scope)
}

// WithImpersonatedUser sets an impersonated user in the context
func WithImpersonatedUser(ctx context.Context, user *ImpersonatedUser) context.Context {
	return contextx.With(ctx, user)
}

// ImpersonatedUserFromContext retrieves an impersonated user from the context
func ImpersonatedUserFromContext(ctx context.Context) (*ImpersonatedUser, bool) {
	return contextx.From[*ImpersonatedUser](ctx)
}

// MustImpersonatedUserFromContext retrieves an impersonated user from the context or panics
func MustImpersonatedUserFromContext(ctx context.Context) *ImpersonatedUser {
	return contextx.MustFrom[*ImpersonatedUser](ctx)
}

// GetEffectiveUser returns the impersonated user if present, otherwise the regular authenticated user
func GetEffectiveUser(ctx context.Context) (*AuthenticatedUser, bool) {
	// First check for impersonated user
	if impUser, ok := ImpersonatedUserFromContext(ctx); ok {
		return impUser.AuthenticatedUser, true
	}

	// Fall back to regular authenticated user
	return AuthenticatedUserFromContext(ctx)
}

// ImpersonationAuditLog represents an audit log entry for impersonation events
type ImpersonationAuditLog struct {
	SessionID         string            `json:"session_id"`
	Type              ImpersonationType `json:"type"`
	ImpersonatorID    string            `json:"impersonator_id"`
	ImpersonatorEmail string            `json:"impersonator_email"`
	TargetUserID      string            `json:"target_user_id"`
	TargetUserEmail   string            `json:"target_user_email"`
	Action            string            `json:"action"` // "start", "end", "action_performed"
	Reason            string            `json:"reason"`
	Timestamp         time.Time         `json:"timestamp"`
	IPAddress         string            `json:"ip_address,omitempty"`
	UserAgent         string            `json:"user_agent,omitempty"`
	OrganizationID    string            `json:"organization_id"`
	Scopes            []string          `json:"scopes"`
	AdditionalData    map[string]any    `json:"additional_data,omitempty"`
}