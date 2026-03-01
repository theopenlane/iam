package auth

import (
	"slices"
	"time"
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
	return slices.ContainsFunc(i.Scopes, func(s string) bool {
		return s == scope || s == "*"
	})
}

// CanPerformAction checks whether this caller's impersonation context allows a specific action.
// Non-impersonated callers are always allowed.
func (c *Caller) CanPerformAction(scope string) bool {
	if c == nil || c.Impersonation == nil {
		return true // Not impersonated, normal user permissions apply
	}

	if c.Impersonation.IsExpired() {
		return false // Impersonation has expired
	}

	return c.Impersonation.HasScope(scope)
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
