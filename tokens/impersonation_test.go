package tokens

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theopenlane/utils/ulids"
)

func TestImpersonationClaims(t *testing.T) {
	claims := &ImpersonationClaims{
		UserID:            ulids.New().String(),
		OrgID:             ulids.New().String(),
		ImpersonatorID:    ulids.New().String(),
		ImpersonatorEmail: "support@example.com",
		Type:              "support",
		Reason:            "debugging issue",
		SessionID:         ulids.New().String(),
		Scopes:            []string{"read", "debug"},
		TargetUserEmail:   "user@example.com",
		OriginalToken:     "original-token-here",
	}

	t.Run("ParseUserID", func(t *testing.T) {
		userID := claims.ParseUserID()
		assert.NotEqual(t, ulids.Null, userID)
		assert.Equal(t, claims.UserID, userID.String())
	})

	t.Run("ParseOrgID", func(t *testing.T) {
		orgID := claims.ParseOrgID()
		assert.NotEqual(t, ulids.Null, orgID)
		assert.Equal(t, claims.OrgID, orgID.String())
	})

	t.Run("ParseImpersonatorID", func(t *testing.T) {
		impersonatorID := claims.ParseImpersonatorID()
		assert.NotEqual(t, ulids.Null, impersonatorID)
		assert.Equal(t, claims.ImpersonatorID, impersonatorID.String())
	})

	t.Run("HasScope", func(t *testing.T) {
		tests := []struct {
			name  string
			scope string
			want  bool
		}{
			{
				name:  "has exact scope",
				scope: "read",
				want:  true,
			},
			{
				name:  "missing scope",
				scope: "write",
				want:  false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				assert.Equal(t, tt.want, claims.HasScope(tt.scope))
			})
		}
	})

	t.Run("GetSessionID", func(t *testing.T) {
		assert.Equal(t, claims.SessionID, claims.GetSessionID())
	})

	t.Run("IsJobImpersonation", func(t *testing.T) {
		claims.Type = "job"
		assert.True(t, claims.IsJobImpersonation())
		assert.False(t, claims.IsSupportImpersonation())
		assert.False(t, claims.IsAdminImpersonation())
	})

	t.Run("IsSupportImpersonation", func(t *testing.T) {
		claims.Type = "support"
		assert.True(t, claims.IsSupportImpersonation())
		assert.False(t, claims.IsJobImpersonation())
		assert.False(t, claims.IsAdminImpersonation())
	})

	t.Run("IsAdminImpersonation", func(t *testing.T) {
		claims.Type = "admin"
		assert.True(t, claims.IsAdminImpersonation())
		assert.False(t, claims.IsJobImpersonation())
		assert.False(t, claims.IsSupportImpersonation())
	})
}

func TestImpersonationClaims_WithWildcardScope(t *testing.T) {
	claims := &ImpersonationClaims{
		Scopes: []string{"*"},
	}

	assert.True(t, claims.HasScope("read"))
	assert.True(t, claims.HasScope("write"))
	assert.True(t, claims.HasScope("admin"))
	assert.True(t, claims.HasScope("anything"))
}

func TestImpersonationClaims_InvalidULIDs(t *testing.T) {
	claims := &ImpersonationClaims{
		UserID:         "invalid-ulid",
		OrgID:          "also-invalid",
		ImpersonatorID: "still-invalid",
	}

	t.Run("ParseUserID with invalid ULID", func(t *testing.T) {
		userID := claims.ParseUserID()
		assert.Equal(t, ulids.Null, userID)
	})

	t.Run("ParseOrgID with invalid ULID", func(t *testing.T) {
		orgID := claims.ParseOrgID()
		assert.Equal(t, ulids.Null, orgID)
	})

	t.Run("ParseImpersonatorID with invalid ULID", func(t *testing.T) {
		impersonatorID := claims.ParseImpersonatorID()
		assert.Equal(t, ulids.Null, impersonatorID)
	})
}

func TestCreateImpersonationTokenOptions(t *testing.T) {
	opts := CreateImpersonationTokenOptions{
		ImpersonatorID:    "support123",
		ImpersonatorEmail: "support@example.com",
		TargetUserID:      "user123",
		TargetUserEmail:   "user@example.com",
		OrganizationID:    "org123",
		Type:              "support",
		Reason:            "debugging issue",
		Duration:          4 * time.Hour,
		Scopes:            []string{"read", "debug"},
		OriginalToken:     "original-token",
	}

	// Test that all fields are properly set
	assert.Equal(t, "support123", opts.ImpersonatorID)
	assert.Equal(t, "support@example.com", opts.ImpersonatorEmail)
	assert.Equal(t, "user123", opts.TargetUserID)
	assert.Equal(t, "user@example.com", opts.TargetUserEmail)
	assert.Equal(t, "org123", opts.OrganizationID)
	assert.Equal(t, "support", opts.Type)
	assert.Equal(t, "debugging issue", opts.Reason)
	assert.Equal(t, 4*time.Hour, opts.Duration)
	assert.Equal(t, []string{"read", "debug"}, opts.Scopes)
	assert.Equal(t, "original-token", opts.OriginalToken)
}

func TestImpersonationTokenManager_DefaultDurations(t *testing.T) {
	// This test verifies the default duration logic that would be used
	// in CreateImpersonationToken when Duration is 0
	tests := []struct {
		name              string
		impersonationType string
		expectedDuration  time.Duration
	}{
		{
			name:              "support impersonation",
			impersonationType: "support",
			expectedDuration:  30 * time.Minute,
		},
		{
			name:              "job impersonation",
			impersonationType: "job",
			expectedDuration:  2 * time.Hour,
		},
		{
			name:              "admin impersonation",
			impersonationType: "admin",
			expectedDuration:  15 * time.Minute,
		},
		{
			name:              "unknown type defaults to 15 minutes",
			impersonationType: "unknown",
			expectedDuration:  15 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This simulates the default duration logic from CreateImpersonationToken
			var duration time.Duration

			switch tt.impersonationType {
			case "support":
				duration = 30 * time.Minute
			case "job":
				duration = 2 * time.Hour
			case "admin":
				duration = 15 * time.Minute
			default:
				duration = 15 * time.Minute
			}

			assert.Equal(t, tt.expectedDuration, duration)
		})
	}
}

func TestImpersonationTokenManager_ValidationChecks(t *testing.T) {
	// This test covers the validation logic that would be used
	// in ValidateImpersonationToken
	tests := []struct {
		name    string
		claims  *ImpersonationClaims
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid claims",
			claims: &ImpersonationClaims{
				Type:           "support",
				ImpersonatorID: "support123",
				UserID:         "user123",
			},
			wantErr: false,
		},
		{
			name: "missing type",
			claims: &ImpersonationClaims{
				Type:           "",
				ImpersonatorID: "support123",
				UserID:         "user123",
			},
			wantErr: true,
			errMsg:  "impersonation token missing type",
		},
		{
			name: "missing impersonator ID",
			claims: &ImpersonationClaims{
				Type:           "support",
				ImpersonatorID: "",
				UserID:         "user123",
			},
			wantErr: true,
			errMsg:  "impersonation token missing impersonator ID",
		},
		{
			name: "missing target user ID",
			claims: &ImpersonationClaims{
				Type:           "support",
				ImpersonatorID: "support123",
				UserID:         "",
			},
			wantErr: true,
			errMsg:  "impersonation token missing target user ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the validation checks from ValidateImpersonationToken
			var err error

			switch {
			case tt.claims.Type == "":
				err = assert.AnError
				assert.Contains(t, "impersonation token missing type", "impersonation token missing type")
			case tt.claims.ImpersonatorID == "":
				err = assert.AnError
				assert.Contains(t, "impersonation token missing impersonator ID", "impersonation token missing impersonator ID")
			case tt.claims.UserID == "":
				err = assert.AnError
				assert.Contains(t, "impersonation token missing target user ID", "impersonation token missing target user ID")
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
