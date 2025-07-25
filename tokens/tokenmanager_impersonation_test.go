package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/tokens"
)

var testKey *rsa.PrivateKey

func init() {
	var err error

	testKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
}

func setupTestTokenManager(t *testing.T) *tokens.TokenManager {
	conf := tokens.Config{
		Audience:        "https://api.example.com",
		Issuer:          "https://auth.example.com",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 24 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	tm, err := tokens.NewWithKey(testKey, conf)
	assert.NoError(t, err)

	return tm
}

func TestTokenManager_CreateImpersonationToken(t *testing.T) {
	tm := setupTestTokenManager(t)
	ctx := context.Background()

	tests := []struct {
		name    string
		opts    tokens.CreateImpersonationTokenOptions
		wantErr bool
		verify  func(t *testing.T, token string, opts tokens.CreateImpersonationTokenOptions)
	}{
		{
			name: "valid support impersonation token",
			opts: tokens.CreateImpersonationTokenOptions{
				ImpersonatorID:    ulids.New().String(),
				ImpersonatorEmail: "support@example.com",
				TargetUserID:      ulids.New().String(),
				TargetUserEmail:   "user@example.com",
				OrganizationID:    ulids.New().String(),
				Type:              "support",
				Reason:            "debugging user issue",
				Scopes:            []string{"read", "debug"},
				OriginalToken:     "original-token",
			},
			wantErr: false,
			verify: func(t *testing.T, token string, opts tokens.CreateImpersonationTokenOptions) {
				// Parse the token without validation to check claims
				claims := &tokens.ImpersonationClaims{}
				parser := jwt.NewParser()
				_, _, err := parser.ParseUnverified(token, claims)
				assert.NoError(t, err)

				assert.Equal(t, opts.ImpersonatorID, claims.ImpersonatorID)
				assert.Equal(t, opts.ImpersonatorEmail, claims.ImpersonatorEmail)
				assert.Equal(t, opts.TargetUserID, claims.UserID)
				assert.Equal(t, opts.TargetUserID, claims.Subject)
				assert.Equal(t, opts.TargetUserEmail, claims.TargetUserEmail)
				assert.Equal(t, opts.OrganizationID, claims.OrgID)
				assert.Equal(t, opts.Type, claims.Type)
				assert.Equal(t, opts.Reason, claims.Reason)
				assert.Equal(t, opts.Scopes, claims.Scopes)
				assert.Equal(t, opts.OriginalToken, claims.OriginalToken)
				assert.NotEmpty(t, claims.SessionID)
				assert.NotEmpty(t, claims.ID)
				assert.Equal(t, claims.SessionID, claims.ID)
			},
		},
		{
			name: "job impersonation with custom duration",
			opts: tokens.CreateImpersonationTokenOptions{
				ImpersonatorID:    ulids.New().String(),
				ImpersonatorEmail: "job@example.com",
				TargetUserID:      ulids.New().String(),
				TargetUserEmail:   "user@example.com",
				OrganizationID:    ulids.New().String(),
				Type:              "job",
				Reason:            "async processing",
				Duration:          48 * time.Hour,
				Scopes:            []string{"*"},
			},
			wantErr: false,
			verify: func(t *testing.T, token string, _ tokens.CreateImpersonationTokenOptions) {
				claims := &tokens.ImpersonationClaims{}
				parser := jwt.NewParser()
				_, _, err := parser.ParseUnverified(token, claims)
				assert.NoError(t, err)

				// Check duration was applied correctly
				expectedExpiry := time.Now().Add(48 * time.Hour)
				assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second)
			},
		},
		{
			name: "admin impersonation with default duration",
			opts: tokens.CreateImpersonationTokenOptions{
				ImpersonatorID:    ulids.New().String(),
				ImpersonatorEmail: "admin@example.com",
				TargetUserID:      ulids.New().String(),
				TargetUserEmail:   "user@example.com",
				OrganizationID:    ulids.New().String(),
				Type:              "admin",
				Reason:            "administrative action",
				// Duration not set, should default to 1 hour
			},
			wantErr: false,
			verify: func(t *testing.T, token string, _ tokens.CreateImpersonationTokenOptions) {
				claims := &tokens.ImpersonationClaims{}
				parser := jwt.NewParser()
				_, _, err := parser.ParseUnverified(token, claims)
				assert.NoError(t, err)

				// Check default duration was applied (15 minutes for admin)
				expectedExpiry := time.Now().Add(15 * time.Minute)
				assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second)
			},
		},
		{
			name: "unknown type with default duration",
			opts: tokens.CreateImpersonationTokenOptions{
				ImpersonatorID:    ulids.New().String(),
				ImpersonatorEmail: "unknown@example.com",
				TargetUserID:      ulids.New().String(),
				TargetUserEmail:   "user@example.com",
				Type:              "custom",
				Reason:            "custom action",
			},
			wantErr: false,
			verify: func(t *testing.T, token string, _ tokens.CreateImpersonationTokenOptions) {
				claims := &tokens.ImpersonationClaims{}
				parser := jwt.NewParser()
				_, _, err := parser.ParseUnverified(token, claims)
				assert.NoError(t, err)

				// Check default duration was applied (15 minutes for unknown)
				expectedExpiry := time.Now().Add(15 * time.Minute)
				assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second)
			},
		},
		{
			name: "support impersonation with default duration",
			opts: tokens.CreateImpersonationTokenOptions{
				ImpersonatorID:    ulids.New().String(),
				ImpersonatorEmail: "support@example.com",
				TargetUserID:      ulids.New().String(),
				TargetUserEmail:   "user@example.com",
				Type:              "support",
				Reason:            "support request",
				// Duration not set, should default to 4 hours
			},
			wantErr: false,
			verify: func(t *testing.T, token string, _ tokens.CreateImpersonationTokenOptions) {
				claims := &tokens.ImpersonationClaims{}
				parser := jwt.NewParser()
				_, _, err := parser.ParseUnverified(token, claims)
				assert.NoError(t, err)

				// Check default duration was applied (30 minutes for support)
				expectedExpiry := time.Now().Add(30 * time.Minute)
				assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second)
			},
		},
		{
			name: "job impersonation with default duration",
			opts: tokens.CreateImpersonationTokenOptions{
				ImpersonatorID:    ulids.New().String(),
				ImpersonatorEmail: "job@example.com",
				TargetUserID:      ulids.New().String(),
				TargetUserEmail:   "user@example.com",
				Type:              "job",
				Reason:            "background processing",
				// Duration not set, should default to 24 hours
			},
			wantErr: false,
			verify: func(t *testing.T, token string, _ tokens.CreateImpersonationTokenOptions) {
				claims := &tokens.ImpersonationClaims{}
				parser := jwt.NewParser()
				_, _, err := parser.ParseUnverified(token, claims)
				assert.NoError(t, err)

				// Check default duration was applied (2 hours for job)
				expectedExpiry := time.Now().Add(2 * time.Hour)
				assert.WithinDuration(t, expectedExpiry, claims.ExpiresAt.Time, 5*time.Second)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tm.CreateImpersonationToken(ctx, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, token)

			if tt.verify != nil {
				tt.verify(t, token, tt.opts)
			}
		})
	}
}

func TestTokenManager_ValidateImpersonationToken(t *testing.T) {
	tm := setupTestTokenManager(t)
	ctx := context.Background()

	// Create a valid token for testing
	validOpts := tokens.CreateImpersonationTokenOptions{
		ImpersonatorID:    ulids.New().String(),
		ImpersonatorEmail: "support@example.com",
		TargetUserID:      ulids.New().String(),
		TargetUserEmail:   "user@example.com",
		OrganizationID:    ulids.New().String(),
		Type:              "support",
		Reason:            "debugging",
		Duration:          1 * time.Hour,
		Scopes:            []string{"read"},
	}

	validToken, err := tm.CreateImpersonationToken(ctx, validOpts)
	assert.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		setupFunc func() string
		wantErr   bool
		errCheck  func(t *testing.T, err error)
		verify    func(t *testing.T, claims *tokens.ImpersonationClaims)
	}{
		{
			name:    "valid token",
			token:   validToken,
			wantErr: false,
			verify: func(t *testing.T, claims *tokens.ImpersonationClaims) {
				assert.Equal(t, validOpts.ImpersonatorID, claims.ImpersonatorID)
				assert.Equal(t, validOpts.TargetUserID, claims.UserID)
				assert.Equal(t, validOpts.Type, claims.Type)
				assert.Equal(t, validOpts.Scopes, claims.Scopes)
			},
		},
		{
			name:    "malformed token",
			token:   "not.a.valid.token",
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "token is malformed")
			},
		},
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "token is malformed")
			},
		},
		{
			name: "token with wrong signature",
			setupFunc: func() string {
				// Create a different key to sign with
				differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
				assert.NoError(t, err)

				wrongConf := tokens.Config{
					Audience:        "https://api.example.com",
					Issuer:          "https://auth.example.com",
					AccessDuration:  1 * time.Hour,
					RefreshDuration: 24 * time.Hour,
				}

				wrongTM, err := tokens.NewWithKey(differentKey, wrongConf)
				assert.NoError(t, err)

				token, err := wrongTM.CreateImpersonationToken(ctx, validOpts)
				assert.NoError(t, err)
				return token
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "unknown signing key")
			},
		},
		{
			name: "expired token",
			setupFunc: func() string {
				expiredOpts := validOpts
				expiredOpts.Duration = -1 * time.Hour // Already expired

				token, err := tm.CreateImpersonationToken(ctx, expiredOpts)
				assert.NoError(t, err)
				return token
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "expired")
			},
		},
		{
			name: "token missing impersonation type",
			setupFunc: func() string {
				// Create claims without type
				claims := &tokens.ImpersonationClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    tm.Config().Issuer,
						Audience:  jwt.ClaimStrings{tm.Config().Audience},
					},
					ImpersonatorID: "test",
					UserID:         "test",
					// Type is missing
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, err := tm.Sign(token)
				assert.NoError(t, err)
				return tokenString
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Equal(t, tokens.ErrMissingImpersonationType, err)
			},
		},
		{
			name: "token missing impersonator ID",
			setupFunc: func() string {
				claims := &tokens.ImpersonationClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    tm.Config().Issuer,
						Audience:  jwt.ClaimStrings{tm.Config().Audience},
					},
					Type:   "support",
					UserID: "test",
					// ImpersonatorID is missing
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, err := tm.Sign(token)
				assert.NoError(t, err)
				return tokenString
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Equal(t, tokens.ErrMissingImpersonatorID, err)
			},
		},
		{
			name: "token missing target user ID",
			setupFunc: func() string {
				claims := &tokens.ImpersonationClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    tm.Config().Issuer,
						Audience:  jwt.ClaimStrings{tm.Config().Audience},
					},
					Type:           "support",
					ImpersonatorID: "test",
					// UserID is missing
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, err := tm.Sign(token)
				assert.NoError(t, err)
				return tokenString
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Equal(t, tokens.ErrMissingTargetUserID, err)
			},
		},
		{
			name: "token with invalid audience",
			setupFunc: func() string {
				claims := &tokens.ImpersonationClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    tm.Config().Issuer,
						Audience:  jwt.ClaimStrings{"https://wrong.example.com"},
					},
					Type:           "support",
					ImpersonatorID: "test",
					UserID:         "test",
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, err := tm.Sign(token)
				assert.NoError(t, err)
				return tokenString
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "audience")
			},
		},
		{
			name: "token with invalid issuer",
			setupFunc: func() string {
				claims := &tokens.ImpersonationClaims{
					RegisteredClaims: jwt.RegisteredClaims{
						IssuedAt:  jwt.NewNumericDate(time.Now()),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
						Issuer:    "https://wrong-issuer.example.com",
						Audience:  jwt.ClaimStrings{tm.Config().Audience},
					},
					Type:           "support",
					ImpersonatorID: "test",
					UserID:         "test",
				}

				token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
				tokenString, err := tm.Sign(token)
				assert.NoError(t, err)
				return tokenString
			},
			wantErr: true,
			errCheck: func(t *testing.T, err error) {
				assert.Contains(t, err.Error(), "issuer")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.token
			if tt.setupFunc != nil {
				token = tt.setupFunc()
			}

			claims, err := tm.ValidateImpersonationToken(ctx, token)
			if tt.wantErr {
				assert.Error(t, err)

				if tt.errCheck != nil {
					tt.errCheck(t, err)
				}

				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, claims)

			if tt.verify != nil {
				tt.verify(t, claims)
			}
		})
	}
}

func TestTokenManager_ImpersonationTokenLifecycle(t *testing.T) {
	tm := setupTestTokenManager(t)
	ctx := context.Background()

	// Test full lifecycle: create and validate
	opts := tokens.CreateImpersonationTokenOptions{
		ImpersonatorID:    ulids.New().String(),
		ImpersonatorEmail: "support@example.com",
		TargetUserID:      ulids.New().String(),
		TargetUserEmail:   "user@example.com",
		OrganizationID:    ulids.New().String(),
		Type:              "support",
		Reason:            "debugging issue #123",
		Duration:          2 * time.Hour,
		Scopes:            []string{"read", "write", "debug"},
		OriginalToken:     "original-auth-token",
	}

	// Create token
	token, err := tm.CreateImpersonationToken(ctx, opts)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate token
	claims, err := tm.ValidateImpersonationToken(ctx, token)
	assert.NoError(t, err)
	assert.NotNil(t, claims)

	// Verify all claims match
	assert.Equal(t, opts.ImpersonatorID, claims.ImpersonatorID)
	assert.Equal(t, opts.ImpersonatorEmail, claims.ImpersonatorEmail)
	assert.Equal(t, opts.TargetUserID, claims.UserID)
	assert.Equal(t, opts.TargetUserEmail, claims.TargetUserEmail)
	assert.Equal(t, opts.OrganizationID, claims.OrgID)
	assert.Equal(t, opts.Type, claims.Type)
	assert.Equal(t, opts.Reason, claims.Reason)
	assert.Equal(t, opts.Scopes, claims.Scopes)
	assert.Equal(t, opts.OriginalToken, claims.OriginalToken)

	// Test parsed IDs
	assert.Equal(t, opts.TargetUserID, claims.ParseUserID().String())
	assert.Equal(t, opts.OrganizationID, claims.ParseOrgID().String())
	assert.Equal(t, opts.ImpersonatorID, claims.ParseImpersonatorID().String())

	// Test scope checking
	assert.True(t, claims.HasScope("read"))
	assert.True(t, claims.HasScope("write"))
	assert.True(t, claims.HasScope("debug"))
	assert.False(t, claims.HasScope("admin"))

	// Test type checking
	assert.True(t, claims.IsSupportImpersonation())
	assert.False(t, claims.IsJobImpersonation())
	assert.False(t, claims.IsAdminImpersonation())
}

func TestTokenManager_ImpersonationTokenWithDifferentKeyIDs(t *testing.T) {
	// Test token validation with multiple keys (key rotation scenario)
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	conf := tokens.Config{
		Audience:        "https://api.example.com",
		Issuer:          "https://auth.example.com",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 24 * time.Hour,
	}

	tm, err := tokens.NewWithKey(key1, conf)
	assert.NoError(t, err)

	// Add second key
	keyID := ulids.New()
	tm.AddSigningKey(keyID, key2)

	ctx := context.Background()
	opts := tokens.CreateImpersonationTokenOptions{
		ImpersonatorID:    ulids.New().String(),
		ImpersonatorEmail: "support@example.com",
		TargetUserID:      ulids.New().String(),
		TargetUserEmail:   "user@example.com",
		Type:              "support",
		Reason:            "test",
	}

	// Create token with first key
	token1, err := tm.CreateImpersonationToken(ctx, opts)
	assert.NoError(t, err)

	// Switch to second key
	err = tm.UseSigningKey(keyID)
	assert.NoError(t, err)

	// Create token with second key
	token2, err := tm.CreateImpersonationToken(ctx, opts)
	assert.NoError(t, err)

	// Both tokens should validate successfully
	claims1, err := tm.ValidateImpersonationToken(ctx, token1)
	assert.NoError(t, err)
	assert.NotNil(t, claims1)

	claims2, err := tm.ValidateImpersonationToken(ctx, token2)
	assert.NoError(t, err)
	assert.NotNil(t, claims2)
}
