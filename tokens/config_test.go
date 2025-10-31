package tokens_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/theopenlane/iam/tokens"
)

func TestConfigValidate(t *testing.T) {
	validConfig := tokens.Config{
		Audience:        "http://localhost:3000",
		Issuer:          "http://localhost:3001",
		AccessDuration:  1 * time.Hour,
		RefreshDuration: 2 * time.Hour,
		RefreshOverlap:  -15 * time.Minute,
	}

	t.Run("valid configuration", func(t *testing.T) {
		err := validConfig.Validate()
		require.NoError(t, err)
	})

	t.Run("missing audience", func(t *testing.T) {
		conf := validConfig
		conf.Audience = ""
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrAudienceRequired)
	})

	t.Run("missing issuer", func(t *testing.T) {
		conf := validConfig
		conf.Issuer = ""
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrIssuerRequired)
	})

	t.Run("access duration too short", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 1 * time.Minute
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrAccessDurationInvalid)
	})

	t.Run("access duration too long", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 48 * time.Hour
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrAccessDurationInvalid)
	})

	t.Run("access duration negative", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = -1 * time.Hour
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrAccessDurationInvalid)
	})

	t.Run("access duration zero", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 0
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrAccessDurationInvalid)
	})

	t.Run("refresh duration too short", func(t *testing.T) {
		conf := validConfig
		conf.RefreshDuration = 5 * time.Minute
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshDurationInvalid)
	})

	t.Run("refresh duration too long", func(t *testing.T) {
		conf := validConfig
		conf.RefreshDuration = 60 * 24 * time.Hour // 60 days
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshDurationInvalid)
	})

	t.Run("refresh duration negative", func(t *testing.T) {
		conf := validConfig
		conf.RefreshDuration = -1 * time.Hour
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshDurationInvalid)
	})

	t.Run("refresh duration zero", func(t *testing.T) {
		conf := validConfig
		conf.RefreshDuration = 0
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshDurationInvalid)
	})

	t.Run("refresh overlap positive", func(t *testing.T) {
		conf := validConfig
		conf.RefreshOverlap = 15 * time.Minute
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshOverlapInvalid)
	})

	t.Run("refresh overlap too large", func(t *testing.T) {
		conf := validConfig
		conf.RefreshOverlap = -2 * time.Hour
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshOverlapInvalid)
	})

	t.Run("refresh duration not greater than access duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 2 * time.Hour
		conf.RefreshDuration = 2 * time.Hour
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshDurationTooShort)
	})

	t.Run("refresh duration less than access duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 2 * time.Hour
		conf.RefreshDuration = 1 * time.Hour
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshDurationTooShort)
	})

	t.Run("refresh overlap too large for access duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 30 * time.Minute
		conf.RefreshOverlap = -30 * time.Minute
		err := conf.Validate()
		require.ErrorIs(t, err, tokens.ErrRefreshOverlapInvalid)
	})

	t.Run("minimum valid access duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = tokens.MinAccessDuration
		conf.RefreshDuration = tokens.MinRefreshDuration
		conf.RefreshOverlap = -1 * time.Minute
		err := conf.Validate()
		require.NoError(t, err)
	})

	t.Run("maximum valid access duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = tokens.MaxAccessDuration
		conf.RefreshDuration = 48 * time.Hour
		conf.RefreshOverlap = -1 * time.Hour
		err := conf.Validate()
		require.NoError(t, err)
	})

	t.Run("minimum valid refresh duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 10 * time.Minute
		conf.RefreshDuration = tokens.MinRefreshDuration
		conf.RefreshOverlap = -1 * time.Minute
		err := conf.Validate()
		require.NoError(t, err)
	})

	t.Run("maximum valid refresh duration", func(t *testing.T) {
		conf := validConfig
		conf.AccessDuration = 1 * time.Hour
		conf.RefreshDuration = tokens.MaxRefreshDuration
		conf.RefreshOverlap = -15 * time.Minute
		err := conf.Validate()
		require.NoError(t, err)
	})
}

func TestAPITokenKeyConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		keyConfig tokens.APITokenKeyConfig
		wantErr   error
	}{
		{
			name: "valid active key with raw secret",
			keyConfig: tokens.APITokenKeyConfig{
				Secret: "this-is-a-valid-secret-that-is-at-least-32-bytes-long",
				Status: string(tokens.KeyStatusActive),
			},
			wantErr: nil,
		},
		{
			name: "valid deprecated key",
			keyConfig: tokens.APITokenKeyConfig{
				Secret: "this-is-a-valid-secret-that-is-at-least-32-bytes-long",
				Status: string(tokens.KeyStatusDeprecated),
			},
			wantErr: nil,
		},
		{
			name: "valid revoked key",
			keyConfig: tokens.APITokenKeyConfig{
				Secret: "this-is-a-valid-secret-that-is-at-least-32-bytes-long",
				Status: string(tokens.KeyStatusRevoked),
			},
			wantErr: nil,
		},
		{
			name: "invalid status",
			keyConfig: tokens.APITokenKeyConfig{
				Secret: "this-is-a-valid-secret-that-is-at-least-32-bytes-long",
				Status: "invalid",
			},
			wantErr: tokens.ErrAPITokenStatusInvalid,
		},
		{
			name: "secret too short",
			keyConfig: tokens.APITokenKeyConfig{
				Secret: "short",
				Status: string(tokens.KeyStatusActive),
			},
			wantErr: tokens.ErrAPITokenSecretTooShort,
		},
		{
			name: "empty secret is allowed",
			keyConfig: tokens.APITokenKeyConfig{
				Secret: "",
				Status: string(tokens.KeyStatusActive),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.keyConfig.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAPITokenConfig_Validate(t *testing.T) {
	validSecret := "this-is-a-valid-secret-that-is-at-least-32-bytes-long"

	tests := []struct {
		name    string
		config  tokens.APITokenConfig
		wantErr error
	}{
		{
			name: "valid config with one active key",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
				Keys: map[string]tokens.APITokenKeyConfig{
					"v1": {
						Secret: validSecret,
						Status: string(tokens.KeyStatusActive),
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "valid config with one active and one deprecated key",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
				Keys: map[string]tokens.APITokenKeyConfig{
					"v1": {
						Secret: validSecret,
						Status: string(tokens.KeyStatusDeprecated),
					},
					"v2": {
						Secret: validSecret,
						Status: string(tokens.KeyStatusActive),
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "valid config with env prefix only",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
				Keys:      nil,
			},
			wantErr: nil,
		},
		{
			name: "no keys and no env prefix",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: "",
				Keys:      nil,
			},
			wantErr: tokens.ErrAPITokenEnvPrefixRequired,
		},
		{
			name: "no active keys",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
				Keys: map[string]tokens.APITokenKeyConfig{
					"v1": {
						Secret: validSecret,
						Status: string(tokens.KeyStatusDeprecated),
					},
				},
			},
			wantErr: tokens.ErrAPITokenNoActive,
		},
		{
			name: "multiple active keys",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
				Keys: map[string]tokens.APITokenKeyConfig{
					"v1": {
						Secret: validSecret,
						Status: string(tokens.KeyStatusActive),
					},
					"v2": {
						Secret: validSecret,
						Status: string(tokens.KeyStatusActive),
					},
				},
			},
			wantErr: tokens.ErrAPITokenMultipleActive,
		},
		{
			name: "invalid key configuration",
			config: tokens.APITokenConfig{
				Enabled:   true,
				EnvPrefix: tokens.DefaultAPITokenEnvPrefix,
				Keys: map[string]tokens.APITokenKeyConfig{
					"v1": {
						Secret: "short",
						Status: string(tokens.KeyStatusActive),
					},
				},
			},
			wantErr: tokens.ErrAPITokenSecretTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
