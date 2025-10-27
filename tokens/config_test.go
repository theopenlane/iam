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
