package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateOAuthState(t *testing.T) {
	first, err := GenerateOAuthState(8)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	second, err := GenerateOAuthState(8)
	require.NoError(t, err)
	require.NotEmpty(t, second)
	require.NotEqual(t, first, second)
}

func TestGenerateOAuthState_DefaultSize(t *testing.T) {
	state, err := GenerateOAuthState(0)
	require.NoError(t, err)
	require.NotEmpty(t, state)
}
