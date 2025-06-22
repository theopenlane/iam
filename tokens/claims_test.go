package tokens_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/tokens"
)

func TestClaimsParseOrgID(t *testing.T) {
	claims := &tokens.Claims{}
	require.Equal(t, ulids.Null, claims.ParseOrgID())

	claims.OrgID = "notvalid"
	require.Equal(t, ulids.Null, claims.ParseOrgID())

	orgID := ulids.New()
	claims.OrgID = orgID.String()
	require.Equal(t, orgID, claims.ParseOrgID())
}

func TestClaimsParseUserID(t *testing.T) {
	claims := &tokens.Claims{}
	require.Equal(t, ulids.Null, claims.ParseUserID())

	claims.UserID = "notvalid"
	require.Equal(t, ulids.Null, claims.ParseUserID())

	userID := ulids.New()
	claims.UserID = userID.String()
	require.Equal(t, userID, claims.ParseUserID())
}

func TestClaimsHasScope(t *testing.T) {
	claims := &tokens.Claims{}
	require.False(t, claims.HasScope("read", "programs"))

	claims.Scopes = tokens.PermissionScopes{
		Read:  []string{"programs"},
		Write: []string{"tasks"},
		Admin: []string{"controls"},
	}

	require.True(t, claims.HasScope("read", "programs"))
	require.False(t, claims.HasScope("read", "tasks"))

	require.True(t, claims.HasScope("write", "tasks"))
	require.False(t, claims.HasScope("write", "programs"))

	require.True(t, claims.HasScope("admin", "controls"))
	require.False(t, claims.HasScope("admin", "programs"))
}
