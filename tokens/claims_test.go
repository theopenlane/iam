package tokens_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theopenlane/utils/ulids"

	"github.com/theopenlane/iam/tokens"
)

func TestClaimsParseOrgID(t *testing.T) {
	claims := &tokens.Claims{}
	assert.Equal(t, ulids.Null, claims.ParseOrgID())

	claims.OrgID = "notvalid"
	assert.Equal(t, ulids.Null, claims.ParseOrgID())

	orgID := ulids.New()
	claims.OrgID = orgID.String()
	assert.Equal(t, orgID, claims.ParseOrgID())
}

func TestClaimsParseUserID(t *testing.T) {
	claims := &tokens.Claims{}
	assert.Equal(t, ulids.Null, claims.ParseUserID())

	claims.UserID = "notvalid"
	assert.Equal(t, ulids.Null, claims.ParseUserID())

	userID := ulids.New()
	claims.UserID = userID.String()
	assert.Equal(t, userID, claims.ParseUserID())
}

func TestClaimsHasScope(t *testing.T) {
	claims := &tokens.Claims{}
	assert.False(t, claims.HasScope("read", "programs"))

	claims.Scopes = tokens.PermissionScopes{
		Read:  []string{"programs"},
		Write: []string{"tasks"},
		Admin: []string{"controls"},
	}

	assert.True(t, claims.HasScope("read", "programs"))
	assert.False(t, claims.HasScope("read", "tasks"))

	assert.True(t, claims.HasScope("write", "tasks"))
	assert.False(t, claims.HasScope("write", "programs"))

	assert.True(t, claims.HasScope("admin", "controls"))
	assert.False(t, claims.HasScope("admin", "programs"))
}
