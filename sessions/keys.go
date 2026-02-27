package sessions

import (
	"github.com/theopenlane/utils/contextx"
	"golang.org/x/oauth2"
)

var oauthTokenContextKey = contextx.NewKey[*oauth2.Token]()

var sessionDataContextKey = contextx.NewKey[*Session[map[string]any]]()

var userIDContextKey = contextx.NewKey[UserID]()
