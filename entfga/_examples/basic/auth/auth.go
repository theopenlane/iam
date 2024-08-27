package auth

import (
	"context"
)

// GetUserIDFromContext is a placeholder function to get the user id from the context
// see implementation at https://github.com/theopenlane/core/blob/main/internal/httpserve/middleware/auth/user.go#L29
func GetUserIDFromContext(ctx context.Context) (string, error) {
	return "USERID", nil
}
