package auth

import (
	"context"

	"github.com/theopenlane/logx"
)

// WithCallerIdentity adds the context caller's identity fields to the log context, making
// caller replacement and capability escalation visible on every log line; contexts
// without a caller pass through unchanged
func WithCallerIdentity(ctx context.Context) context.Context {
	caller, ok := CallerFromContext(ctx)
	if !ok {
		return ctx
	}

	fields := map[string]any{}

	if caller.SubjectID != "" {
		fields[logx.FieldSubjectID] = caller.SubjectID
	}

	if caller.SubjectEmail != "" {
		fields[logx.FieldSubjectEmail] = caller.SubjectEmail
	}

	if caller.OrganizationID != "" {
		fields[logx.FieldOrganizationID] = caller.OrganizationID
	}

	if caller.Capabilities != 0 {
		fields[logx.FieldCapabilities] = caller.Capabilities
	}

	return logx.WithFields(ctx, fields)
}
