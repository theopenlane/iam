package auth

import (
	"context"
	"testing"

	"github.com/theopenlane/logx"
)

func TestWithCallerIdentity(t *testing.T) {
	ctx := WithCaller(context.Background(), &Caller{
		SubjectID:      "user-1",
		SubjectEmail:   "user@example.com",
		OrganizationID: "org-1",
		Capabilities:   CapInternalOperation,
	})

	fields := logx.FieldsFromContext(WithCallerIdentity(ctx))

	if fields[logx.FieldSubjectID] != "user-1" {
		t.Fatalf("expected subject_id field, got %v", fields[logx.FieldSubjectID])
	}

	if fields[logx.FieldSubjectEmail] != "user@example.com" {
		t.Fatalf("expected subject_email field, got %v", fields[logx.FieldSubjectEmail])
	}

	if fields[logx.FieldOrganizationID] != "org-1" {
		t.Fatalf("expected organization_id field, got %v", fields[logx.FieldOrganizationID])
	}

	if fields[logx.FieldCapabilities] != CapInternalOperation {
		t.Fatalf("expected capabilities field, got %v", fields[logx.FieldCapabilities])
	}
}

func TestWithCallerIdentityWithoutCaller(t *testing.T) {
	ctx := context.Background()

	if got := WithCallerIdentity(ctx); got != ctx {
		t.Fatal("expected untouched context without a caller")
	}
}
