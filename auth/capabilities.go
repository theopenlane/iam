package auth

import (
	"context"
)

// Capability is a set of flags describing what a Caller is allowed to bypass.
// Values are explicit powers of two so they remain stable if constants are
// reordered, which matters when Caller is serialized by gala.
type Capability uint64

const (
	// CapBypassOrgFilter skips org-scoped interceptor filtering
	// This capability should only be used when a cross-org query is required to retrieve data
	// which is rarely ever required, and if required, usually only for an initial query
	// Examples would include: during organization creation, anonymous calls for initial lookup, and cross
	// organization async jobs
	// includes bypass on: org_mixin, subprocessors, trust center filters
	CapBypassOrgFilter Capability = 1 << 0
	// CapBypassFeatureCheck skips feature-flag checks
	// This capability is used to skip module checks, it is not needed when
	// the caller has InternalOperation as well; system admins get it from CapabilitiesForSystemAdmin
	CapBypassFeatureCheck Capability = 1 << 1
	// CapInternalRead marks the caller as a trusted internal read
	// Used to skip FGA filtering and query privacy checks on reads; mutations still require CapInternalOperation
	CapInternalRead Capability = 1 << 2
	// CapBypassManagedGroup bypasses managed-group mutation guards
	// used to allow updates to managed groups, which are only allowed
	// for internal requests and not all users
	CapBypassManagedGroup Capability = 1 << 3
	// CapBypassAuditLog suppresses audit log emission, skips writes to history tables, commonly used by integrations with heavy churn of data
	CapBypassAuditLog Capability = 1 << 4
	// CapInternalOperation marks the caller as a trusted internal service operation
	// This is the most common capability use to bypass certain restrictions
	CapInternalOperation Capability = 1 << 5
	// CapSystemAdmin is set by the auth middleware for callers holding the FGA system_admin relation
	// and grants platform-wide administrator access across all organizations
	CapSystemAdmin Capability = 1 << 7
	// CapTrustCenterAnonymous gives select bypass to checks
	// used for anonymous trust center visitors scoped to a single trust center
	CapTrustCenterAnonymous Capability = 1 << 8
	// CapQuestionnaireAnonymous gives select bypass to checks
	CapQuestionnaireAnonymous Capability = 1 << 9
	// CapOrgSupport grants org-scoped support access without bypassing the org filter or owner assignment
	CapOrgSupport Capability = 1 << 10
	// CapIntegrationActor is used to identify an integration installation virtual user/actor
	CapIntegrationActor Capability = 1 << 11
	// CapSystemSweep marks a full system job that skips org owner handling, e.g. backfills, org bootstrap and scheduled sweeps
	CapSystemSweep Capability = 1 << 12
)

// Has reports whether the Caller holds all of the specified capabilities
func (c *Caller) Has(caps Capability) bool {
	return c.Capabilities&caps == caps
}

// HasAny reports whether the Caller holds at least one of the specified capabilities
func (c *Caller) HasAny(caps Capability) bool {
	return c.Capabilities&caps != 0
}

// HasInLineage reports whether the Caller or its original system-admin lineage
// holds all of the specified capabilities
func (c *Caller) HasInLineage(caps Capability) bool {
	if c == nil {
		return false
	}

	if c.Has(caps) {
		return true
	}

	if c.OriginalSystemAdmin == nil {
		return false
	}

	return c.OriginalSystemAdmin.HasInLineage(caps)
}

// mergeCapabilities ORs a slice of Capability values into a single bitmask
func mergeCapabilities(caps []Capability) Capability {
	var merged Capability
	for _, c := range caps {
		merged |= c
	}

	return merged
}

// WithCapabilities returns a copy of the Caller with the given capabilities added
func (c *Caller) WithCapabilities(caps Capability) *Caller {
	cp := *c
	cp.Capabilities |= caps

	return &cp
}

// WithoutCapabilities returns a copy of the Caller with the given capabilities removed
func (c *Caller) WithoutCapabilities(caps Capability) *Caller {
	cp := *c
	cp.Capabilities &^= caps

	return &cp
}

// CapabilitiesForSystemAdmin returns capability flags for System Admins
func CapabilitiesForSystemAdmin(isSystemAdmin bool) Capability {
	if isSystemAdmin {
		return CapSystemAdmin | CapBypassOrgFilter | CapBypassFeatureCheck
	}

	return 0
}

// CapabilitiesForSupportCaller returns capability flags for support callers
func CapabilitiesForSupportCaller() Capability {
	return CapOrgSupport | CapBypassFeatureCheck
}

// CapabilitiesForOrgBootstrap are the capabilities required to bootstrap an organization
func CapabilitiesForOrgBootstrap() Capability {
	return CapBypassOrgFilter | CapSystemSweep | CapInternalOperation | CapBypassManagedGroup
}

// WithOrganizationBootstrapCapabilities adds the organization bootstrap capabilities to the caller in context
func WithOrganizationBootstrapCapabilities(ctx context.Context) context.Context {
	return WithCallerCapabilities(ctx, CapabilitiesForOrgBootstrap())
}

// WithCrossOrgContext adds the org filter bypass to the current caller which allows for cross-org queries
func WithCrossOrgContext(ctx context.Context) context.Context {
	return WithCallerCapabilities(ctx, CapBypassOrgFilter)
}

// WithInternalCrossOrgContext adds internal operation and the org filter bypass to the current caller:
// skips privacy, FGA, module, and edge checks and reads every org's rows; only for lookups before the org is known
func WithInternalCrossOrgContext(ctx context.Context) context.Context {
	return WithCallerCapabilities(ctx, CapInternalOperation|CapBypassOrgFilter)
}

// WithInternalOperationContext adds internal operation to the current caller, keeping its user and orgs:
// skips privacy, FGA, module, and edge checks but reads stay limited to the caller's orgs
func WithInternalOperationContext(ctx context.Context) context.Context {
	return WithCallerCapabilities(ctx, CapInternalOperation)
}

// WithInternalReadContext adds internal read to the current caller, keeping its user and orgs:
// skips FGA and query privacy checks on reads only, reads stay limited to the caller's orgs
func WithInternalReadContext(ctx context.Context) context.Context {
	return WithCallerCapabilities(ctx, CapInternalRead)
}

// WithInternalReadCrossOrgContext adds internal read and the org filter bypass to the current caller:
// skips FGA and query privacy checks on reads across every org's rows; only for lookups before the org is known
func WithInternalReadCrossOrgContext(ctx context.Context) context.Context {
	return WithCallerCapabilities(ctx, CapInternalRead|CapBypassOrgFilter)
}

// WithOrgInternalCaller replaces the current caller with OrgInternalCaller, dropping its user and any other capabilities
func WithOrgInternalCaller(ctx context.Context, orgID string) context.Context {
	return WithCaller(ctx, NewOrgInternalCaller(orgID))
}

// WithSystemSweepContext builds a cross-organization system caller context bypassing org filtering and FGA
func WithSystemSweepContext(ctx context.Context) context.Context {
	return WithCaller(ctx, &Caller{
		Capabilities: CapBypassOrgFilter | CapInternalOperation | CapSystemSweep,
	})
}

// WithCallerCapabilities adds the capabilities to a copy of the caller in context, creating an empty caller when none is set
// the created caller means later "no caller" checks no longer see an empty context, so only use it where a caller is expected
func WithCallerCapabilities(ctx context.Context, caps Capability) context.Context {
	caller := fromContextOrNew(ctx)

	return WithCaller(ctx, caller.WithCapabilities(caps))
}

// IsInternalRequest checks if the context caller has internal operation capability
func IsInternalRequest(ctx context.Context) bool {
	return HasInContextCaller(ctx, CapInternalOperation)
}

// IsInternalReadRequest checks if the context caller can bypass read authorization, via internal operation or internal read
func IsInternalReadRequest(ctx context.Context) bool {
	return HasAnyInContextCaller(ctx, CapInternalOperation|CapInternalRead)
}

// HasInContextCaller reports whether the caller in context holds all of the specified capabilities
func HasInContextCaller(ctx context.Context, caps Capability) bool {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return false
	}

	return c.Has(caps)
}

// HasInLineageContextCaller reports whether the caller in context or its original system-admin lineage holds all of the specified capabilities
func HasInLineageContextCaller(ctx context.Context, caps Capability) bool {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return false
	}

	return c.HasInLineage(caps)
}

// HasAnyInContextCaller reports whether the caller in context holds at least one of the specified capabilities
func HasAnyInContextCaller(ctx context.Context, caps Capability) bool {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return false
	}

	return c.HasAny(caps)
}

// HasCrossOrgCapabilities reports whether the caller in context has any capability that allows cross org queries
func HasCrossOrgCapabilities(ctx context.Context) bool {
	return HasAnyInContextCaller(ctx, CapBypassOrgFilter|CapSystemAdmin)
}

// HasFullSystemCapabilities reports whether the caller in context has all capabilities required for full system access
func HasFullSystemCapabilities(ctx context.Context) bool {
	return HasInContextCaller(ctx, CapBypassOrgFilter|CapInternalOperation|CapSystemSweep)
}

// HasAnonymousTrustCenterCapability reports whether the caller in context has the CapTrustCenterAnonymous
func HasAnonymousTrustCenterCapability(ctx context.Context) bool {
	return HasInContextCaller(ctx, CapTrustCenterAnonymous)
}
