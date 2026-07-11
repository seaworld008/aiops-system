package credential

import (
	"context"
	"errors"
	"reflect"
)

var (
	ErrInvalidIssuerRegistry      = errors.New("invalid durable issuer registry")
	ErrDurableIssuerNotRegistered = errors.New("durable issuer is not registered")
)

type IssuerRegistration struct {
	Selection DurableIssuerResolveRequest
	Profile   DurableIssuerProfile
	Issuer    DurableIssuer
}

// IssuerRegistry is immutable after construction and performs exact tuple
// lookup. It has no wildcard, prefix, default, or cross-tenant fallback.
type IssuerRegistry struct {
	issuers map[DurableIssuerResolveRequest]ResolvedDurableIssuer
}

type scopedDurableIssuerIdentity struct {
	tenantID       string
	workspaceID    string
	environmentID  string
	issuerID       string
	issuerRevision string
}

func NewIssuerRegistry(registrations []IssuerRegistration) (*IssuerRegistry, error) {
	if len(registrations) == 0 {
		return nil, ErrInvalidIssuerRegistry
	}
	issuers := make(map[DurableIssuerResolveRequest]ResolvedDurableIssuer, len(registrations))
	identities := make(map[scopedDurableIssuerIdentity]ResolvedDurableIssuer, len(registrations))
	for _, registration := range registrations {
		resolved := ResolvedDurableIssuer{Profile: registration.Profile, Issuer: registration.Issuer}
		if !validDurableSelection(registration.Selection) || !validDurableResolution(resolved) ||
			!stableDurableIssuerIdentity(resolved.Issuer) {
			return nil, ErrInvalidIssuerRegistry
		}
		if _, duplicate := issuers[registration.Selection]; duplicate {
			return nil, ErrInvalidIssuerRegistry
		}
		identity := scopedDurableIssuerIdentity{
			tenantID: registration.Selection.TenantID, workspaceID: registration.Selection.WorkspaceID,
			environmentID: registration.Selection.EnvironmentID, issuerID: registration.Profile.IssuerID,
			issuerRevision: registration.Profile.Revision,
		}
		if existing, duplicate := identities[identity]; duplicate {
			if existing.Profile != resolved.Profile || existing.Issuer != resolved.Issuer {
				return nil, ErrInvalidIssuerRegistry
			}
		} else {
			identities[identity] = resolved
		}
		issuers[registration.Selection] = resolved
	}
	return &IssuerRegistry{issuers: issuers}, nil
}

func stableDurableIssuerIdentity(issuer DurableIssuer) bool {
	return !nilInterface(issuer) && reflect.TypeOf(issuer).Comparable()
}

func (registry *IssuerRegistry) ResolveDurableIssuer(
	ctx context.Context,
	selection DurableIssuerResolveRequest,
) (ResolvedDurableIssuer, error) {
	if registry == nil || ctx == nil || ctx.Err() != nil || !validDurableSelection(selection) {
		return ResolvedDurableIssuer{}, ErrDurableIssuerNotRegistered
	}
	resolved, exists := registry.issuers[selection]
	if !exists || !validDurableResolution(resolved) {
		return ResolvedDurableIssuer{}, ErrDurableIssuerNotRegistered
	}
	return resolved, nil
}

var _ durableIssuerResolver = (*IssuerRegistry)(nil)
