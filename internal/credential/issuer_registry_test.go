package credential

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIssuerRegistryResolvesOnlyTheExactTrustedTuple(t *testing.T) {
	t.Parallel()

	selection := durableTestSelection()
	profile := DurableIssuerProfile{
		IssuerID: "vault-database-nonprod", Revision: "rev-17", CredentialTTL: 5 * time.Minute,
	}
	issuer := registryIssuer{profile: profile}
	registry, err := NewIssuerRegistry([]IssuerRegistration{{
		Selection: selection, Profile: profile, Issuer: issuer,
	}})
	if err != nil {
		t.Fatalf("NewIssuerRegistry() error = %v", err)
	}
	resolved, err := registry.ResolveDurableIssuer(context.Background(), selection)
	if err != nil || resolved.Profile != profile || resolved.Issuer != issuer {
		t.Fatalf("ResolveDurableIssuer(exact) = %#v, %v", resolved, err)
	}

	for name, mutate := range map[string]func(*DurableIssuerResolveRequest){
		"tenant":      func(value *DurableIssuerResolveRequest) { value.TenantID = "tenant-2" },
		"workspace":   func(value *DurableIssuerResolveRequest) { value.WorkspaceID = "workspace-2" },
		"environment": func(value *DurableIssuerResolveRequest) { value.EnvironmentID = "staging-2" },
		"action":      func(value *DurableIssuerResolveRequest) { value.ActionType = "OTHER_ACTION" },
		"connector":   func(value *DurableIssuerResolveRequest) { value.ConnectorID = "postgres-other" },
		"permission":  func(value *DurableIssuerResolveRequest) { value.Permission = "database.readonly" },
		"resource":    func(value *DurableIssuerResolveRequest) { value.Resource = "postgres://inventory/other" },
		"production":  func(value *DurableIssuerResolveRequest) { value.Production = true },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := selection
			mutate(&candidate)
			if _, resolveErr := registry.ResolveDurableIssuer(context.Background(), candidate); !errors.Is(resolveErr, ErrDurableIssuerNotRegistered) {
				t.Fatalf("ResolveDurableIssuer(%s mismatch) error = %v", name, resolveErr)
			}
		})
	}
}

func TestIssuerRegistryRejectsAmbiguousOrMismatchedRegistrations(t *testing.T) {
	t.Parallel()

	selection := durableTestSelection()
	profile := DurableIssuerProfile{
		IssuerID: "vault-database-nonprod", Revision: "rev-17", CredentialTTL: 5 * time.Minute,
	}
	valid := IssuerRegistration{Selection: selection, Profile: profile, Issuer: registryIssuer{profile: profile}}
	var typedNil *registryIssuer
	for name, registrations := range map[string][]IssuerRegistration{
		"empty":           nil,
		"duplicate tuple": {valid, valid},
		"production": func() []IssuerRegistration {
			candidate := valid
			candidate.Selection.Production = true
			return []IssuerRegistration{candidate}
		}(),
		"wildcard resource": func() []IssuerRegistration {
			candidate := valid
			candidate.Selection.Resource = "*"
			return []IssuerRegistration{candidate}
		}(),
		"typed nil issuer": func() []IssuerRegistration {
			candidate := valid
			candidate.Issuer = typedNil
			return []IssuerRegistration{candidate}
		}(),
		"issuer id mismatch": func() []IssuerRegistration {
			candidate := valid
			candidate.Issuer = registryIssuer{profile: DurableIssuerProfile{
				IssuerID: "vault-other", Revision: profile.Revision, CredentialTTL: profile.CredentialTTL,
			}}
			return []IssuerRegistration{candidate}
		}(),
		"issuer revision mismatch": func() []IssuerRegistration {
			candidate := valid
			candidate.Issuer = registryIssuer{profile: DurableIssuerProfile{
				IssuerID: profile.IssuerID, Revision: "rev-other", CredentialTTL: profile.CredentialTTL,
			}}
			return []IssuerRegistration{candidate}
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewIssuerRegistry(registrations); !errors.Is(err, ErrInvalidIssuerRegistry) {
				t.Fatalf("NewIssuerRegistry(%s) error = %v", name, err)
			}
		})
	}
}

func TestIssuerRegistryRequiresOneCanonicalIssuerPerPersistedScopedIdentity(t *testing.T) {
	t.Parallel()

	first := durableTestSelection()
	second := first
	second.ActionType = "database.rotate"
	profile := DurableIssuerProfile{
		IssuerID: "vault-database-nonprod", Revision: "rev-17", CredentialTTL: 5 * time.Minute,
	}
	issuer := &registryIssuer{profile: profile}
	registrations := []IssuerRegistration{
		{Selection: first, Profile: profile, Issuer: issuer},
		{Selection: second, Profile: profile, Issuer: issuer},
	}
	registry, err := NewIssuerRegistry(registrations)
	if err != nil {
		t.Fatalf("NewIssuerRegistry(canonical multi-binding) error = %v", err)
	}
	resolved, err := registry.ResolveDurableIssuer(context.Background(), second)
	if err != nil || resolved.Issuer != issuer || resolved.Profile != profile {
		t.Fatalf("ResolveDurableIssuer(second binding) = %#v, %v", resolved, err)
	}

	inconsistentIssuer := append([]IssuerRegistration(nil), registrations...)
	inconsistentIssuer[1].Issuer = &registryIssuer{profile: profile}
	if _, err := NewIssuerRegistry(inconsistentIssuer); !errors.Is(err, ErrInvalidIssuerRegistry) {
		t.Fatalf("NewIssuerRegistry(different issuer for persisted identity) error = %v", err)
	}

	inconsistentProfile := append([]IssuerRegistration(nil), registrations...)
	inconsistentProfile[1].Profile.CredentialTTL = 4 * time.Minute
	if _, err := NewIssuerRegistry(inconsistentProfile); !errors.Is(err, ErrInvalidIssuerRegistry) {
		t.Fatalf("NewIssuerRegistry(different profile for persisted identity) error = %v", err)
	}
}

type registryIssuer struct {
	profile DurableIssuerProfile
}

func (issuer registryIssuer) IssuerID() string       { return issuer.profile.IssuerID }
func (issuer registryIssuer) IssuerRevision() string { return issuer.profile.Revision }
func (registryIssuer) ValidateManager(context.Context) error {
	return nil
}
func (registryIssuer) CreateChild(context.Context, DurableChildCreateRequest) (DurableChild, error) {
	return DurableChild{}, errors.New("unexpected CreateChild")
}
func (registryIssuer) InspectChild(context.Context, *SensitiveReference, DurableChildInspectionRequest) error {
	return errors.New("unexpected InspectChild")
}
func (registryIssuer) IssueDynamic(context.Context, SensitiveValue, DurableDynamicIssueRequest) (DurableDynamicSecret, error) {
	return DurableDynamicSecret{}, errors.New("unexpected IssueDynamic")
}
