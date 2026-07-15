package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

func TestSourceReadRejectsInvalidInputBeforeQuery(t *testing.T) {
	repository := &Repository{}
	scope := assetcatalog.SourceScope{
		TenantID:    "10000000-0000-4000-8000-000000000201",
		WorkspaceID: "20000000-0000-4000-8000-000000000201",
	}
	zeroConstraint := assetcatalog.SourceReadConstraint{}

	if _, err := repository.GetSource(context.Background(), assetcatalog.SourceLocator{
		Scope: scope, SourceID: "60000000-0000-4000-8000-000000000201",
	}, zeroConstraint); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("GetSource() zero constraint error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.GetSourceRun(context.Background(), assetcatalog.SourceRunLocator{
		Scope: scope, RunID: "62000000-0000-4000-8000-000000000201",
	}, zeroConstraint); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("GetSourceRun() zero constraint error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.ListSources(context.Background(), assetcatalog.ListSourcesRequest{
		Scope: scope, Access: zeroConstraint, Limit: 10,
	}); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ListSources() zero constraint error = %v, want ErrInvalidRequest", err)
	}
	if _, err := repository.ResolveSourceScope(context.Background(), "not-a-uuid"); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ResolveSourceScope() malformed workspace error = %v, want ErrInvalidRequest", err)
	}
}

func TestSourceReadRejectsCursorDriftBeforeQuery(t *testing.T) {
	repository := &Repository{}
	access, err := assetcatalog.NewSourceReadConstraint([]string{
		"30000000-0000-4000-8000-000000000201",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := assetcatalog.ListSourcesRequest{
		Scope: assetcatalog.SourceScope{
			TenantID:    "10000000-0000-4000-8000-000000000201",
			WorkspaceID: "20000000-0000-4000-8000-000000000201",
		},
		Access: access,
		Limit:  10,
	}
	digest, err := request.QueryDigest()
	if err != nil {
		t.Fatal(err)
	}
	request.Cursor = &assetcatalog.SourceCursor{
		QueryDigest: digest,
		SourceID:    "60000000-0000-4000-8000-000000000201",
	}
	request.Kinds = []assetcatalog.SourceKind{assetcatalog.SourceKindManual}

	if _, err := repository.ListSources(context.Background(), request); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("ListSources() drifted cursor error = %v, want ErrInvalidRequest before query", err)
	}
}

func TestSourceRevisionProjectionValidatesAuthorityClosure(t *testing.T) {
	environmentID := "30000000-0000-4000-8000-000000000201"
	digest, err := assetcatalog.AuthorityScopeDigest([]string{environmentID})
	if err != nil {
		t.Fatal(err)
	}
	now := canonicalDatabaseTime(time.Date(2026, 7, 15, 12, 0, 0, 123456000, time.UTC))
	base := sourceRevisionProjectionWire{
		ID:                      "61000000-0000-4000-8000-000000000201",
		SourceID:                "60000000-0000-4000-8000-000000000201",
		TenantID:                "10000000-0000-4000-8000-000000000201",
		WorkspaceID:             "20000000-0000-4000-8000-000000000201",
		Revision:                1,
		Status:                  assetcatalog.SourceRevisionDraft,
		ProfileManifestSHA256:   strings.Repeat("1", 64),
		ProviderSchemaSHA256:    strings.Repeat("2", 64),
		SourceDefinitionDigest:  strings.Repeat("3", 64),
		CanonicalRevisionDigest: strings.Repeat("4", 64),
		SyncMode:                assetcatalog.SyncModeManual,
		AuthorityEnvironmentIDs: []string{environmentID},
		AuthorityOrdinals:       []int{1},
		AuthorityScopeDigest:    digest,
		RateLimitRequests:       1,
		RateLimitWindowSeconds:  1,
		BackpressureBaseSeconds: 1,
		BackpressureMaxSeconds:  1,
		ProfileCode:             assetcatalog.ProfileCode("MANUAL_V1"),
		CreatedBy:               "human-reviewer",
		ChangeReasonCode:        "INITIAL_CREATE",
		ExpectedSourceVersion:   1,
		Version:                 1,
		CreatedAt:               databaseJSONTime{Time: now},
		UpdatedAt:               databaseJSONTime{Time: now},
		ManifestSourceKind:      assetcatalog.SourceKindManual,
		ManifestProviderKind:    "MANUAL_V1",
		ManifestProfileCode:     assetcatalog.ProfileCode("MANUAL_V1"),
		ManifestSyncMode:        assetcatalog.SyncModeManual,
		EnvironmentMappingMode:  assetcatalog.EnvironmentMappingSingle,
		BindingValid:            true,
	}
	expected := assetcatalog.Source{
		ID: base.SourceID, TenantID: base.TenantID, WorkspaceID: base.WorkspaceID,
		Kind: assetcatalog.SourceKindManual, ProviderKind: "MANUAL_V1",
	}
	if _, ok := base.finish(&expected); !ok {
		t.Fatal("valid authority projection was rejected")
	}

	tests := []struct {
		name   string
		mutate func(*sourceRevisionProjectionWire)
	}{
		{name: "empty", mutate: func(value *sourceRevisionProjectionWire) {
			value.AuthorityEnvironmentIDs = nil
			value.AuthorityOrdinals = nil
		}},
		{name: "ordinal gap", mutate: func(value *sourceRevisionProjectionWire) {
			value.AuthorityOrdinals = []int{2}
		}},
		{name: "digest mismatch", mutate: func(value *sourceRevisionProjectionWire) {
			value.AuthorityScopeDigest = strings.Repeat("f", 64)
		}},
		{name: "non canonical UUID", mutate: func(value *sourceRevisionProjectionWire) {
			value.AuthorityEnvironmentIDs = []string{"30000000-0000-4000-8000-00000000020A"}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			candidate := base
			candidate.AuthorityEnvironmentIDs = append([]string(nil), base.AuthorityEnvironmentIDs...)
			candidate.AuthorityOrdinals = append([]int(nil), base.AuthorityOrdinals...)
			testCase.mutate(&candidate)
			if _, ok := candidate.finish(&expected); ok {
				t.Fatal("invalid authority projection was accepted")
			}
		})
	}
}

func TestSourceRunProjectionOmitsLeaseAndFence(t *testing.T) {
	now := canonicalDatabaseTime(time.Date(2026, 7, 15, 12, 0, 0, 123456000, time.UTC))
	started := now.Add(time.Second)
	heartbeat := started.Add(time.Second)
	wire := sourceRunProjectionWire{
		ID:                      "62000000-0000-4000-8000-000000000201",
		SourceID:                "60000000-0000-4000-8000-000000000201",
		TenantID:                "10000000-0000-4000-8000-000000000201",
		WorkspaceID:             "20000000-0000-4000-8000-000000000201",
		SourceRevision:          1,
		SourceRevisionDigest:    strings.Repeat("d", 64),
		Kind:                    assetcatalog.RunKindDiscovery,
		Status:                  assetcatalog.RunStatusRunning,
		Stage:                   assetcatalog.RunStageReading,
		StageChangedAt:          databaseJSONTime{Time: heartbeat},
		TriggerType:             assetcatalog.TriggerScheduled,
		NotBefore:               databaseJSONTime{Time: now},
		HeartbeatSequence:       1,
		CredentialCleanupStatus: assetcatalog.CredentialCleanupNotOpened,
		Version:                 2,
		CreatedAt:               databaseJSONTime{Time: now},
		StartedAt:               &databaseJSONTime{Time: started},
		HeartbeatAt:             &databaseJSONTime{Time: heartbeat},
	}
	run, ok := wire.finish()
	if !ok {
		t.Fatal("valid safe running projection was rejected")
	}
	if run.LeaseExpiresAt != nil || run.FenceEpoch != 0 {
		t.Fatalf("safe run returned lease/fence metadata: lease=%v fence=%d", run.LeaseExpiresAt, run.FenceEpoch)
	}
}
