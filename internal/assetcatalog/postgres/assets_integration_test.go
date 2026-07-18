package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/domain"
)

func TestAssetRepositoryScopeIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, func() string {
		return "70000000-0000-4000-8000-000000000201"
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	scope, err := repository.ResolveScope(context.Background(), fixture.workspaceID, fixture.environmentID)
	if err != nil {
		t.Fatalf("ResolveScope() error = %v", err)
	}
	want := (assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	})
	if scope != want {
		t.Fatalf("ResolveScope() = %#v, want %#v", scope, want)
	}

	_, err = repository.ResolveScope(
		context.Background(), fixture.workspaceID, "30000000-0000-4000-8000-000000000299",
	)
	if !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("ResolveScope(cross-scope) error = %v, want ErrNotFound", err)
	}
}

func TestAssetGovernanceWritesAreAtomicReplaySafeAndVersionedIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	owner := "platform-sre"
	update := assetcatalog.UpdateGovernanceCommand{
		Context:            assetMutationContext(t, scope, "asset-update-1", "a"),
		AssetID:            fixture.assetID,
		DisplayName:        "fixture-host-a-governed",
		OwnerGroup:         &owner,
		Criticality:        assetcatalog.CriticalityHigh,
		DataClassification: assetcatalog.DataClassificationConfidential,
		Labels:             map[string]string{"team": "platform"},
		ExpectedVersion:    1,
	}
	first, err := repository.UpdateGovernance(context.Background(), update)
	if err != nil {
		t.Fatalf("UpdateGovernance() error = %v", err)
	}
	if first.Asset.Version != 2 || first.Asset.DisplayName != update.DisplayName || first.Asset.OwnerGroup == nil ||
		*first.Asset.OwnerGroup != owner || first.Receipt.AuditID == "" || first.Receipt.IdempotentReplay {
		t.Fatalf("UpdateGovernance() = %#v", first)
	}
	replay, err := repository.UpdateGovernance(context.Background(), update)
	if err != nil || replay.Asset.ID != first.Asset.ID || replay.Asset.Version != first.Asset.Version ||
		replay.Receipt.AuditID != first.Receipt.AuditID || !replay.Receipt.IdempotentReplay {
		t.Fatalf("UpdateGovernance(replay) = (%#v, %v), want exact replay", replay, err)
	}

	stale := update.Clone()
	stale.Context = assetMutationContext(t, scope, "asset-update-stale", "b")
	if _, err := repository.UpdateGovernance(context.Background(), stale); !errors.Is(err, assetcatalog.ErrVersionConflict) {
		t.Fatalf("UpdateGovernance(stale) error = %v, want ErrVersionConflict", err)
	}
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM audit_records WHERE resource_type='ASSET' AND resource_id=$1 AND action='asset.governance.updated.v1'),
		  (SELECT count(*) FROM outbox_events WHERE aggregate_type='ASSET' AND aggregate_id=$1::uuid AND event_type='asset.governance.updated.v1')
	`, fixture.assetID).Scan(&auditCount, &outboxCount); err != nil {
		t.Fatalf("read governance side effects: %v", err)
	}
	if auditCount != 1 || outboxCount != 1 {
		t.Fatalf("governance side effects = audit:%d outbox:%d, want 1/1", auditCount, outboxCount)
	}

	transition := assetcatalog.TransitionCommand{
		Context: assetMutationContext(t, scope, "asset-transition-1", "c"), AssetID: fixture.assetID,
		To: assetcatalog.LifecycleQuarantined, ReasonCode: "SECURITY_REVIEW", ExpectedVersion: 2,
	}
	quarantined, err := repository.Transition(context.Background(), transition)
	if err != nil {
		t.Fatalf("Transition() error = %v", err)
	}
	if quarantined.Asset.Lifecycle != assetcatalog.LifecycleQuarantined || quarantined.Asset.Version != 3 {
		t.Fatalf("Transition() = %#v", quarantined)
	}
	var persistedReason, transitionPayload string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT audit.details->>'reason_code', event.payload::text
		FROM audit_records AS audit
		JOIN outbox_events AS event
		  ON event.tenant_id=audit.tenant_id AND event.workspace_id=audit.workspace_id
		 AND event.aggregate_id=audit.resource_id::uuid AND event.aggregate_version=3
		 AND event.event_type='asset.quarantined.v1'
		WHERE audit.id=$1::uuid
	`, quarantined.Receipt.AuditID).Scan(&persistedReason, &transitionPayload); err != nil {
		t.Fatalf("read transition evidence: %v", err)
	}
	if persistedReason != transition.ReasonCode {
		t.Fatalf("transition reason = %q, want %q", persistedReason, transition.ReasonCode)
	}
	for _, forbidden := range []string{"owner_group", "labels", "external_id", "platform-sre", "fixture-host"} {
		if strings.Contains(strings.ToLower(transitionPayload), strings.ToLower(forbidden)) {
			t.Fatalf("transition outbox leaked %q: %s", forbidden, transitionPayload)
		}
	}
	invalidTransition := transition
	invalidTransition.Context = assetMutationContext(t, scope, "asset-transition-invalid", "d")
	invalidTransition.To = assetcatalog.LifecycleActive
	invalidTransition.ExpectedVersion = 3
	if _, err := repository.Transition(context.Background(), invalidTransition); !errors.Is(err, assetcatalog.ErrInvalidRequest) {
		t.Fatalf("Transition(unowned edge) error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateAssetIsReceiptFirstAndAtomicallyClosesManualRunIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	owner := "manual-owner"
	command := assetcatalog.CreateAssetCommand{
		Context:  assetMutationContext(t, scope, "manual-asset-create-1", "e"),
		SourceID: fixture.sourceID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "manual-host-new", DisplayName: "manual host new", OwnerGroup: &owner,
		Criticality:        assetcatalog.CriticalityCritical,
		DataClassification: assetcatalog.DataClassificationRestricted,
		Labels:             map[string]string{"team": "platform", "tier": "critical"},
	}
	first, err := repository.Create(context.Background(), command)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if first.Asset.ID == "" || first.Asset.SourceID != fixture.sourceID || first.Asset.ExternalID != command.ExternalID ||
		first.Asset.Lifecycle != assetcatalog.LifecycleDiscovered || first.Asset.MappingStatus != domain.MappingUnresolved ||
		first.Asset.Version != 1 || first.Asset.OwnerGroup == nil || *first.Asset.OwnerGroup != owner ||
		first.Asset.Criticality != command.Criticality || first.Asset.DataClassification != command.DataClassification ||
		first.Asset.Labels["team"] != "platform" || first.Receipt.AuditID == "" || first.Receipt.IdempotentReplay {
		t.Fatalf("Create() = %#v", first)
	}
	replay, err := repository.Create(context.Background(), command)
	if err != nil || replay.Asset.ID != first.Asset.ID || replay.Asset.Version != first.Asset.Version ||
		replay.Receipt.AuditID != first.Receipt.AuditID || !replay.Receipt.IdempotentReplay {
		t.Fatalf("Create(replay) = (%#v, %v), want exact persisted result", replay, err)
	}
	conflict := command.Clone()
	conflict.DisplayName = "different semantic request"
	if _, err := repository.Create(context.Background(), conflict); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("Create(conflicting replay) error = %v, want ErrIdempotency", err)
	}
	missingSource := command.Clone()
	missingSource.SourceID = "40000000-0000-4000-8000-000000000299"
	if _, err := repository.Create(context.Background(), missingSource); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("Create(replay with nonexistent source) error = %v, want ErrIdempotency", err)
	}

	var assets, observations, details, runs, managementAudits, runReceipts, outbox, checkpoint int
	var payload, provenance string
	if err := harness.db.QueryRow(context.Background(), `
		SELECT
		  (SELECT count(*) FROM assets WHERE id=$1::uuid),
		  (SELECT count(*) FROM asset_observations WHERE id=(SELECT last_observation_id FROM assets WHERE id=$1::uuid)),
		  (SELECT count(*) FROM asset_type_details WHERE asset_id=$1::uuid),
		  (SELECT count(*) FROM asset_source_runs WHERE source_id=$2::uuid AND run_kind='MANUAL_MUTATION'),
		  (SELECT count(*) FROM audit_records WHERE resource_type='ASSET' AND resource_id=$1 AND action='asset.created.v1'),
		  (SELECT count(*) FROM audit_records WHERE resource_type='ASSET_SOURCE_RUN' AND action IN ('PAGE_APPLIED','ATTEMPT_CLEANED','TERMINAL_COMMITTED') AND resource_id=(SELECT last_success_run_id::text FROM asset_sources WHERE id=$2::uuid)),
		  (SELECT count(*) FROM outbox_events WHERE aggregate_id=$1::uuid AND event_type='asset.created.v1'),
		  (SELECT checkpoint_version FROM asset_sources WHERE id=$2::uuid),
		  (SELECT payload::text FROM outbox_events WHERE aggregate_id=$1::uuid AND event_type='asset.created.v1'),
		  (SELECT convert_from(field_provenance,'UTF8') FROM asset_observations WHERE id=(SELECT last_observation_id FROM assets WHERE id=$1::uuid))
	`, first.Asset.ID, fixture.sourceID).Scan(
		&assets, &observations, &details, &runs, &managementAudits, &runReceipts, &outbox, &checkpoint, &payload, &provenance,
	); err != nil {
		t.Fatalf("read MANUAL closure: %v", err)
	}
	if assets != 1 || observations != 1 || details != 1 || runs != 1 || managementAudits != 1 ||
		runReceipts != 3 || outbox != 1 || checkpoint != 1 {
		t.Fatalf("MANUAL closure counts = asset:%d observation:%d detail:%d run:%d management:%d receipts:%d outbox:%d checkpoint:%d",
			assets, observations, details, runs, managementAudits, runReceipts, outbox, checkpoint)
	}
	for _, forbidden := range []string{command.ExternalID, owner, "platform", "critical", "normalized_document", "provider_kind", "credential", "token"} {
		if strings.Contains(strings.ToLower(payload), strings.ToLower(forbidden)) {
			t.Fatalf("outbox payload leaked forbidden value %q: %s", forbidden, payload)
		}
	}
	for _, governanceField := range []string{"owner_group", "criticality", "data_classification", "labels"} {
		if strings.Contains(provenance, governanceField) {
			t.Fatalf("MANUAL observation provenance claimed governance field %q: %s", governanceField, provenance)
		}
	}
	secondCommand := command.Clone()
	secondCommand.Context = assetMutationContext(t, scope, "manual-asset-create-2", "7")
	secondCommand.ExternalID = "manual-host-next"
	secondCommand.DisplayName = "manual host next"
	secondResult, err := repository.Create(context.Background(), secondCommand)
	if err != nil || secondResult.Asset.ID == first.Asset.ID {
		t.Fatalf("Create(second sequence) = (%#v, %v)", secondResult, err)
	}
	var secondCheckpoint, secondRunCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT checkpoint_version,
		       (SELECT count(*) FROM asset_source_runs WHERE source_id=$1::uuid AND run_kind='MANUAL_MUTATION')
		FROM asset_sources WHERE id=$1::uuid
	`, fixture.sourceID).Scan(&secondCheckpoint, &secondRunCount); err != nil {
		t.Fatal(err)
	}
	if secondCheckpoint != 2 || secondRunCount != 2 {
		t.Fatalf("second MANUAL sequence = checkpoint:%d runs:%d, want 2/2", secondCheckpoint, secondRunCount)
	}
}

func TestCreateAssetRejectsCrossEnvironmentBeforeAllocatingRunIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	otherEnvironmentID := "30000000-0000-4000-8000-000000000299"
	execAssetSQL(t, harness.db, `
		INSERT INTO environments (id,tenant_id,workspace_id,name,kind)
		VALUES ($1,$2,$3,'fixture-other','PROD')
	`, otherEnvironmentID, fixture.tenantID, fixture.workspaceID)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: otherEnvironmentID,
	}
	command := assetcatalog.CreateAssetCommand{
		Context:  assetMutationContext(t, scope, "manual-cross-environment", "1"),
		SourceID: fixture.sourceID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "cross-environment", DisplayName: "cross environment",
		Criticality:        assetcatalog.CriticalityLow,
		DataClassification: assetcatalog.DataClassificationInternal,
		Labels:             map[string]string{},
	}
	if _, err := repository.Create(context.Background(), command); !errors.Is(err, assetcatalog.ErrScopeViolation) {
		t.Fatalf("Create(cross environment) error = %v, want ErrScopeViolation", err)
	}
	assertManualCreateRolledBack(t, harness.db, fixture.sourceID, command.Context.IdempotencyKey())
}

func TestCreateAssetRollsBackWholeClosureWhenOutboxFailsIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	execAssetSQL(t, harness.db, `
		SET ROLE aiops_schema_owner;
		CREATE FUNCTION reject_task3_asset_outbox() RETURNS trigger AS $$
		BEGIN
			IF NEW.event_type = 'asset.created.v1' THEN
				RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='test outbox rejection';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER reject_task3_asset_outbox
			BEFORE INSERT ON outbox_events FOR EACH ROW EXECUTE FUNCTION reject_task3_asset_outbox();
		RESET ROLE;
	`)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	command := assetcatalog.CreateAssetCommand{
		Context:  assetMutationContext(t, scope, "manual-outbox-rollback", "2"),
		SourceID: fixture.sourceID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "rollback-host", DisplayName: "rollback host",
		Criticality:        assetcatalog.CriticalityLow,
		DataClassification: assetcatalog.DataClassificationInternal,
		Labels:             map[string]string{},
	}
	_, createErr := repository.Create(context.Background(), command)
	if createErr == nil || createErr.Error() != "asset catalog repository failure" {
		t.Fatalf("Create(outbox failure) error = %v, want sanitized repository failure", createErr)
	}
	if errors.Is(createErr, assetcatalog.ErrStateConflict) ||
		errors.Is(createErr, assetcatalog.ErrUnavailable) {
		t.Fatalf("Create(outbox failure) error = %v, must not masquerade as state conflict or unavailable", createErr)
	}
	if strings.Contains(createErr.Error(), "test outbox rejection") ||
		strings.Contains(createErr.Error(), "55000") {
		t.Fatalf("Create(outbox failure) leaked injected PostgreSQL detail: %v", createErr)
	}
	assertManualCreateRolledBack(t, harness.db, fixture.sourceID, command.Context.IdempotencyKey())
}

func TestCreateAssetRejectsPersistedFenceMismatchAndRollsBackIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	execAssetSQL(t, harness.db, `
		SET ROLE aiops_schema_owner;
		CREATE FUNCTION corrupt_task3_manual_claim_fence() RETURNS trigger AS $$
		BEGIN
			IF OLD.status = 'QUEUED' AND NEW.status = 'RUNNING' AND NEW.run_kind = 'MANUAL_MUTATION' THEN
				NEW.fence_token_hash := repeat('0',64);
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
		CREATE TRIGGER aaa_corrupt_task3_manual_claim_fence
			BEFORE UPDATE ON asset_source_runs FOR EACH ROW EXECUTE FUNCTION corrupt_task3_manual_claim_fence();
		RESET ROLE;
	`)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	command := assetcatalog.CreateAssetCommand{
		Context:  assetMutationContext(t, scope, "manual-fence-mismatch", "3"),
		SourceID: fixture.sourceID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "fence-host", DisplayName: "fence host",
		Criticality:        assetcatalog.CriticalityLow,
		DataClassification: assetcatalog.DataClassificationInternal,
		Labels:             map[string]string{},
	}
	if _, err := repository.Create(context.Background(), command); !errors.Is(err, assetcatalog.ErrStateConflict) {
		t.Fatalf("Create(fence mismatch) error = %v, want ErrStateConflict", err)
	}
	assertManualCreateRolledBack(t, harness.db, fixture.sourceID, command.Context.IdempotencyKey())
}

func TestCreateAssetRejectsSameCodeManualProfileSemanticDriftBeforeRunIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	execAssetSQL(t, harness.db, `
		SET ROLE aiops_schema_owner;
		ALTER TABLE asset_source_revisions DISABLE TRIGGER asset_source_revisions_transition_guard;
		ALTER TABLE asset_source_revisions DISABLE TRIGGER asset_source_revisions_deferred_state_guard;
		UPDATE asset_source_revisions
		SET canonical_profile_manifest = convert_to(
		      replace(convert_from(canonical_profile_manifest,'UTF8'),'65536','65535'),
		      'UTF8'
		    ),
		    profile_manifest_sha256 = encode(sha256(convert_to(
		      replace(convert_from(canonical_profile_manifest,'UTF8'),'65536','65535'),
		      'UTF8'
		    )),'hex')
		WHERE id = $1::uuid;
		ALTER TABLE asset_source_revisions ENABLE TRIGGER asset_source_revisions_transition_guard;
		ALTER TABLE asset_source_revisions ENABLE TRIGGER asset_source_revisions_deferred_state_guard;
		RESET ROLE;
	`, fixture.revisionID)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	command := assetcatalog.CreateAssetCommand{
		Context:  assetMutationContext(t, scope, "manual-profile-drift", "8"),
		SourceID: fixture.sourceID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "profile-drift-host", DisplayName: "profile drift host",
		Criticality:        assetcatalog.CriticalityLow,
		DataClassification: assetcatalog.DataClassificationInternal,
		Labels:             map[string]string{},
	}
	if _, err := repository.Create(context.Background(), command); !errors.Is(err, assetcatalog.ErrStateConflict) {
		t.Fatalf("Create(profile drift) error = %v, want ErrStateConflict", err)
	}
	assertManualCreateRolledBack(t, harness.db, fixture.sourceID, command.Context.IdempotencyKey())
}

func TestConcurrentCreateAssetHasOneClosureAndOneReceiptReplayIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	command := assetcatalog.CreateAssetCommand{
		Context:  assetMutationContext(t, scope, "manual-concurrent-create", "4"),
		SourceID: fixture.sourceID, Kind: assetcatalog.KindLinuxVM,
		ExternalID: "concurrent-host", DisplayName: "concurrent host",
		Criticality:        assetcatalog.CriticalityMedium,
		DataClassification: assetcatalog.DataClassificationInternal,
		Labels:             map[string]string{},
	}
	type callResult struct {
		result assetcatalog.AssetMutationResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan callResult, 2)
	for range 2 {
		go func() {
			<-start
			result, callErr := repository.Create(context.Background(), command)
			results <- callResult{result: result, err: callErr}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent Create errors = %v / %v", first.err, second.err)
	}
	if first.result.Asset.ID != second.result.Asset.ID ||
		first.result.Receipt.IdempotentReplay == second.result.Receipt.IdempotentReplay {
		t.Fatalf("concurrent Create results = %#v / %#v", first.result, second.result)
	}
	var runCount, assetCount, auditCount int
	if err := harness.db.QueryRow(context.Background(), `
		SELECT
		 (SELECT count(*) FROM asset_source_runs WHERE source_id=$1::uuid AND run_kind='MANUAL_MUTATION'),
		 (SELECT count(*) FROM assets WHERE source_id=$1::uuid AND external_id='concurrent-host'),
		 (SELECT count(*) FROM audit_records WHERE workspace_id=$2::uuid AND request_id='manual-concurrent-create')
	`, fixture.sourceID, fixture.workspaceID).Scan(&runCount, &assetCount, &auditCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || assetCount != 1 || auditCount != 1 {
		t.Fatalf("concurrent closure counts = run:%d asset:%d receipt:%d", runCount, assetCount, auditCount)
	}
}

func TestConcurrentGovernanceUpdatesYieldOneVersionWinnerIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, deterministicAssetIDGenerator())
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
	}
	commands := []assetcatalog.UpdateGovernanceCommand{
		{
			Context: assetMutationContext(t, scope, "concurrent-update-a", "5"), AssetID: fixture.assetID,
			DisplayName: "winner a", Criticality: assetcatalog.CriticalityHigh,
			DataClassification: assetcatalog.DataClassificationInternal, Labels: map[string]string{}, ExpectedVersion: 1,
		},
		{
			Context: assetMutationContext(t, scope, "concurrent-update-b", "6"), AssetID: fixture.assetID,
			DisplayName: "winner b", Criticality: assetcatalog.CriticalityCritical,
			DataClassification: assetcatalog.DataClassificationInternal, Labels: map[string]string{}, ExpectedVersion: 1,
		},
	}
	start := make(chan struct{})
	errorsFound := make(chan error, 2)
	for _, command := range commands {
		command := command
		go func() {
			<-start
			_, callErr := repository.UpdateGovernance(context.Background(), command)
			errorsFound <- callErr
		}()
	}
	close(start)
	firstErr, secondErr := <-errorsFound, <-errorsFound
	successes, conflicts := 0, 0
	for _, callErr := range []error{firstErr, secondErr} {
		switch {
		case callErr == nil:
			successes++
		case errors.Is(callErr, assetcatalog.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent UpdateGovernance error = %v", callErr)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent UpdateGovernance outcomes = success:%d conflict:%d", successes, conflicts)
	}
}

func assertManualCreateRolledBack(t *testing.T, database *pgxpool.Pool, sourceID, requestID string) {
	t.Helper()
	var runs, assets, observations, details, audits, outbox, checkpoint int
	var lastSuccessID *string
	if err := database.QueryRow(context.Background(), `
		SELECT
		 (SELECT count(*) FROM asset_source_runs WHERE source_id=$1::uuid AND run_kind='MANUAL_MUTATION'),
		 (SELECT count(*) FROM assets WHERE source_id=$1::uuid),
		 (SELECT count(*) FROM asset_observations WHERE source_id=$1::uuid),
		 (SELECT count(*) FROM asset_type_details WHERE source_id=$1::uuid),
		 (SELECT count(*) FROM audit_records WHERE request_id=$2),
		 (SELECT count(*) FROM outbox_events WHERE aggregate_type='ASSET' AND event_type='asset.created.v1'),
		 (SELECT checkpoint_version FROM asset_sources WHERE id=$1::uuid),
		 (SELECT last_success_run_id::text FROM asset_sources WHERE id=$1::uuid)
	`, sourceID, requestID).Scan(
		&runs, &assets, &observations, &details, &audits, &outbox, &checkpoint, &lastSuccessID,
	); err != nil {
		t.Fatalf("read rollback state: %v", err)
	}
	if runs != 0 || assets != 0 || observations != 0 || details != 0 || audits != 0 || outbox != 0 ||
		checkpoint != 0 || lastSuccessID != nil {
		t.Fatalf("partial MANUAL closure remained = run:%d asset:%d observation:%d detail:%d audit:%d outbox:%d checkpoint:%d last:%v",
			runs, assets, observations, details, audits, outbox, checkpoint, lastSuccessID)
	}
}

func seedEligibleManualSource(t *testing.T, database *pgxpool.Pool) assetCatalogFixture {
	t.Helper()
	fixture := seedDraftAssetCatalog(t, database)
	proof := repeatAssetDigest("f")
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin validation closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	execAssetSQL(t, tx, `
		INSERT INTO asset_source_runs (
			id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
			run_kind,trigger_type,gate_revision,idempotency_key,request_hash,checkpoint_version
		) SELECT $1,$2,$3,$4,1,$5,'VALIDATION','HUMAN',gate_revision,'validate-revision-1',repeat('1',64),0
		FROM asset_sources WHERE id=$4
	`, fixture.validationRunID, fixture.tenantID, fixture.workspaceID, fixture.sourceID, fixture.revisionDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_revisions SET state='VALIDATING',validation_run_id=$2,validation_digest=NULL,version=version+1
		WHERE id=$1
	`, fixture.revisionID, fixture.validationRunID)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs SET status='RUNNING',stage_code='VALIDATING',lease_owner='validation-worker',
			lease_expires_at=statement_timestamp()+interval '5 minutes',fence_epoch=1,fence_token_hash=repeat('2',64),
			heartbeat_sequence=1,heartbeat_at=statement_timestamp(),version=version+1 WHERE id=$1
	`, fixture.validationRunID)
	cleanupDigest := sourceRunNoCredentialDigest(t, tx, fixture.validationRunID)
	insertCleanupAudit(t, tx, fixture, fixture.validationRunID, 0, cleanupDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs SET status='FINALIZING',stage_code='CLEANING_UP',work_result_kind='VALIDATION_PROOF',
			work_result_status='SUCCEEDED',work_result_digest=$2,work_result_recorded_at=statement_timestamp(),
			validation_outcome='SUCCEEDED',validation_digest=$2,validation_proof_digest=$2,
			cleanup_status='NO_CREDENTIAL',cleanup_digest=$3,version=version+1 WHERE id=$1
	`, fixture.validationRunID, proof, cleanupDigest)
	terminalDigest := sourceRunTerminalDigest(t, tx, fixture.validationRunID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_runs SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,version=version+1
		WHERE id=$1
	`, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
		UPDATE asset_source_revisions SET state='VALIDATED',validation_digest=$2,version=version+1 WHERE id=$1
	`, fixture.revisionID, proof)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit validation closure: %v", err)
	}
	execAssetSQL(t, database, `UPDATE asset_source_revisions SET state='PUBLISHED',version=version+1 WHERE id=$1`, fixture.revisionID)
	execAssetSQL(t, database, `
		UPDATE asset_sources SET gate_status='AVAILABLE',gate_reason_code=NULL,gate_revision=gate_revision+1,
			validated_run_id=$2,validation_digest=$3,validated_binding_digest=$4,version=version+1 WHERE id=$1
	`, fixture.sourceID, fixture.validationRunID, proof, fixture.revisionDigest)
	return fixture
}

func deterministicAssetIDGenerator() func() string {
	var (
		mutex sync.Mutex
		next  = 1
	)
	return func() string {
		mutex.Lock()
		defer mutex.Unlock()
		value := fmt.Sprintf("70000000-0000-4000-8000-%012d", next)
		next++
		return value
	}
}

func assetMutationContext(t *testing.T, scope assetcatalog.Scope, idempotencyKey, digestCharacter string) assetcatalog.MutationContext {
	t.Helper()
	when := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	value, err := assetcatalog.NewMutationContext(authn.Principal{
		Subject: "asset-manager", TenantID: scope.TenantID, AuthenticatedAt: when,
	}, scope, assetcatalog.MutationMetadata{
		TraceID: "trace-" + idempotencyKey, IdempotencyKey: idempotencyKey,
		RequestHash: repeatAssetDigest(digestCharacter),
	})
	if err != nil {
		t.Fatalf("NewMutationContext() error = %v", err)
	}
	return value
}

func repeatAssetDigest(character string) string {
	result := ""
	for len(result) < 64 {
		result += character
	}
	return result[:64]
}

func TestAssetRepositoryGetIsCompositeScopedIntegration(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedGovernedManualCatalog(t, harness.db)
	repository, err := assetpostgres.New(harness.application, time.Now, func() string {
		return "70000000-0000-4000-8000-000000000202"
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	asset, err := repository.Get(context.Background(), assetcatalog.AssetLocator{
		Scope: assetcatalog.Scope{
			TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID, EnvironmentID: fixture.environmentID,
		},
		AssetID: fixture.assetID,
	})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if asset.ID != fixture.assetID || asset.SourceID != fixture.sourceID ||
		asset.Scope.TenantID != fixture.tenantID || asset.Scope.WorkspaceID != fixture.workspaceID ||
		asset.Scope.EnvironmentID != fixture.environmentID {
		t.Fatalf("Get() = %#v, want exact composite scope", asset)
	}
	if err := asset.Validate(); err != nil {
		t.Fatalf("Get().Validate() error = %v", err)
	}

	wrongScope := assetcatalog.Scope{
		TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
		EnvironmentID: "30000000-0000-4000-8000-000000000299",
	}
	_, err = repository.Get(context.Background(), assetcatalog.AssetLocator{Scope: wrongScope, AssetID: fixture.assetID})
	if !errors.Is(err, assetcatalog.ErrNotFound) {
		t.Fatalf("Get(cross-scope) error = %v, want ErrNotFound", err)
	}
}
