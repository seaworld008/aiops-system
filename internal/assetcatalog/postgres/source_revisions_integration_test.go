package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	assetpostgres "github.com/seaworld008/aiops-system/internal/assetcatalog/postgres"
	"github.com/seaworld008/aiops-system/internal/authn"
)

func TestSourceRevisionIntegrationManualLifecycleAndReplay(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}

	create := assetcatalog.CreateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "create-source-revision-2", "1"),
		SourceID: fixture.sourceID, ProfileCode: "MANUAL_V1",
		AuthorityEnvironmentIDs: []string{fixture.environmentID},
		ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion:   2,
	}
	created, err := repository.CreateRevision(context.Background(), create)
	if err != nil {
		t.Fatalf("CreateRevision() error = %v", err)
	}
	if created.Source.Version != 3 || created.Revision.Revision != 2 ||
		created.Revision.Status != assetcatalog.SourceRevisionDraft ||
		created.Revision.ExpectedSourceVersion != 2 ||
		created.Receipt.IdempotentReplay {
		t.Fatalf("CreateRevision() = %#v", created)
	}
	replay, err := repository.CreateRevision(context.Background(), create)
	if err != nil || !replay.Receipt.IdempotentReplay ||
		replay.Receipt.AuditID != created.Receipt.AuditID ||
		replay.Revision.CanonicalRevisionDigest != created.Revision.CanonicalRevisionDigest {
		t.Fatalf("CreateRevision(replay) = (%#v, %v)", replay, err)
	}
	changed := create
	changed.ChangeReasonCode = "DIFFERENT_REASON"
	if _, err := repository.CreateRevision(context.Background(), changed); !errors.Is(err, assetcatalog.ErrIdempotency) {
		t.Fatalf("CreateRevision(hash drift) error = %v", err)
	}

	validateCommand := assetcatalog.ValidateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "validate-source-revision-2", "2"),
		SourceID: fixture.sourceID, Revision: 2,
		ExpectedSourceVersion:   created.Source.Version,
		ExpectedRevisionVersion: created.Revision.Version,
		ExpectedRevisionDigest:  created.Revision.CanonicalRevisionDigest,
	}
	validated, err := repository.RequestValidation(context.Background(), validateCommand)
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	if validated.Source.GateStatus != assetcatalog.SourceGateValidating ||
		validated.Revision.Status != assetcatalog.SourceRevisionValidated ||
		validated.Run.Status != assetcatalog.RunStatusSucceeded ||
		validated.Run.CredentialCleanupStatus != assetcatalog.CredentialCleanupNoCredential ||
		validated.Run.ValidationProofDigest == "" {
		t.Fatalf("RequestValidation() = %#v", validated)
	}
	assertSourceValidationSystemReceipts(t, harness.db, validated.Run.ID)
	validationReplay, err := repository.RequestValidation(context.Background(), validateCommand)
	if err != nil || !validationReplay.Receipt.IdempotentReplay ||
		validationReplay.Run.ID != validated.Run.ID {
		t.Fatalf("RequestValidation(replay) = (%#v, %v)", validationReplay, err)
	}

	publishCommand := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-source-revision-2", "3"),
		SourceID: fixture.sourceID, Revision: 2, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion:    validated.Source.Version,
		ExpectedRevisionVersion:  validated.Revision.Version,
		ExpectedRevisionDigest:   validated.Revision.CanonicalRevisionDigest,
		ExpectedValidationRunID:  validated.Run.ID,
		ExpectedValidationDigest: validated.Run.ValidationProofDigest,
	}
	published, err := repository.Publish(context.Background(), publishCommand)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if published.Source.Status != assetcatalog.SourceStatusActive ||
		published.Source.GateStatus != assetcatalog.SourceGateAvailable ||
		published.Source.PublishedRevision != 2 ||
		published.Revision.Status != assetcatalog.SourceRevisionPublished ||
		published.Source.ValidatedRunID != validated.Run.ID {
		t.Fatalf("Publish() = %#v", published)
	}
	publishReplay, err := repository.Publish(context.Background(), publishCommand)
	if err != nil || !publishReplay.Receipt.IdempotentReplay ||
		publishReplay.Revision.Revision != published.Revision.Revision {
		t.Fatalf("Publish(replay) = (%#v, %v)", publishReplay, err)
	}

	disableCommand := assetcatalog.DisableSourceCommand{
		Context:  sourceRevisionMutationContext(t, scope, "disable-source", "4"),
		SourceID: fixture.sourceID, ReasonCode: "OPERATOR_DISABLED",
		ExpectedSourceVersion: published.Source.Version,
	}
	disabled, err := repository.Disable(context.Background(), disableCommand)
	if err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if disabled.Source.Status != assetcatalog.SourceStatusDisabled ||
		disabled.Source.GateStatus != assetcatalog.SourceGateUnavailable ||
		disabled.Source.GateReasonCode != "SOURCE_NOT_ACTIVE" {
		t.Fatalf("Disable() = %#v", disabled)
	}
	disableReplay, err := repository.Disable(context.Background(), disableCommand)
	if err != nil || !disableReplay.Receipt.IdempotentReplay ||
		disableReplay.Source.ID != disabled.Source.ID {
		t.Fatalf("Disable(replay) = (%#v, %v)", disableReplay, err)
	}
	assertSourceMutationSideEffectsDLP(
		t,
		harness.db,
		fixture.workspaceID,
		correctiveManualProfileManifestV1,
		`{"additionalProperties":false,"properties":{},"type":"object"}`,
		"MANUAL_V1",
		"additionalProperties",
		"canonical_profile_manifest",
		"canonical_provider_schema",
		"opaque://sanitized",
		"secret-canary",
		"https://endpoint.invalid",
		"authorization",
		"header-canary",
		"body-canary",
	)
}

func TestSourceRevisionIntegrationConcurrentCreateRevisionHasOneCASWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	commands := []assetcatalog.CreateSourceRevisionCommand{
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-revision-a", "a"),
			SourceID: fixture.sourceID, ProfileCode: "MANUAL_V1",
			AuthorityEnvironmentIDs: []string{fixture.environmentID},
			ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
			ExpectedSourceVersion:   2,
		},
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-revision-b", "b"),
			SourceID: fixture.sourceID, ProfileCode: "MANUAL_V1",
			AuthorityEnvironmentIDs: []string{fixture.environmentID},
			ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
			ExpectedSourceVersion:   2,
		},
	}
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			value, callErr := repository.CreateRevision(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	var winner assetcatalog.SourceRevisionMutation
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.value
		case errors.Is(result.err, assetcatalog.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent CreateRevision() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 ||
		winner.Source.Version != 3 || winner.Revision.Revision != 2 {
		t.Fatalf("concurrent CreateRevision outcomes = success:%d conflict:%d winner:%#v",
			successes, conflicts, winner)
	}
	var revisionCount, auditCount, auditResourceCount, outboxCount, outboxAggregateCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_source_revisions
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid),
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND action='asset.source.revision.created.v1'),
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND resource_type='ASSET_SOURCE' AND resource_id=$3
     AND action='asset.source.revision.created.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND event_type='asset.source.revision.created.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND aggregate_type='ASSET_SOURCE' AND aggregate_id=$3::uuid
     AND event_type='asset.source.revision.created.v1')
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(
		&revisionCount, &auditCount, &auditResourceCount, &outboxCount, &outboxAggregateCount,
	); err != nil {
		t.Fatal(err)
	}
	if revisionCount != 2 || auditCount != 1 || auditResourceCount != 1 ||
		outboxCount != 1 || outboxAggregateCount != 1 {
		t.Fatalf("concurrent CreateRevision side effects = revisions:%d audit:%d/%d outbox:%d/%d",
			revisionCount, auditResourceCount, auditCount, outboxAggregateCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationCreateRevisionOwnsCallerAuthorityMemoryBeforeAllocation(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	firstAllocationEntered := make(chan struct{})
	releaseAllocation := make(chan struct{})
	baseGenerator := deterministicAssetIDGenerator()
	allocationCount := 0
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		func() string {
			allocationCount++
			if allocationCount == 1 {
				close(firstAllocationEntered)
				<-releaseAllocation
			}
			return baseGenerator()
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	callerAuthorities := []string{fixture.environmentID}
	command := assetcatalog.CreateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "owned-authority-memory", "6"),
		SourceID: fixture.sourceID, ProfileCode: "MANUAL_V1",
		AuthorityEnvironmentIDs: callerAuthorities,
		ChangeReasonCode:        "SOURCE_CONFIGURATION_CHANGED",
		ExpectedSourceVersion:   2,
	}
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	result := make(chan callResult, 1)
	go func() {
		value, callErr := repository.CreateRevision(context.Background(), command)
		result <- callResult{value: value, err: callErr}
	}()
	<-firstAllocationEntered
	callerAuthorities[0] = "30000000-0000-4000-8000-000000000099"
	close(releaseAllocation)
	created := <-result
	if created.err != nil {
		t.Fatalf("CreateRevision(owned authority memory) error = %v", created.err)
	}
	if len(created.value.Revision.AuthorityEnvironmentIDs) != 1 ||
		created.value.Revision.AuthorityEnvironmentIDs[0] != fixture.environmentID {
		t.Fatalf("CreateRevision consumed caller mutation: %#v", created.value.Revision)
	}
}

func TestSourceRevisionIntegrationConcurrentManualPublishHasOneCASWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	validated, err := repository.RequestValidation(context.Background(), assetcatalog.ValidateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "prepare-concurrent-publish", "c"),
		SourceID: fixture.sourceID, Revision: 1,
		ExpectedSourceVersion: 2, ExpectedRevisionVersion: 1,
		ExpectedRevisionDigest: fixture.revisionDigest,
	})
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	commands := []assetcatalog.PublishSourceRevisionCommand{
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-publish-a", "a"),
			SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
			ExpectedSourceVersion:   validated.Source.Version,
			ExpectedRevisionVersion: validated.Revision.Version,
			ExpectedRevisionDigest:  validated.Revision.CanonicalRevisionDigest,
			ExpectedValidationRunID: validated.Run.ID, ExpectedValidationDigest: validated.Run.ValidationProofDigest,
		},
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-publish-b", "b"),
			SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
			ExpectedSourceVersion:   validated.Source.Version,
			ExpectedRevisionVersion: validated.Revision.Version,
			ExpectedRevisionDigest:  validated.Revision.CanonicalRevisionDigest,
			ExpectedValidationRunID: validated.Run.ID, ExpectedValidationDigest: validated.Run.ValidationProofDigest,
		},
	}
	type callResult struct {
		value assetcatalog.SourceRevisionMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			value, callErr := repository.Publish(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	var winner assetcatalog.SourceRevisionMutation
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.value
		case errors.Is(result.err, assetcatalog.ErrVersionConflict):
			conflicts++
		default:
			t.Fatalf("concurrent Publish() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 ||
		winner.Revision.Status != assetcatalog.SourceRevisionPublished ||
		winner.Source.GateStatus != assetcatalog.SourceGateAvailable {
		t.Fatalf("concurrent Publish outcomes = success:%d conflict:%d winner:%#v",
			successes, conflicts, winner)
	}
	var auditCount, auditResourceCount, outboxCount, outboxAggregateCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND action='asset.source.revision.published.v1'),
  (SELECT count(*) FROM audit_records
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND resource_type='ASSET_SOURCE' AND resource_id=$3
     AND action='asset.source.revision.published.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND event_type='asset.source.revision.published.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
     AND aggregate_type='ASSET_SOURCE' AND aggregate_id=$3::uuid
     AND event_type='asset.source.revision.published.v1')
`, fixture.tenantID, fixture.workspaceID, fixture.sourceID).Scan(
		&auditCount, &auditResourceCount, &outboxCount, &outboxAggregateCount,
	); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 || auditResourceCount != 1 ||
		outboxCount != 1 || outboxAggregateCount != 1 {
		t.Fatalf("concurrent Publish side effects = audit:%d/%d outbox:%d/%d",
			auditResourceCount, auditCount, outboxAggregateCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationPublishRejectsUnvalidatedRevisionWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revisionVersion int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,revision.version
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
WHERE source.id=$1::uuid
`, fixture.sourceID).Scan(&sourceVersion, &revisionVersion); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	command := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-unvalidated", "9"),
		SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion:    sourceVersion,
		ExpectedRevisionVersion:  revisionVersion,
		ExpectedRevisionDigest:   fixture.revisionDigest,
		ExpectedValidationRunID:  fixture.validationRunID,
		ExpectedValidationDigest: strings.Repeat("9", 64),
	}
	if _, err := repository.Publish(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrSourceRevisionNotValidated,
	) {
		t.Fatalf("Publish(unvalidated) error = %v", err)
	}
	var state, gateStatus string
	var persistedSourceVersion, persistedRevisionVersion int64
	var publishedRevision *int64
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  source.version,source.published_revision,source.gate_status,
  revision.version,revision.state,
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND request_id=$3),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.revision.published.v1')
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&persistedSourceVersion, &publishedRevision, &gateStatus,
		&persistedRevisionVersion, &state, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if persistedSourceVersion != sourceVersion || publishedRevision != nil ||
		gateStatus != "UNAVAILABLE" || persistedRevisionVersion != revisionVersion ||
		state != "DRAFT" || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("Publish(unvalidated) side effects = source-version:%d/%d published:%v gate:%s revision-version:%d/%d state:%s audit:%d outbox:%d",
			persistedSourceVersion, sourceVersion, publishedRevision, gateStatus,
			persistedRevisionVersion, revisionVersion, state, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationExternalValidatedPublishFailsClosedWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	proof := strings.Repeat("7", 64)
	finishSourceRevisionExternalValidationOnly(t, harness.db, fixture, proof)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revisionVersion, runVersion int64
	var gateStatus, revisionStatus, runStatus, sourceRunID string
	var publishedRevision *int64
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.gate_status,source.published_revision,
       source.validated_run_id::text,revision.version,revision.state,
       run.version,run.status
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID).Scan(
		&sourceVersion, &gateStatus, &publishedRevision, &sourceRunID,
		&revisionVersion, &revisionStatus, &runVersion, &runStatus,
	); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	command := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-external-closed", "5"),
		SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion: sourceVersion, ExpectedRevisionVersion: revisionVersion,
		ExpectedRevisionDigest:  fixture.revisionDigest,
		ExpectedValidationRunID: fixture.validationRunID, ExpectedValidationDigest: proof,
	}
	if _, err := repository.Publish(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrUnavailable,
	) {
		t.Fatalf("Publish(external unsupported) error = %v", err)
	}
	var persistedSourceVersion, persistedRevisionVersion, persistedRunVersion int64
	var persistedGateStatus, persistedRevisionStatus, persistedRunStatus, persistedSourceRunID string
	var persistedPublishedRevision *int64
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.gate_status,source.published_revision,
       source.validated_run_id::text,revision.version,revision.state,
       run.version,run.status,
       (SELECT count(*) FROM audit_records
        WHERE workspace_id=$2::uuid AND request_id=$3),
       (SELECT count(*) FROM outbox_events
        WHERE workspace_id=$2::uuid AND event_type='asset.source.revision.published.v1')
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=1
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&persistedSourceVersion, &persistedGateStatus, &persistedPublishedRevision,
		&persistedSourceRunID, &persistedRevisionVersion, &persistedRevisionStatus,
		&persistedRunVersion, &persistedRunStatus, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if persistedSourceVersion != sourceVersion || persistedGateStatus != gateStatus ||
		persistedPublishedRevision != nil || publishedRevision != nil ||
		persistedSourceRunID != sourceRunID || persistedRevisionVersion != revisionVersion ||
		persistedRevisionStatus != revisionStatus || persistedRunVersion != runVersion ||
		persistedRunStatus != runStatus || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("Publish(external unsupported) side effects = source-version:%d/%d gate:%s/%s published:%v/%v source-run:%s/%s revision-version:%d/%d revision:%s/%s run-version:%d/%d run:%s/%s audit:%d outbox:%d",
			persistedSourceVersion, sourceVersion, persistedGateStatus, gateStatus,
			persistedPublishedRevision, publishedRevision, persistedSourceRunID, sourceRunID,
			persistedRevisionVersion, revisionVersion, persistedRevisionStatus, revisionStatus,
			persistedRunVersion, runVersion, persistedRunStatus, runStatus, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationPublishRejectsVisibleValidationGateBindingDriftWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	revisionOneID := fixture.revisionID
	revisionOneDigest := fixture.revisionDigest
	revisionOneRunID := fixture.validationRunID
	revisionOneProof := strings.Repeat("7", 64)
	finishSourceRevisionExternalValidationOnly(t, harness.db, fixture, revisionOneProof)
	fixture = seedClosureExternalSuccessorDefinition(
		t, harness.db, fixture,
		"8f520000-0000-4000-8000-000000000002", 2, "EXTERNAL_V1",
		[]byte(`{"type":"object","version":2}`), "DEFINITION_CHANGE",
	)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	var sourceVersion int64
	if err := harness.db.QueryRow(context.Background(),
		`SELECT version FROM asset_sources WHERE id=$1::uuid`,
		fixture.sourceID,
	).Scan(&sourceVersion); err != nil {
		t.Fatal(err)
	}
	revisionTwoValidation, err := repository.RequestValidation(
		context.Background(),
		assetcatalog.ValidateSourceRevisionCommand{
			Context:  sourceRevisionMutationContext(t, scope, "validate-revision-two-gate-drift", "4"),
			SourceID: fixture.sourceID, Revision: 2,
			ExpectedSourceVersion: sourceVersion, ExpectedRevisionVersion: 1,
			ExpectedRevisionDigest: fixture.revisionDigest,
		},
	)
	if err != nil {
		t.Fatalf("RequestValidation(revision two) error = %v", err)
	}
	if revisionTwoValidation.Run.Status != assetcatalog.RunStatusQueued {
		t.Fatalf("revision two validation run = %#v", revisionTwoValidation.Run)
	}
	before := readSourceRevisionGateBindingSnapshot(
		t, harness.db, fixture.sourceID, revisionOneID, fixture.revisionID,
	)
	if before.GateStatus != "VALIDATING" ||
		before.GateReasonCode != "VALIDATION_IN_PROGRESS" ||
		before.SourceValidationDigest != "" || before.SourceBindingDigest != "" ||
		before.SourceValidationRunID != revisionTwoValidation.Run.ID ||
		before.RevisionOneValidationRunID != revisionOneRunID ||
		before.RevisionOneStatus != "VALIDATED" ||
		before.RevisionTwoStatus != "VALIDATING" ||
		before.RevisionTwoRunStatus != "QUEUED" {
		t.Fatalf("gate-binding drift fixture = %#v", before)
	}
	command := assetcatalog.PublishSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "publish-gate-binding-drift", "3"),
		SourceID: fixture.sourceID, Revision: 1, ReasonCode: "VALIDATION_REVIEWED",
		ExpectedSourceVersion:   before.SourceVersion,
		ExpectedRevisionVersion: before.RevisionOneVersion,
		ExpectedRevisionDigest:  revisionOneDigest,
		ExpectedValidationRunID: revisionOneRunID, ExpectedValidationDigest: revisionOneProof,
	}
	if _, err := repository.Publish(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrStateConflict,
	) {
		t.Fatalf("Publish(gate binding drift) error = %v", err)
	}
	after := readSourceRevisionGateBindingSnapshot(
		t, harness.db, fixture.sourceID, revisionOneID, fixture.revisionID,
	)
	var auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$1::uuid AND request_id=$2),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$1::uuid AND event_type='asset.source.revision.published.v1')
`, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if after != before || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("Publish(gate binding drift) side effects = before:%#v after:%#v audit:%d outbox:%d",
			before, after, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationDisableRejectsClaimedValidationWithoutSideEffects(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		finalizing bool
		wantStatus string
	}{
		{name: "running", wantStatus: "RUNNING"},
		{name: "finalizing", finalizing: true, wantStatus: "FINALIZING"},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			harness := newAssetCatalogHarness(t)
			harness.applyThroughAssetCatalog(t)
			fixture := seedDraftAssetCatalog(t, harness.db)
			fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
			if testCase.finalizing {
				prepareCleanupUncertainValidationRun(t, harness.db, fixture)
			}
			repository, err := assetpostgres.New(
				harness.application,
				func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
				deterministicAssetIDGenerator(),
			)
			if err != nil {
				t.Fatal(err)
			}
			var sourceVersion, revisionVersion, runVersion int64
			var sourceRunID, revisionRunID, cleanupStatus string
			if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.validated_run_id::text,
       revision.version,revision.validation_run_id::text,
       run.version,run.cleanup_status
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.validation_run_id=$2::uuid
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.validationRunID).Scan(
				&sourceVersion, &sourceRunID, &revisionVersion, &revisionRunID,
				&runVersion, &cleanupStatus,
			); err != nil {
				t.Fatal(err)
			}
			scope := assetcatalog.SourceScope{
				TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID,
			}
			command := assetcatalog.DisableSourceCommand{
				Context: sourceRevisionMutationContext(
					t, scope, "disable-"+testCase.name+"-validation", "8",
				),
				SourceID: fixture.sourceID, ReasonCode: "OPERATOR_DISABLED",
				ExpectedSourceVersion: sourceVersion,
			}
			if _, err := repository.Disable(context.Background(), command); !errors.Is(
				err, assetcatalog.ErrStateConflict,
			) {
				t.Fatalf("Disable(%s validation) error = %v", testCase.name, err)
			}
			var sourceStatus, gateStatus, runStatus, persistedSourceRunID string
			var persistedRevisionRunID, persistedCleanupStatus string
			var persistedSourceVersion, persistedRevisionVersion, persistedRunVersion int64
			var auditCount, outboxCount int
			if err := harness.db.QueryRow(context.Background(), `
SELECT
  source.version,source.status,source.gate_status,source.validated_run_id::text,
  revision.version,revision.validation_run_id::text,
  run.version,run.status,run.cleanup_status,
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$3::uuid AND request_id=$4),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$3::uuid AND event_type='asset.source.disabled.v1')
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.validation_run_id=$2::uuid
JOIN asset_source_runs AS run ON run.id=revision.validation_run_id
WHERE source.id=$1::uuid
`, fixture.sourceID, fixture.validationRunID, fixture.workspaceID,
				command.Context.IdempotencyKey()).Scan(
				&persistedSourceVersion, &sourceStatus, &gateStatus, &persistedSourceRunID,
				&persistedRevisionVersion, &persistedRevisionRunID,
				&persistedRunVersion, &runStatus, &persistedCleanupStatus,
				&auditCount, &outboxCount,
			); err != nil {
				t.Fatal(err)
			}
			if persistedSourceVersion != sourceVersion || sourceStatus != "ACTIVE" ||
				gateStatus != "VALIDATING" || persistedSourceRunID != sourceRunID ||
				persistedRevisionVersion != revisionVersion ||
				persistedRevisionRunID != revisionRunID ||
				persistedRunVersion != runVersion || runStatus != testCase.wantStatus ||
				persistedCleanupStatus != cleanupStatus || auditCount != 0 || outboxCount != 0 {
				t.Fatalf("Disable(%s validation) side effects = source-version:%d/%d source:%s gate:%s source-run:%s/%s revision-version:%d/%d revision-run:%s/%s run-version:%d/%d run:%s cleanup:%s/%s audit:%d outbox:%d",
					testCase.name, persistedSourceVersion, sourceVersion, sourceStatus, gateStatus,
					persistedSourceRunID, sourceRunID, persistedRevisionVersion, revisionVersion,
					persistedRevisionRunID, revisionRunID, persistedRunVersion, runVersion,
					runStatus, persistedCleanupStatus, cleanupStatus, auditCount, outboxCount)
			}
		})
	}
}

func TestSourceRevisionIntegrationRequestSyncRejectsManualWithoutSideEffects(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedEligibleManualSource(t, harness.db)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revision, checkpointVersion int64
	var revisionDigest string
	var checkpointSHA *string
	if err := harness.db.QueryRow(context.Background(), `
SELECT version,published_revision,published_revision_digest,
       checkpoint_version,checkpoint_sha256
FROM asset_sources
WHERE id=$1::uuid
`, fixture.sourceID).Scan(
		&sourceVersion, &revision, &revisionDigest, &checkpointVersion, &checkpointSHA,
	); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	command := assetcatalog.RequestSyncCommand{
		Context:  sourceRevisionMutationContext(t, scope, "request-manual-sync", "7"),
		SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
		ExpectedRevision: revision, ExpectedRevisionDigest: revisionDigest,
		ExpectedCheckpointVersion: checkpointVersion,
		ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
	}
	if _, err := repository.RequestSync(context.Background(), command); !errors.Is(
		err, assetcatalog.ErrStateConflict,
	) {
		t.Fatalf("RequestSync(MANUAL) error = %v", err)
	}
	var runCount, auditCount, outboxCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_source_runs
   WHERE source_id=$1::uuid AND run_kind='DISCOVERY'),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND request_id=$3),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.sync.requested.v1')
`, fixture.sourceID, fixture.workspaceID, command.Context.IdempotencyKey()).Scan(
		&runCount, &auditCount, &outboxCount,
	); err != nil {
		t.Fatal(err)
	}
	if runCount != 0 || auditCount != 0 || outboxCount != 0 {
		t.Fatalf("RequestSync(MANUAL) side effects = run:%d audit:%d outbox:%d",
			runCount, auditCount, outboxCount)
	}
}

func TestSourceRevisionIntegrationValidationClosesAvailableGateBeforeCancellingQueuedDiscovery(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	fixture = seedClosureExternalSuccessorDefinition(
		t, harness.db, fixture,
		"8f510000-0000-4000-8000-000000000002", 2, "EXTERNAL_V1",
		[]byte(`{"type":"object","version":2}`), "DEFINITION_CHANGE",
	)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	var sourceVersion int64
	if err := harness.db.QueryRow(context.Background(),
		`SELECT version FROM asset_sources WHERE id=$1`, fixture.sourceID).Scan(&sourceVersion); err != nil {
		t.Fatal(err)
	}
	execAssetSQL(t, harness.db, `
INSERT INTO asset_source_runs (
    id,tenant_id,workspace_id,source_id,source_revision,source_revision_digest,
    run_kind,trigger_type,gate_revision,idempotency_key,request_hash,
    checkpoint_version,cursor_before_sha256
) SELECT $1,$2,$3,$4,published_revision,published_revision_digest,
         'DISCOVERY','HUMAN',gate_revision,'queued-before-validation',repeat('6',64),
         checkpoint_version,checkpoint_sha256
  FROM asset_sources WHERE id=$4
`, fixture.runID, fixture.tenantID, fixture.workspaceID, fixture.sourceID)

	validated, err := repository.RequestValidation(context.Background(), assetcatalog.ValidateSourceRevisionCommand{
		Context:  sourceRevisionMutationContext(t, scope, "replace-queued-with-validation", "7"),
		SourceID: fixture.sourceID, Revision: 2,
		ExpectedSourceVersion:   sourceVersion,
		ExpectedRevisionVersion: 1,
		ExpectedRevisionDigest:  fixture.revisionDigest,
	})
	if err != nil {
		t.Fatalf("RequestValidation() error = %v", err)
	}
	var oldStatus string
	if err := harness.db.QueryRow(context.Background(),
		`SELECT status FROM asset_source_runs WHERE id=$1`, fixture.runID).Scan(&oldStatus); err != nil {
		t.Fatal(err)
	}
	if oldStatus != "CANCELLED" || validated.Source.GateStatus != assetcatalog.SourceGateValidating ||
		validated.Run.Status != assetcatalog.RunStatusQueued {
		t.Fatalf("replacement = old:%s new:%#v", oldStatus, validated)
	}
}

func TestSourceRevisionIntegrationExternalSyncReplaySurvivesClaimWithoutDuplicateRun(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	proof := strings.Repeat("7", 64)
	finishClosureExternalValidation(t, harness.db, fixture, 1, proof)
	execAssetSQL(t, harness.db, `
UPDATE integrations
SET secret_ref='secret-canary',
    config='{"endpoint":"https://endpoint.invalid","headers":{"authorization":"header-canary"},"body":"body-canary"}'::jsonb
WHERE id=$1::uuid
`, fixture.integrationID)
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	var sourceVersion, revisionVersion, checkpointVersion int64
	var revisionDigest string
	var checkpointSHA *string
	if err := harness.db.QueryRow(context.Background(), `
SELECT source.version,source.published_revision_digest,source.checkpoint_version,
       source.checkpoint_sha256,revision.version
FROM asset_sources AS source
JOIN asset_source_revisions AS revision
  ON revision.source_id=source.id AND revision.revision=source.published_revision
WHERE source.id=$1
`, fixture.sourceID).Scan(
		&sourceVersion, &revisionDigest, &checkpointVersion, &checkpointSHA, &revisionVersion,
	); err != nil {
		t.Fatal(err)
	}
	_ = revisionVersion
	command := assetcatalog.RequestSyncCommand{
		Context:  sourceRevisionMutationContext(t, scope, "request-external-sync", "8"),
		SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
		ExpectedRevision: 1, ExpectedRevisionDigest: revisionDigest,
		ExpectedCheckpointVersion: checkpointVersion,
		ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
	}
	first, err := repository.RequestSync(context.Background(), command)
	if err != nil {
		t.Fatalf("RequestSync() error = %v", err)
	}
	if first.Run.Status != assetcatalog.RunStatusQueued ||
		first.Source.Version != sourceVersion || first.Receipt.IdempotentReplay {
		t.Fatalf("RequestSync() = %#v", first)
	}
	execAssetSQL(t, harness.db, `
UPDATE asset_source_runs
SET status='RUNNING',stage_code='READING',lease_owner='sync-replay-worker',
    lease_expires_at=clock_timestamp()+interval '5 minutes',fence_epoch=1,
    fence_token_hash=repeat('9',64),heartbeat_sequence=1,version=version+1
WHERE id=$1
`, first.Run.ID)
	replay, err := repository.RequestSync(context.Background(), command)
	if err != nil {
		t.Fatalf("RequestSync(claimed replay) error = %v", err)
	}
	if !replay.Receipt.IdempotentReplay || replay.Run.ID != first.Run.ID ||
		replay.Run.Status != assetcatalog.RunStatusRunning {
		t.Fatalf("RequestSync(claimed replay) = %#v", replay)
	}
	var runCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT count(*) FROM asset_source_runs
WHERE source_id=$1 AND run_kind='DISCOVERY'
`, fixture.sourceID).Scan(&runCount); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 {
		t.Fatalf("DISCOVERY run count = %d", runCount)
	}
	assertSourceMutationSideEffectsDLP(
		t,
		harness.db,
		fixture.workspaceID,
		closureExternalProfileManifestV1,
		`{"type":"object"}`,
		`{"endpoint":"https://endpoint.invalid","headers":{"authorization":"header-canary"},"body":"body-canary"}`,
		"EXTERNAL_V1",
		"additionalProperties",
		"opaque-credential",
		"secret-canary",
		"https://endpoint.invalid",
		"authorization",
		"header-canary",
		"body-canary",
		"canonical_profile_manifest",
		"canonical_provider_schema",
	)
}

func TestSourceRevisionIntegrationConcurrentExternalSyncHasOneNonterminalWinner(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyThroughAssetCatalog(t)
	fixture := seedDraftAssetCatalog(t, harness.db)
	fixture = seedClosureExternalValidationOnFixture(t, harness.db, fixture)
	finishClosureExternalValidation(t, harness.db, fixture, 1, strings.Repeat("7", 64))
	repository, err := assetpostgres.New(
		harness.application,
		func() time.Time { return time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC) },
		deterministicAssetIDGenerator(),
	)
	if err != nil {
		t.Fatal(err)
	}
	var sourceVersion, revision, checkpointVersion int64
	var revisionDigest string
	var checkpointSHA *string
	if err := harness.db.QueryRow(context.Background(), `
SELECT version,published_revision,published_revision_digest,
       checkpoint_version,checkpoint_sha256
FROM asset_sources
WHERE id=$1::uuid
`, fixture.sourceID).Scan(
		&sourceVersion, &revision, &revisionDigest, &checkpointVersion, &checkpointSHA,
	); err != nil {
		t.Fatal(err)
	}
	scope := assetcatalog.SourceScope{TenantID: fixture.tenantID, WorkspaceID: fixture.workspaceID}
	commands := []assetcatalog.RequestSyncCommand{
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-external-sync-a", "a"),
			SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
			ExpectedRevision: revision, ExpectedRevisionDigest: revisionDigest,
			ExpectedCheckpointVersion: checkpointVersion,
			ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
		},
		{
			Context:  sourceRevisionMutationContext(t, scope, "concurrent-external-sync-b", "b"),
			SourceID: fixture.sourceID, ExpectedSourceVersion: sourceVersion,
			ExpectedRevision: revision, ExpectedRevisionDigest: revisionDigest,
			ExpectedCheckpointVersion: checkpointVersion,
			ExpectedCheckpointSHA256:  optionalIntegrationString(checkpointSHA),
		},
	}
	type callResult struct {
		value assetcatalog.SourceRunMutation
		err   error
	}
	start := make(chan struct{})
	results := make(chan callResult, len(commands))
	for _, command := range commands {
		command := command
		go func() {
			<-start
			value, callErr := repository.RequestSync(context.Background(), command)
			results <- callResult{value: value, err: callErr}
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	var winner assetcatalog.SourceRunMutation
	for range commands {
		result := <-results
		switch {
		case result.err == nil:
			successes++
			winner = result.value
		case errors.Is(result.err, assetcatalog.ErrStateConflict):
			conflicts++
		default:
			t.Fatalf("concurrent RequestSync() error = %v", result.err)
		}
	}
	if successes != 1 || conflicts != 1 ||
		winner.Run.Status != assetcatalog.RunStatusQueued ||
		winner.Source.Version != sourceVersion {
		t.Fatalf("concurrent RequestSync outcomes = success:%d conflict:%d winner:%#v",
			successes, conflicts, winner)
	}
	var runCount, auditCount, auditResourceCount, outboxCount, outboxAggregateCount int
	if err := harness.db.QueryRow(context.Background(), `
SELECT
  (SELECT count(*) FROM asset_source_runs
   WHERE source_id=$1::uuid AND run_kind='DISCOVERY'),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND action='asset.source.sync.requested.v1'),
  (SELECT count(*) FROM audit_records
   WHERE workspace_id=$2::uuid AND action='asset.source.sync.requested.v1'
     AND resource_type='ASSET_SOURCE' AND resource_id=$1),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.sync.requested.v1'),
  (SELECT count(*) FROM outbox_events
   WHERE workspace_id=$2::uuid AND event_type='asset.source.sync.requested.v1'
     AND aggregate_type='ASSET_SOURCE_RUN' AND aggregate_id=$3::uuid)
`, fixture.sourceID, fixture.workspaceID, winner.Run.ID).Scan(
		&runCount, &auditCount, &auditResourceCount, &outboxCount, &outboxAggregateCount,
	); err != nil {
		t.Fatal(err)
	}
	if runCount != 1 || auditCount != 1 || auditResourceCount != 1 ||
		outboxCount != 1 || outboxAggregateCount != 1 {
		t.Fatalf("concurrent RequestSync side effects = run:%d audit:%d/%d outbox:%d/%d",
			runCount, auditResourceCount, auditCount, outboxAggregateCount, outboxCount)
	}
}

func sourceRevisionMutationContext(
	t *testing.T,
	scope assetcatalog.SourceScope,
	key string,
	digestCharacter string,
) assetcatalog.MutationContext {
	t.Helper()
	value, err := assetcatalog.NewSourceMutationContext(authn.Principal{
		Subject: "source-manager", TenantID: scope.TenantID,
		AuthenticatedAt: time.Date(2026, 7, 17, 3, 0, 0, 0, time.UTC),
	}, scope, assetcatalog.MutationMetadata{
		TraceID: "trace-" + key, IdempotencyKey: key,
		RequestHash: strings.Repeat(digestCharacter, 64),
	})
	if err != nil {
		t.Fatalf("NewSourceMutationContext() error = %v", err)
	}
	return value
}

func assertSourceValidationSystemReceipts(t *testing.T, database *pgxpool.Pool, runID string) {
	t.Helper()
	var cleanup, terminal int
	if err := database.QueryRow(context.Background(), `
		SELECT
			count(*) FILTER (WHERE action='ATTEMPT_CLEANED' AND request_id='source-attempt:'||$1::text||':0'),
			count(*) FILTER (WHERE action='TERMINAL_COMMITTED' AND request_id='source-terminal:'||$1::text)
		FROM audit_records
		WHERE resource_type='ASSET_SOURCE_RUN' AND resource_id=$1::text
	`, runID).Scan(&cleanup, &terminal); err != nil {
		t.Fatalf("read validation SYSTEM receipts: %v", err)
	}
	if cleanup != 1 || terminal != 1 {
		t.Fatalf("validation SYSTEM receipts = cleanup:%d terminal:%d", cleanup, terminal)
	}
}

func finishSourceRevisionExternalValidationOnly(
	t *testing.T,
	database *pgxpool.Pool,
	fixture assetCatalogFixture,
	proof string,
) {
	t.Helper()
	execAssetSQL(t, database, `
UPDATE asset_source_runs
SET stage_code='CLEANING_UP',cleanup_status='PENDING',cleanup_attempt_id=gen_random_uuid(),
    cleanup_attempt_epoch=fence_epoch,version=version+1
WHERE id=$1::uuid
`, fixture.validationRunID)
	execAssetSQL(t, database, `
UPDATE asset_source_runs
SET status='FINALIZING',work_result_kind='VALIDATION_PROOF',
    work_result_status='SUCCEEDED',work_result_digest=$2,
    work_result_recorded_at=statement_timestamp(),validation_outcome='SUCCEEDED',
    validation_digest=$2,validation_proof_digest=$2,version=version+1
WHERE id=$1::uuid
`, fixture.validationRunID, proof)
	revokeClosureAttempt(t, database, fixture, fixture.validationRunID, strings.Repeat("6", 64))
	tx, err := database.BeginTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		t.Fatalf("begin external validation-only terminal closure: %v", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	terminalDigest := sourceRunTerminalDigest(t, tx, fixture.validationRunID, "SUCCEEDED", nil)
	insertTerminalAudit(t, tx, fixture, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
UPDATE asset_source_runs
SET status='SUCCEEDED',stage_code='COMPLETED',terminal_command_sha256=$2,
    version=version+1
WHERE id=$1::uuid
`, fixture.validationRunID, terminalDigest)
	execAssetSQL(t, tx, `
UPDATE asset_source_revisions
SET state='VALIDATED',validation_digest=$2,version=version+1
WHERE id=$1::uuid
`, fixture.revisionID, proof)
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit external validation-only terminal closure: %v", err)
	}
}

type sourceRevisionGateBindingSnapshot struct {
	SourceVersion               int64
	SourceStatus                string
	GateStatus                  string
	GateReasonCode              string
	SourceValidationRunID       string
	SourceValidationDigest      string
	SourceBindingDigest         string
	RevisionOneVersion          int64
	RevisionOneStatus           string
	RevisionOneValidationRunID  string
	RevisionOneValidationDigest string
	RevisionTwoVersion          int64
	RevisionTwoStatus           string
	RevisionTwoValidationRunID  string
	RevisionTwoValidationDigest string
	RevisionTwoRunVersion       int64
	RevisionTwoRunStatus        string
	RevisionTwoCleanupStatus    string
}

func readSourceRevisionGateBindingSnapshot(
	t *testing.T,
	database *pgxpool.Pool,
	sourceID, revisionOneID, revisionTwoID string,
) sourceRevisionGateBindingSnapshot {
	t.Helper()
	var snapshot sourceRevisionGateBindingSnapshot
	if err := database.QueryRow(context.Background(), `
SELECT source.version,source.status,source.gate_status,source.gate_reason_code,
       source.validated_run_id::text,COALESCE(source.validation_digest,''),
       COALESCE(source.validated_binding_digest,''),
       revision_one.version,revision_one.state,revision_one.validation_run_id::text,
       COALESCE(revision_one.validation_digest,''),
       revision_two.version,revision_two.state,revision_two.validation_run_id::text,
       COALESCE(revision_two.validation_digest,''),
       run.version,run.status,run.cleanup_status
FROM asset_sources AS source
JOIN asset_source_revisions AS revision_one ON revision_one.id=$2::uuid
JOIN asset_source_revisions AS revision_two ON revision_two.id=$3::uuid
JOIN asset_source_runs AS run ON run.id=revision_two.validation_run_id
WHERE source.id=$1::uuid
  AND revision_one.source_id=source.id
  AND revision_two.source_id=source.id
`, sourceID, revisionOneID, revisionTwoID).Scan(
		&snapshot.SourceVersion, &snapshot.SourceStatus,
		&snapshot.GateStatus, &snapshot.GateReasonCode,
		&snapshot.SourceValidationRunID, &snapshot.SourceValidationDigest,
		&snapshot.SourceBindingDigest, &snapshot.RevisionOneVersion,
		&snapshot.RevisionOneStatus, &snapshot.RevisionOneValidationRunID,
		&snapshot.RevisionOneValidationDigest, &snapshot.RevisionTwoVersion,
		&snapshot.RevisionTwoStatus, &snapshot.RevisionTwoValidationRunID,
		&snapshot.RevisionTwoValidationDigest, &snapshot.RevisionTwoRunVersion,
		&snapshot.RevisionTwoRunStatus, &snapshot.RevisionTwoCleanupStatus,
	); err != nil {
		t.Fatalf("read source revision gate binding snapshot: %v", err)
	}
	return snapshot
}

func assertSourceMutationSideEffectsDLP(
	t *testing.T,
	database *pgxpool.Pool,
	workspaceID string,
	forbidden ...string,
) {
	t.Helper()
	var auditDetails, outboxPayloads string
	if err := database.QueryRow(context.Background(), `
SELECT COALESCE(string_agg(details::text,E'\n'),'')
FROM audit_records
WHERE workspace_id=$1::uuid AND action LIKE 'asset.source.%'
`, workspaceID).Scan(&auditDetails); err != nil {
		t.Fatalf("read source mutation audit DLP surface: %v", err)
	}
	if err := database.QueryRow(context.Background(), `
SELECT COALESCE(string_agg(payload::text,E'\n'),'')
FROM outbox_events
WHERE workspace_id=$1::uuid AND event_type LIKE 'asset.source.%'
`, workspaceID).Scan(&outboxPayloads); err != nil {
		t.Fatalf("read source mutation outbox DLP surface: %v", err)
	}
	if auditDetails == "" || outboxPayloads == "" {
		t.Fatalf("source mutation DLP surfaces are empty: audit=%q outbox=%q",
			auditDetails, outboxPayloads)
	}
	persisted := strings.ToLower(auditDetails + "\n" + outboxPayloads)
	for _, value := range forbidden {
		normalized := strings.ToLower(value)
		encoded := strings.ToLower(base64.StdEncoding.EncodeToString([]byte(value)))
		if strings.Contains(persisted, normalized) ||
			strings.Contains(persisted, encoded) {
			t.Errorf("source mutation Audit/Outbox persisted forbidden value %q", value)
		}
	}
}

func optionalIntegrationString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
