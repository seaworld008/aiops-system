package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const (
	assetCreatedAction           = "asset.created.v1"
	assetGovernanceUpdatedAction = "asset.governance.updated.v1"
	assetQuarantinedAction       = "asset.quarantined.v1"
	assetRetiredAction           = "asset.retired.v1"
)

var assetLabelKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

const assetColumns = `
a.id::text,
a.tenant_id::text,
a.workspace_id::text,
a.environment_id::text,
a.source_id::text,
a.kind,
a.provider_kind,
a.external_id,
a.display_name,
a.lifecycle,
a.mapping_status,
a.owner_group,
a.criticality,
a.data_classification,
a.labels,
a.last_observation_id::text,
a.last_observation_chain_sha256,
a.last_observed_at,
a.last_source_revision,
a.version,
a.created_at,
a.updated_at`

const getAssetSQL = `
SELECT ` + assetColumns + `
FROM assets AS a
WHERE a.tenant_id = $1::uuid
  AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND a.id = $4::uuid
`

const getAssetForUpdateSQL = `
SELECT ` + assetColumns + `
FROM assets AS a
WHERE a.tenant_id = $1::uuid
  AND a.workspace_id = $2::uuid
  AND a.environment_id = $3::uuid
  AND a.id = $4::uuid
FOR UPDATE
`

const updateGovernanceSQL = `
UPDATE assets
SET display_name = $5,
    owner_group = $6,
    criticality = $7,
    data_classification = $8,
    labels = $9::jsonb,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND environment_id = $3::uuid
  AND id = $4::uuid
  AND version = $10
RETURNING version
`

const transitionAssetSQL = `
UPDATE assets
SET lifecycle = $5,
    version = version + 1
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND environment_id = $3::uuid
  AND id = $4::uuid
  AND version = $6
RETURNING version
`

const mutationAuditLookupSQL = `
SELECT id::text, actor_id, action, resource_type, resource_id, payload_hash, trace_id, details
FROM audit_records
WHERE tenant_id = $1::uuid
  AND workspace_id = $2::uuid
  AND request_id = $3
`

const insertMutationAuditSQL = `
INSERT INTO audit_records (
    id, tenant_id, workspace_id, actor_type, actor_id, action,
    resource_type, resource_id, request_id, trace_id, payload_hash, details
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, 'USER', $4, $5,
    'ASSET', $6, $7, $8, $9, $10::jsonb
)
`

const insertAssetOutboxSQL = `
INSERT INTO outbox_events (
    id, tenant_id, workspace_id, aggregate_type, aggregate_id,
    aggregate_version, event_type, payload
) VALUES (
    $1::uuid, $2::uuid, $3::uuid, 'ASSET', $4::uuid,
    $5, $6, $7::jsonb
)
`

func (repository *Repository) Get(
	ctx context.Context,
	locator assetcatalog.AssetLocator,
) (assetcatalog.Asset, error) {
	if !locator.Scope.Valid() || !validUUID(locator.AssetID) {
		return assetcatalog.Asset{}, assetcatalog.ErrInvalidRequest
	}
	asset, err := scanAsset(repository.pool.QueryRow(
		ctx,
		getAssetSQL,
		locator.Scope.TenantID,
		locator.Scope.WorkspaceID,
		locator.Scope.EnvironmentID,
		locator.AssetID,
	))
	if err != nil {
		return assetcatalog.Asset{}, mapPGError(err)
	}
	return asset.Clone(), nil
}

func (repository *Repository) Create(
	ctx context.Context,
	command assetcatalog.CreateAssetCommand,
) (assetcatalog.AssetMutationResult, error) {
	command = command.Clone()
	scope, commandHash, err := validateCreateAssetCommand(command)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	ids, err := repository.allocateIDs(9)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	executor := newManualRunExecutor(ids)
	defer executor.destroy()

	return repository.withSerializable(ctx, func(tx pgx.Tx) (assetcatalog.AssetMutationResult, error) {
		if err := prepareMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		receipt, found, err := findMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if found {
			if receipt.ResourceType != "ASSET" || !validUUID(receipt.ResourceID) {
				return assetcatalog.AssetMutationResult{}, assetcatalog.ErrIdempotency
			}
			if err := validateMutationReceiptIdentity(
				scope, command.Context, commandHash, assetCreatedAction, receipt.ResourceID, receipt,
			); err != nil {
				return assetcatalog.AssetMutationResult{}, err
			}
			manual, err := lockEligibleManualSource(ctx, tx, scope, command.SourceID)
			if err != nil {
				return assetcatalog.AssetMutationResult{}, err
			}
			asset, err := lockMutationReplayAsset(ctx, tx, scope, receipt.ResourceID, receipt)
			if err != nil {
				return assetcatalog.AssetMutationResult{}, err
			}
			if !manualCreateMatches(asset, command, manual.source.ProviderKind) {
				return assetcatalog.AssetMutationResult{}, assetcatalog.ErrIdempotency
			}
			return mutationReplayResult(ctx, tx, scope, asset, receipt)
		}
		manual, err := lockEligibleManualSource(ctx, tx, scope, command.SourceID)
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}

		return executor.execute(ctx, tx, scope, command, commandHash, manual)
	})
}

func (repository *Repository) UpdateGovernance(
	ctx context.Context,
	command assetcatalog.UpdateGovernanceCommand,
) (assetcatalog.AssetMutationResult, error) {
	command = command.Clone()
	scope, commandHash, err := validateUpdateGovernanceCommand(command)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	ids, err := repository.allocateIDs(2)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	return repository.withSerializable(ctx, func(tx pgx.Tx) (assetcatalog.AssetMutationResult, error) {
		if err := prepareMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		receipt, found, err := findMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if found {
			asset, replayErr := validateMutationReplay(
				ctx, tx, scope, command.Context, commandHash, assetGovernanceUpdatedAction, command.AssetID, receipt,
			)
			if replayErr != nil {
				return assetcatalog.AssetMutationResult{}, replayErr
			}
			if !governanceMatches(asset, command) {
				return assetcatalog.AssetMutationResult{}, assetcatalog.ErrIdempotency
			}
			return mutationReplayResult(ctx, tx, scope, asset, receipt)
		}

		asset, err := lockAsset(ctx, tx, scope, command.AssetID)
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if asset.Version != command.ExpectedVersion {
			return assetcatalog.AssetMutationResult{}, assetcatalog.ErrVersionConflict
		}
		labels, _ := json.Marshal(command.Labels)
		var version int64
		if err := tx.QueryRow(
			ctx,
			updateGovernanceSQL,
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
			command.AssetID,
			command.DisplayName,
			command.OwnerGroup,
			command.Criticality,
			command.DataClassification,
			string(labels),
			command.ExpectedVersion,
		).Scan(&version); err != nil {
			return assetcatalog.AssetMutationResult{}, classifyAssetCAS(ctx, tx, scope, command.AssetID, err)
		}
		if version != command.ExpectedVersion+1 {
			return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
		}
		updated, err := loadAssetDetailInTx(ctx, tx, scope, command.AssetID)
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if err := insertAssetMutationSideEffects(
			ctx, tx, ids[0], ids[1], command.Context, commandHash, assetGovernanceUpdatedAction, updated, "",
		); err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		return assetcatalog.AssetMutationResult{
			Asset: updated,
			Receipt: assetcatalog.MutationReceipt{
				AuditID: ids[0], TraceID: command.Context.TraceID(), IdempotentReplay: false,
			},
		}, nil
	})
}

func (repository *Repository) Transition(
	ctx context.Context,
	command assetcatalog.TransitionCommand,
) (assetcatalog.AssetMutationResult, error) {
	scope, commandHash, eventType, err := validateTransitionCommand(command)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	ids, err := repository.allocateIDs(2)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	return repository.withSerializable(ctx, func(tx pgx.Tx) (assetcatalog.AssetMutationResult, error) {
		if err := prepareMutation(ctx, tx, scope, command.Context.IdempotencyKey()); err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		receipt, found, err := findMutationAudit(ctx, tx, scope, command.Context.IdempotencyKey())
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if found {
			asset, replayErr := validateMutationReplay(
				ctx, tx, scope, command.Context, commandHash, eventType, command.AssetID, receipt,
			)
			if replayErr != nil {
				return assetcatalog.AssetMutationResult{}, replayErr
			}
			if asset.Lifecycle != command.To {
				return assetcatalog.AssetMutationResult{}, assetcatalog.ErrIdempotency
			}
			return mutationReplayResult(ctx, tx, scope, asset, receipt)
		}

		asset, err := lockAsset(ctx, tx, scope, command.AssetID)
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if asset.Version != command.ExpectedVersion {
			return assetcatalog.AssetMutationResult{}, assetcatalog.ErrVersionConflict
		}
		if !assetcatalog.IsLifecycleEdge(asset.Lifecycle, command.To) {
			return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
		}
		var version int64
		if err := tx.QueryRow(
			ctx,
			transitionAssetSQL,
			scope.TenantID,
			scope.WorkspaceID,
			scope.EnvironmentID,
			command.AssetID,
			command.To,
			command.ExpectedVersion,
		).Scan(&version); err != nil {
			return assetcatalog.AssetMutationResult{}, classifyAssetCAS(ctx, tx, scope, command.AssetID, err)
		}
		if version != command.ExpectedVersion+1 {
			return assetcatalog.AssetMutationResult{}, assetcatalog.ErrStateConflict
		}
		updated, err := loadAssetDetailInTx(ctx, tx, scope, command.AssetID)
		if err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		if err := insertAssetMutationSideEffects(
			ctx, tx, ids[0], ids[1], command.Context, commandHash, eventType, updated, command.ReasonCode,
		); err != nil {
			return assetcatalog.AssetMutationResult{}, err
		}
		return assetcatalog.AssetMutationResult{
			Asset: updated,
			Receipt: assetcatalog.MutationReceipt{
				AuditID: ids[0], TraceID: command.Context.TraceID(), IdempotentReplay: false,
			},
		}, nil
	})
}

type mutationAuditDetails struct {
	EnvironmentID string                 `json:"environment_id"`
	ResultVersion int64                  `json:"result_version"`
	Lifecycle     assetcatalog.Lifecycle `json:"lifecycle"`
	CommandSHA256 string                 `json:"command_sha256"`
	ReasonCode    string                 `json:"reason_code,omitempty"`
}

type mutationAuditRecord struct {
	ID, ActorID, Action, ResourceType, ResourceID string
	PayloadHash, TraceID                          string
	Details                                       mutationAuditDetails
}

type assetOutboxPayload struct {
	AssetID       string                 `json:"asset_id"`
	EnvironmentID string                 `json:"environment_id"`
	Lifecycle     assetcatalog.Lifecycle `json:"lifecycle"`
	Version       int64                  `json:"version"`
	TraceID       string                 `json:"trace_id"`
}

func prepareMutation(ctx context.Context, tx pgx.Tx, scope assetcatalog.Scope, idempotencyKey string) error {
	if err := lockMutationScope(ctx, tx, scope); err != nil {
		return err
	}
	return lockIdempotency(ctx, tx, scope, idempotencyKey)
}

func findMutationAudit(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	idempotencyKey string,
) (mutationAuditRecord, bool, error) {
	var (
		record  mutationAuditRecord
		details []byte
		traceID *string
	)
	err := tx.QueryRow(
		ctx,
		mutationAuditLookupSQL,
		scope.TenantID,
		scope.WorkspaceID,
		idempotencyKey,
	).Scan(
		&record.ID,
		&record.ActorID,
		&record.Action,
		&record.ResourceType,
		&record.ResourceID,
		&record.PayloadHash,
		&traceID,
		&details,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return mutationAuditRecord{}, false, nil
	}
	if err != nil {
		return mutationAuditRecord{}, false, err
	}
	if traceID == nil || !validUUID(record.ID) || decodeStrictJSON(details, &record.Details) != nil {
		return mutationAuditRecord{}, false, assetcatalog.ErrStateConflict
	}
	record.TraceID = *traceID
	return record, true, nil
}

func validateMutationReplay(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	mutationContext assetcatalog.MutationContext,
	commandHash string,
	action string,
	resourceID string,
	record mutationAuditRecord,
) (assetcatalog.Asset, error) {
	if err := validateMutationReceiptIdentity(
		scope, mutationContext, commandHash, action, resourceID, record,
	); err != nil {
		return assetcatalog.Asset{}, err
	}
	return lockMutationReplayAsset(ctx, tx, scope, resourceID, record)
}

func validateMutationReceiptIdentity(
	scope assetcatalog.Scope,
	mutationContext assetcatalog.MutationContext,
	commandHash string,
	action string,
	resourceID string,
	record mutationAuditRecord,
) error {
	if record.Action != action || record.ResourceType != "ASSET" || record.ResourceID != resourceID ||
		record.PayloadHash != mutationContext.RequestHash() || record.ActorID != mutationContext.ActorID() ||
		record.Details.EnvironmentID != scope.EnvironmentID || record.Details.CommandSHA256 != commandHash {
		return assetcatalog.ErrIdempotency
	}
	return nil
}

func lockMutationReplayAsset(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	resourceID string,
	record mutationAuditRecord,
) (assetcatalog.Asset, error) {
	asset, err := lockAsset(ctx, tx, scope, resourceID)
	if err != nil {
		return assetcatalog.Asset{}, err
	}
	if asset.Version != record.Details.ResultVersion || asset.Lifecycle != record.Details.Lifecycle {
		return assetcatalog.Asset{}, assetcatalog.ErrStateConflict
	}
	return asset, nil
}

func mutationReplayResult(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	asset assetcatalog.Asset,
	record mutationAuditRecord,
) (assetcatalog.AssetMutationResult, error) {
	model, err := loadAssetDetailInTx(ctx, tx, scope, asset.ID)
	if err != nil {
		return assetcatalog.AssetMutationResult{}, err
	}
	return assetcatalog.AssetMutationResult{
		Asset: model,
		Receipt: assetcatalog.MutationReceipt{
			AuditID: record.ID, TraceID: record.TraceID, IdempotentReplay: true,
		},
	}, nil
}

func insertAssetMutationSideEffects(
	ctx context.Context,
	tx pgx.Tx,
	auditID string,
	outboxID string,
	mutationContext assetcatalog.MutationContext,
	commandHash string,
	action string,
	model assetcatalog.AssetDetailReadModel,
	reasonCode string,
) error {
	details := mutationAuditDetails{
		EnvironmentID: model.Scope.EnvironmentID,
		ResultVersion: model.Version, Lifecycle: model.Lifecycle,
		CommandSHA256: commandHash, ReasonCode: reasonCode,
	}
	if err := insertMutationAuditRecord(
		ctx, tx, auditID, mutationContext, action, model.ID, model.Scope, details,
	); err != nil {
		return err
	}
	return insertAssetOutboxRecord(ctx, tx, outboxID, mutationContext.TraceID(), action, model.Asset)
}

func insertMutationAuditRecord(
	ctx context.Context,
	tx pgx.Tx,
	auditID string,
	mutationContext assetcatalog.MutationContext,
	action string,
	assetID string,
	scope assetcatalog.Scope,
	details mutationAuditDetails,
) error {
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return assetcatalog.ErrStateConflict
	}
	if _, err := tx.Exec(
		ctx,
		insertMutationAuditSQL,
		auditID,
		scope.TenantID,
		scope.WorkspaceID,
		mutationContext.ActorID(),
		action,
		assetID,
		mutationContext.IdempotencyKey(),
		mutationContext.TraceID(),
		mutationContext.RequestHash(),
		string(detailsJSON),
	); err != nil {
		return err
	}
	return nil
}

func insertAssetOutboxRecord(
	ctx context.Context,
	tx pgx.Tx,
	outboxID string,
	traceID string,
	action string,
	asset assetcatalog.Asset,
) error {
	payload, err := json.Marshal(assetOutboxPayload{
		AssetID: asset.ID, EnvironmentID: asset.Scope.EnvironmentID, Lifecycle: asset.Lifecycle,
		Version: asset.Version, TraceID: traceID,
	})
	if err != nil {
		return assetcatalog.ErrStateConflict
	}
	_, err = tx.Exec(
		ctx,
		insertAssetOutboxSQL,
		outboxID,
		asset.Scope.TenantID,
		asset.Scope.WorkspaceID,
		asset.ID,
		asset.Version,
		action,
		string(payload),
	)
	return err
}

func loadAssetDetailInTx(
	ctx context.Context,
	tx pgx.Tx,
	scope assetcatalog.Scope,
	assetID string,
) (assetcatalog.AssetDetailReadModel, error) {
	model, err := scanAssetDetailReadModel(tx.QueryRow(
		ctx,
		getAssetReadModelSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		assetID,
		true,
		[]string{},
	))
	if err != nil {
		return assetcatalog.AssetDetailReadModel{}, err
	}
	return model, nil
}

func lockAsset(ctx context.Context, tx pgx.Tx, scope assetcatalog.Scope, assetID string) (assetcatalog.Asset, error) {
	asset, err := scanAsset(tx.QueryRow(
		ctx,
		getAssetForUpdateSQL,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		assetID,
	))
	if err != nil {
		return assetcatalog.Asset{}, err
	}
	return asset, nil
}

func classifyAssetCAS(ctx context.Context, tx pgx.Tx, scope assetcatalog.Scope, assetID string, err error) error {
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	var persistedVersion int64
	existenceErr := tx.QueryRow(
		ctx,
		`SELECT version FROM assets WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND environment_id=$3::uuid AND id=$4::uuid`,
		scope.TenantID,
		scope.WorkspaceID,
		scope.EnvironmentID,
		assetID,
	).Scan(&persistedVersion)
	if errors.Is(existenceErr, pgx.ErrNoRows) {
		return assetcatalog.ErrNotFound
	}
	if existenceErr != nil {
		return existenceErr
	}
	return assetcatalog.ErrVersionConflict
}

func validateUpdateGovernanceCommand(
	command assetcatalog.UpdateGovernanceCommand,
) (assetcatalog.Scope, string, error) {
	scope, ok := validEnvironmentMutationContext(command.Context)
	if !ok || !validUUID(command.AssetID) || !validAssetSafeText(command.DisplayName, 1, 256) ||
		command.OwnerGroup != nil && !validAssetSafeText(*command.OwnerGroup, 1, 256) ||
		!command.Criticality.Valid() || !command.DataClassification.Valid() ||
		!validAssetLabels(command.Labels) || command.ExpectedVersion <= 0 {
		return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation          string                          `json:"operation"`
		Scope              assetcatalog.Scope              `json:"scope"`
		AssetID            string                          `json:"asset_id"`
		DisplayName        string                          `json:"display_name"`
		OwnerGroup         *string                         `json:"owner_group"`
		Criticality        assetcatalog.Criticality        `json:"criticality"`
		DataClassification assetcatalog.DataClassification `json:"data_classification"`
		Labels             map[string]string               `json:"labels"`
		ExpectedVersion    int64                           `json:"expected_version"`
	}{
		Operation: assetGovernanceUpdatedAction, Scope: scope, AssetID: command.AssetID,
		DisplayName: command.DisplayName, OwnerGroup: command.OwnerGroup, Criticality: command.Criticality,
		DataClassification: command.DataClassification, Labels: command.Labels, ExpectedVersion: command.ExpectedVersion,
	})
	return scope, hash, err
}

func validateCreateAssetCommand(command assetcatalog.CreateAssetCommand) (assetcatalog.Scope, string, error) {
	scope, ok := validEnvironmentMutationContext(command.Context)
	if !ok || !validUUID(command.SourceID) || !command.Kind.Valid() ||
		!validAssetSafeText(command.ExternalID, 1, 512) || !validAssetSafeText(command.DisplayName, 1, 256) ||
		command.OwnerGroup != nil && !validAssetSafeText(*command.OwnerGroup, 1, 256) ||
		!command.Criticality.Valid() || !command.DataClassification.Valid() || !validAssetLabels(command.Labels) ||
		!validAssetSafeText(command.Context.TraceID(), 1, 128) {
		return assetcatalog.Scope{}, "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation          string                          `json:"operation"`
		Scope              assetcatalog.Scope              `json:"scope"`
		SourceID           string                          `json:"source_id"`
		Kind               assetcatalog.Kind               `json:"kind"`
		ExternalID         string                          `json:"external_id"`
		DisplayName        string                          `json:"display_name"`
		OwnerGroup         *string                         `json:"owner_group"`
		Criticality        assetcatalog.Criticality        `json:"criticality"`
		DataClassification assetcatalog.DataClassification `json:"data_classification"`
		Labels             map[string]string               `json:"labels"`
	}{
		Operation: assetCreatedAction, Scope: scope, SourceID: command.SourceID, Kind: command.Kind,
		ExternalID: command.ExternalID, DisplayName: command.DisplayName, OwnerGroup: command.OwnerGroup,
		Criticality: command.Criticality, DataClassification: command.DataClassification, Labels: command.Labels,
	})
	return scope, hash, err
}

func validateTransitionCommand(
	command assetcatalog.TransitionCommand,
) (assetcatalog.Scope, string, string, error) {
	scope, ok := validEnvironmentMutationContext(command.Context)
	if !ok || !validUUID(command.AssetID) || !validAssetCode(command.ReasonCode, 128) || command.ExpectedVersion <= 0 {
		return assetcatalog.Scope{}, "", "", assetcatalog.ErrInvalidRequest
	}
	var action string
	switch command.To {
	case assetcatalog.LifecycleQuarantined:
		action = assetQuarantinedAction
	case assetcatalog.LifecycleRetired:
		action = assetRetiredAction
	default:
		return assetcatalog.Scope{}, "", "", assetcatalog.ErrInvalidRequest
	}
	hash, err := semanticCommandHash(struct {
		Operation       string                 `json:"operation"`
		Scope           assetcatalog.Scope     `json:"scope"`
		AssetID         string                 `json:"asset_id"`
		To              assetcatalog.Lifecycle `json:"to"`
		ReasonCode      string                 `json:"reason_code"`
		ExpectedVersion int64                  `json:"expected_version"`
	}{action, scope, command.AssetID, command.To, command.ReasonCode, command.ExpectedVersion})
	return scope, hash, action, err
}

func validEnvironmentMutationContext(value assetcatalog.MutationContext) (assetcatalog.Scope, bool) {
	if value.Validate() != nil {
		return assetcatalog.Scope{}, false
	}
	scope, ok := value.EnvironmentScope()
	return scope, ok && scope.Valid()
}

func validAssetSafeText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == utf8.RuneError || character == 0 || character == '\r' || character == '\n' ||
			unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func validAssetCode(value string, maximum int) bool {
	if !validAssetSafeText(value, 1, maximum) || strings.ContainsAny(value, " \t") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._+@/:-", character) {
			continue
		}
		return false
	}
	return true
}

func validAssetLabels(labels map[string]string) bool {
	if len(labels) > 64 {
		return false
	}
	wire, err := json.Marshal(labels)
	if err != nil || len(wire) > 16<<10 {
		return false
	}
	for key, value := range labels {
		if !assetLabelKeyPattern.MatchString(key) || !validAssetSafeText(value, 0, 16<<10) {
			return false
		}
		normalized := strings.ToLower(key)
		normalized = strings.NewReplacer("-", "", "_", "", ".", "").Replace(normalized)
		for _, unsafe := range []string{"secret", "token", "password", "credential", "dsn", "endpoint"} {
			if strings.Contains(normalized, unsafe) {
				return false
			}
		}
	}
	return true
}

func semanticCommandHash(value any) (string, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return "", assetcatalog.ErrInvalidRequest
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func decodeStrictJSON(value []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return assetcatalog.ErrStateConflict
		}
		return err
	}
	return nil
}

func governanceMatches(asset assetcatalog.Asset, command assetcatalog.UpdateGovernanceCommand) bool {
	return asset.DisplayName == command.DisplayName && equalOptionalString(asset.OwnerGroup, command.OwnerGroup) &&
		asset.Criticality == command.Criticality && asset.DataClassification == command.DataClassification &&
		equalStringMap(asset.Labels, command.Labels)
}

func manualCreateMatches(asset assetcatalog.Asset, command assetcatalog.CreateAssetCommand, providerKind string) bool {
	return asset.SourceID == command.SourceID && asset.ProviderKind == providerKind && asset.Kind == command.Kind &&
		asset.ExternalID == command.ExternalID && asset.DisplayName == command.DisplayName &&
		equalOptionalString(asset.OwnerGroup, command.OwnerGroup) && asset.Criticality == command.Criticality &&
		asset.DataClassification == command.DataClassification && equalStringMap(asset.Labels, command.Labels) &&
		asset.Version == 1 && asset.Lifecycle == assetcatalog.LifecycleDiscovered
}

func equalOptionalString(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func (repository *Repository) allocateIDs(count int) ([]string, error) {
	ids := make([]string, count)
	seen := make(map[string]struct{}, count)
	for index := range ids {
		ids[index] = repository.newID()
		if !validUUID(ids[index]) {
			return nil, assetcatalog.ErrStateConflict
		}
		if _, duplicate := seen[ids[index]]; duplicate {
			return nil, assetcatalog.ErrStateConflict
		}
		seen[ids[index]] = struct{}{}
	}
	return ids, nil
}
