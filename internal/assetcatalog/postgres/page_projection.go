package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverycheckpoint"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

type pageProjectionCounts struct {
	Observed, Created, Changed, Unchanged          int64
	Conflict, Missing, Stale, Restored, Tombstoned int64
	Rejected                                       int64
}

type pageProjectionResult struct {
	Counts             pageProjectionCounts
	ItemPageDigest     string
	RelationPageDigest string
}

type pageItemIDs struct {
	Observation, Asset, Detail, Audit, Outbox, Conflict string
}

type pageRelationIDs struct {
	Relationship, Audit, Outbox string
}

type pageProjectionIDs struct {
	Items           []pageItemIDs
	Relations       []pageRelationIDs
	PageAuditID     string
	RelationAuditID string
}

type pageItemFacts struct {
	Provenance, Document                         []byte
	ProvenanceDigest, FingerprintDigest          string
	ProviderProvenanceDigest, ProviderFactDigest string
	ObservationChainDigest                       string
}

type pagePriorAsset struct {
	ID, EnvironmentID, Kind, DisplayName, Lifecycle string
	LastObservationID, LastChain                    string
	LastObservedAt                                  time.Time
	LastSourceRevision, Version                     int64
	PriorRunID                                      string
	PriorFreshnessKind                              assetcatalog.FreshnessKind
	PriorFreshnessTime                              *time.Time
	PriorFreshnessSequence                          int64
	PriorProviderVersion, PriorProviderFact         string
	PriorDocumentSHA256, PriorSchemaVersion         string
}

type pageFingerprintCandidate struct {
	ID, Lifecycle, MappingStatus string
	Version                      int64
}

type pageRelationFact struct {
	Relation assetdiscovery.ObservedRelation
	Digest   string
}

var errPageAcceptanceTimeRetry = errors.New("page acceptance time retry")

const (
	pageAssetMappingAmbiguousAction = "asset.source.asset.mapping.ambiguous.v1"
	pageAssetStaleAction            = "asset.source.asset.stale.v1"
	pageRelationshipProjectedAction = "asset.relationship.projected.v1"
	pageRelationshipInactiveAction  = "asset.source.relationship.inactive.v1"
)

func allocatePageProjectionIDs(
	repository *Repository,
	itemCount, relationCount int,
) (pageProjectionIDs, error) {
	if repository == nil || itemCount < 0 || relationCount < 0 {
		return pageProjectionIDs{}, assetcatalog.ErrStateConflict
	}
	const itemWidth = 6
	const relationWidth = 3
	values, err := repository.allocateIDs(itemCount*itemWidth + relationCount*relationWidth + 2)
	if err != nil {
		return pageProjectionIDs{}, err
	}
	result := pageProjectionIDs{
		Items: make([]pageItemIDs, itemCount), Relations: make([]pageRelationIDs, relationCount),
	}
	offset := 0
	for index := range result.Items {
		result.Items[index] = pageItemIDs{
			Observation: values[offset], Asset: values[offset+1], Detail: values[offset+2],
			Audit: values[offset+3], Outbox: values[offset+4], Conflict: values[offset+5],
		}
		offset += itemWidth
	}
	for index := range result.Relations {
		result.Relations[index] = pageRelationIDs{
			Relationship: values[offset], Audit: values[offset+1], Outbox: values[offset+2],
		}
		offset += relationWidth
	}
	result.PageAuditID = values[offset]
	result.RelationAuditID = values[offset+1]
	return result, nil
}

func projectDiscoveryPage(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
	acceptedAt time.Time,
	ids pageProjectionIDs,
	newID func() string,
) (pageProjectionResult, error) {
	if tx == nil || newID == nil || len(ids.Items) != len(page.Items) || len(ids.Relations) != len(page.Relations) {
		return pageProjectionResult{}, discoverysource.ErrPageCommitUnavailable
	}
	itemOrder := make([]int, len(page.Items))
	for index := range itemOrder {
		itemOrder[index] = index
	}
	sort.Slice(itemOrder, func(left, right int) bool {
		return itemIdentityLess(page.Items[itemOrder[left]], page.Items[itemOrder[right]])
	})
	sortedItems := make([]assetdiscovery.NormalizedItem, 0, len(page.Items))
	providerFactDigests := make([]string, 0, len(page.Items))
	var counts pageProjectionCounts
	tombstonedAssets := make([]string, 0)
	tombstonedItemIdentities := make(map[string]struct{})
	for slot, pageIndex := range itemOrder {
		item := page.Items[pageIndex]
		duplicate, err := pageRunObjectExists(ctx, tx, admission, item)
		if err != nil {
			return pageProjectionResult{}, err
		}
		if duplicate {
			return pageProjectionResult{}, discoverysource.ErrPageCommitConflict
		}
		prior, found, err := lockPagePriorAsset(ctx, tx, admission, item)
		if err != nil {
			return pageProjectionResult{}, err
		}
		if found && prior.EnvironmentID != item.EnvironmentID {
			return pageProjectionResult{}, discoverysource.ErrPageCommitConflict
		}
		if found {
			if prior.PriorRunID == admission.Run.ID || string(item.Kind) != prior.Kind && !item.Tombstone {
				return pageProjectionResult{}, discoverysource.ErrPageCommitConflict
			}
			if !acceptedAt.After(prior.LastObservedAt) {
				return pageProjectionResult{}, errPageAcceptanceTimeRetry
			}
		}
		persistedItem := item
		if found && item.Tombstone && persistedItem.SchemaVersion == "" {
			persistedItem.SchemaVersion = prior.PriorSchemaVersion
		}
		var priorFacts *pagePriorAsset
		if found {
			priorFacts = &prior
		}
		facts, err := buildPageItemFacts(
			admission, coordinates, persistedItem, acceptedAt, ids.Items[slot].Observation, priorFacts,
		)
		if err != nil {
			return pageProjectionResult{}, err
		}
		if found && !pageFreshnessAccepts(
			admission.Revision.Revision, persistedItem.Freshness, facts.ProviderFactDigest, prior,
		) {
			return pageProjectionResult{}, discoverysource.ErrPageCommitConflict
		}
		sortedItems = append(sortedItems, item)
		providerFactDigests = append(providerFactDigests, facts.ProviderFactDigest)
		if item.Tombstone && !found {
			counts.Missing++
			counts.Rejected++
			continue
		}
		if err := insertPageObservation(
			ctx, tx, admission, coordinates, persistedItem, facts, acceptedAt, ids.Items[slot].Observation, prior, found,
		); err != nil {
			return pageProjectionResult{}, err
		}
		counts.Observed++
		if !found {
			candidate, collision, err := lockPageFingerprintCandidate(
				ctx, tx, admission, persistedItem, facts.FingerprintDigest,
			)
			if err != nil {
				return pageProjectionResult{}, err
			}
			if collision {
				if err := insertPageFingerprintConflict(
					ctx, tx, admission, persistedItem, ids.Items[slot], candidate,
					facts.FingerprintDigest,
				); err != nil {
					return pageProjectionResult{}, err
				}
				counts.Conflict++
				counts.Rejected++
				continue
			}
			if err := insertPageAssetAndDetail(
				ctx, tx, admission, coordinates, persistedItem, facts, acceptedAt, ids.Items[slot],
			); err != nil {
				return pageProjectionResult{}, err
			}
			counts.Created++
			continue
		}
		changed := prior.PriorProviderFact != facts.ProviderFactDigest
		lifecycle := prior.Lifecycle
		if item.Tombstone {
			counts.Tombstoned++
			tombstonedAssets = append(tombstonedAssets, prior.ID)
			tombstonedItemIdentities[item.EnvironmentID+"\x00"+item.ExternalID] = struct{}{}
			if lifecycle == string(assetcatalog.LifecycleActive) {
				lifecycle = string(assetcatalog.LifecycleStale)
				counts.Stale++
			}
		} else if lifecycle == string(assetcatalog.LifecycleStale) {
			counts.Restored++
		}
		if changed {
			counts.Changed++
		} else {
			counts.Unchanged++
		}
		if err := updatePageAssetAndDetail(
			ctx, tx, admission, coordinates, persistedItem, facts, acceptedAt, ids.Items[slot], prior, lifecycle, changed,
		); err != nil {
			return pageProjectionResult{}, err
		}
	}
	itemPageDigest, err := aggregatePageItemDigest(sortedItems, providerFactDigests)
	if err != nil {
		return pageProjectionResult{}, err
	}

	for _, relation := range page.Relations {
		_, sourceTombstoned := tombstonedItemIdentities[relation.SourceEnvironmentID+"\x00"+relation.FromExternalID]
		_, targetTombstoned := tombstonedItemIdentities[relation.TargetEnvironmentID+"\x00"+relation.ToExternalID]
		if sourceTombstoned || targetTombstoned {
			return pageProjectionResult{}, discoverysource.ErrPageCommitConflict
		}
	}
	relationFacts, relationDigest, err := buildPageRelationFacts(admission, page.Relations)
	if err != nil {
		return pageProjectionResult{}, err
	}
	for index, relationFact := range relationFacts {
		if err := projectPageRelation(
			ctx, tx, admission, coordinates, relationFact, relationDigest, ids.Relations[index],
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return pageProjectionResult{}, discoverysource.ErrPageCommitConflict
			}
			return pageProjectionResult{}, err
		}
	}
	for _, assetID := range tombstonedAssets {
		if err := inactivatePageRelationships(
			ctx, tx, admission, coordinates, relationDigest, assetID, false, newID,
		); err != nil {
			return pageProjectionResult{}, err
		}
	}
	if page.FinalPage && page.CompleteSnapshot && admission.Run.Rejected == 0 && counts.Rejected == 0 {
		missing, stale, err := closeMissingPageAssets(ctx, tx, admission, coordinates, newID)
		if err != nil {
			return pageProjectionResult{}, err
		}
		counts.Missing += missing
		counts.Stale += stale
		if err := inactivatePageRelationships(
			ctx, tx, admission, coordinates, relationDigest, "", true, newID,
		); err != nil {
			return pageProjectionResult{}, err
		}
	}
	return pageProjectionResult{
		Counts: counts, ItemPageDigest: itemPageDigest, RelationPageDigest: relationDigest,
	}, nil
}

func buildPageItemFacts(
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	item assetdiscovery.NormalizedItem,
	acceptedAt time.Time,
	observationID string,
	prior *pagePriorAsset,
) (pageItemFacts, error) {
	provenanceValues := make(map[string]persistedProvenanceValue, len(item.FieldProvenance))
	provenance := append([]assetdiscovery.FieldProvenance{}, item.FieldProvenance...)
	sort.Slice(provenance, func(left, right int) bool {
		return provenance[left].FieldCode < provenance[right].FieldCode
	})
	for _, value := range provenance {
		provenanceValues[value.FieldCode] = persistedProvenanceValue{
			Confidence: value.Confidence, ObservedAt: pageTimeText(acceptedAt), Ownership: value.Ownership,
			ProviderKind: admission.Source.ProviderKind, ProviderPathCode: value.ProviderPathCode,
			SourceID: admission.Source.ID, SourceRevision: admission.Revision.Revision,
		}
	}
	provenanceJSON, err := canonicalJSON(provenanceValues)
	if err != nil {
		return pageItemFacts{}, discoverysource.ErrPageCommitInvalid
	}
	providerProvenanceFrames := [][]byte{
		[]byte("asset-provider-provenance.v1"), []byte(strconv.Itoa(len(provenance))),
	}
	for _, value := range provenance {
		providerProvenanceFrames = append(providerProvenanceFrames,
			[]byte(value.FieldCode), []byte(value.ProviderPathCode), []byte(value.Ownership),
			[]byte(strconv.Itoa(value.Confidence)),
		)
	}
	providerProvenance := framedDigest(providerProvenanceFrames...)
	fingerprintCodes := make([]string, 0, len(item.Fingerprints))
	for code := range item.Fingerprints {
		fingerprintCodes = append(fingerprintCodes, code)
	}
	sort.Strings(fingerprintCodes)
	fingerprintFrames := []manualFrame{
		{value: []byte("asset-fingerprints.v1")}, {value: []byte(strconv.Itoa(len(fingerprintCodes)))},
	}
	for _, code := range fingerprintCodes {
		valueDigest := framedDigest(
			[]byte("asset-fingerprint-value.v1"), []byte(code), []byte(item.Fingerprints[code]),
		)
		fingerprintFrames = append(fingerprintFrames, manualFrame{value: []byte(code)}, manualFrame{digest: valueDigest})
	}
	fingerprintDigest, err := framedDigestWithNamedHashes(fingerprintFrames)
	if err != nil {
		return pageItemFacts{}, discoverysource.ErrPageCommitInvalid
	}
	kindFrame, displayFrame := manualFrame{value: []byte(item.Kind)}, manualFrame{value: []byte(item.DisplayName)}
	documentFrame, tombstoneReason := manualFrame{digest: item.DocumentSHA256}, manualFrame{null: true}
	if item.Tombstone {
		kindFrame, displayFrame, documentFrame = manualFrame{null: true}, manualFrame{null: true}, manualFrame{null: true}
		tombstoneReason = manualFrame{value: []byte(item.TombstoneReason)}
	}
	providerFact, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-provider-fact.v1")},
		{value: []byte(admission.Run.TenantID)}, {value: []byte(admission.Run.WorkspaceID)},
		{value: []byte(admission.Source.ID)}, {value: []byte(admission.Source.ProviderKind)},
		{value: []byte(strconv.FormatInt(admission.Revision.Revision, 10))},
		{digest: admission.Revision.CanonicalRevisionDigest}, {digest: admission.Revision.SourceDefinitionDigest},
		{value: []byte(item.EnvironmentID)}, {value: []byte(item.ExternalID)}, kindFrame, displayFrame,
		{value: []byte(item.SchemaVersion)}, {value: boolFrame(item.Tombstone)}, tombstoneReason,
		documentFrame, {digest: fingerprintDigest}, {digest: providerProvenance},
	})
	if err != nil {
		return pageItemFacts{}, discoverysource.ErrPageCommitInvalid
	}
	previousID, previousChain := manualFrame{null: true}, manualFrame{null: true}
	if prior != nil {
		previousID, previousChain = manualFrame{value: []byte(prior.LastObservationID)}, manualFrame{digest: prior.LastChain}
	}
	freshnessTime := manualFrame{null: true}
	if item.Freshness.OrderTime != nil {
		freshnessTime = manualFrame{value: []byte(pageTimeText(*item.Freshness.OrderTime))}
	}
	chain, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-observation-chain.v1")},
		{value: []byte(admission.Run.TenantID)}, {value: []byte(admission.Run.WorkspaceID)},
		{value: []byte(item.EnvironmentID)}, {value: []byte(admission.Source.ID)},
		{value: []byte(coordinates.RunID)}, {value: []byte(observationID)},
		{value: []byte(item.ProviderKind)}, {value: []byte(item.ExternalID)},
		{value: []byte(strconv.FormatInt(admission.Revision.Revision, 10))},
		{digest: admission.Revision.CanonicalRevisionDigest}, {value: []byte(pageTimeText(acceptedAt))},
		{value: []byte(item.Freshness.Kind)}, freshnessTime,
		{value: []byte(strconv.FormatInt(item.Freshness.OrderSequence, 10))},
		{digest: item.Freshness.ProviderVersionSHA256},
		{value: []byte(strconv.FormatInt(admission.Run.CheckpointVersion+1, 10))},
		{value: []byte(strconv.FormatInt(admission.Run.FenceEpoch, 10))},
		{value: []byte(strconv.FormatInt(coordinates.PageSequence, 10))},
		{digest: providerFact}, {digest: sha256Hex(provenanceJSON)}, previousID, previousChain,
	})
	if err != nil {
		return pageItemFacts{}, discoverysource.ErrPageCommitInvalid
	}
	document := append([]byte{}, item.Document...)
	if item.Tombstone {
		document = nil
	}
	return pageItemFacts{
		Provenance: provenanceJSON, Document: document, ProvenanceDigest: sha256Hex(provenanceJSON),
		FingerprintDigest: fingerprintDigest, ProviderProvenanceDigest: providerProvenance,
		ProviderFactDigest: providerFact, ObservationChainDigest: chain,
	}, nil
}

func insertPageObservation(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	item assetdiscovery.NormalizedItem,
	facts pageItemFacts,
	acceptedAt time.Time,
	observationID string,
	prior pagePriorAsset,
	hasPrior bool,
) error {
	var previousID, previousChain any
	if hasPrior {
		previousID, previousChain = prior.LastObservationID, prior.LastChain
	}
	var document, documentSHA, reason any = facts.Document, item.DocumentSHA256, nil
	schemaVersion := item.SchemaVersion
	if item.Tombstone {
		document, documentSHA, reason = nil, nil, item.TombstoneReason
		if schemaVersion == "" {
			schemaVersion = prior.PriorSchemaVersion
		}
	}
	_, err := tx.Exec(ctx, `
INSERT INTO asset_observations (
 id,tenant_id,workspace_id,environment_id,source_id,run_id,provider_kind,external_id,
 source_revision,canonical_revision_digest,source_definition_digest,observed_at,
 freshness_kind,freshness_order_time,freshness_order_sequence,provider_version_sha256,
 provider_fact_sha256,fingerprint_sha256,provider_provenance_sha256,
 previous_observation_id,previous_chain_sha256,observation_chain_sha256,
 accepted_checkpoint_version,run_fence_epoch,run_page_sequence,schema_version,
 normalized_document,document_sha256,field_provenance,field_provenance_sha256,
 tombstone,tombstone_reason_code
) VALUES (
 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7,$8,
 $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20::uuid,$21,$22,
 $23,$24,$25,$26,$27,$28,$29,$30,$31,$32
)
`, observationID, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID,
		admission.Source.ID, admission.Run.ID, item.ProviderKind, item.ExternalID,
		admission.Revision.Revision, admission.Revision.CanonicalRevisionDigest,
		admission.Revision.SourceDefinitionDigest, acceptedAt, item.Freshness.Kind,
		item.Freshness.OrderTime, item.Freshness.OrderSequence, item.Freshness.ProviderVersionSHA256,
		facts.ProviderFactDigest, facts.FingerprintDigest, facts.ProviderProvenanceDigest,
		previousID, previousChain, facts.ObservationChainDigest,
		admission.Run.CheckpointVersion+1, admission.Run.FenceEpoch, coordinates.PageSequence,
		schemaVersion, document, documentSHA, facts.Provenance, facts.ProvenanceDigest,
		item.Tombstone, reason)
	return err
}

func insertPageAssetAndDetail(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	item assetdiscovery.NormalizedItem,
	facts pageItemFacts,
	acceptedAt time.Time,
	ids pageItemIDs,
) error {
	requestID := pageAssetRequestID(coordinates, item, "create")
	if _, err := tx.Exec(ctx, `
INSERT INTO assets (
 id,tenant_id,workspace_id,environment_id,source_id,provider_kind,external_id,
 kind,display_name,owner_group,criticality,data_classification,labels,lifecycle,mapping_status,
 last_observation_id,last_observation_chain_sha256,last_observed_at,last_source_revision,
 create_idempotency_key,create_request_hash,version
) VALUES (
 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7,$8,$9,NULL,'MEDIUM','INTERNAL','{}'::jsonb,
 'DISCOVERED','UNRESOLVED',$10::uuid,$11,$12,$13,$14,$15,1
)
`, ids.Asset, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID,
		admission.Source.ID, item.ProviderKind, item.ExternalID, item.Kind, item.DisplayName,
		ids.Observation, facts.ObservationChainDigest, acceptedAt, admission.Revision.Revision,
		requestID, facts.ProviderFactDigest); err != nil {
		return err
	}
	if err := insertPageTypeDetail(
		ctx, tx, admission, item, facts, acceptedAt, ids, 1,
	); err != nil {
		return err
	}
	asset := assetcatalog.Asset{
		ID: ids.Asset, SourceID: admission.Source.ID, Scope: assetcatalog.Scope{
			TenantID: admission.Run.TenantID, WorkspaceID: admission.Run.WorkspaceID,
			EnvironmentID: item.EnvironmentID,
		}, Lifecycle: assetcatalog.LifecycleDiscovered, Version: 1,
	}
	return insertPageAssetSideEffects(
		ctx, tx, admission, ids.Audit, ids.Outbox, requestID, assetCreatedAction,
		facts.ProviderFactDigest, asset,
	)
}

func updatePageAssetAndDetail(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	item assetdiscovery.NormalizedItem,
	facts pageItemFacts,
	acceptedAt time.Time,
	ids pageItemIDs,
	prior pagePriorAsset,
	lifecycle string,
	changed bool,
) error {
	displayName := prior.DisplayName
	if !item.Tombstone {
		displayName = item.DisplayName
	}
	var nextVersion int64
	if err := tx.QueryRow(ctx, `
UPDATE assets
SET display_name=$5,lifecycle=$6,last_observation_id=$7::uuid,
    last_observation_chain_sha256=$8,last_observed_at=$9,last_source_revision=$10,
    version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND id=$4::uuid AND version=$11
RETURNING version
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID, prior.ID,
		displayName, lifecycle, ids.Observation, facts.ObservationChainDigest, acceptedAt,
		admission.Revision.Revision, prior.Version).Scan(&nextVersion); err != nil || nextVersion != prior.Version+1 {
		if err != nil {
			return err
		}
		return discoverysource.ErrPageCommitConflict
	}
	if !item.Tombstone && (prior.PriorDocumentSHA256 != item.DocumentSHA256 ||
		prior.PriorSchemaVersion != item.SchemaVersion) {
		var detailRevision int64
		if err := tx.QueryRow(ctx, `
SELECT COALESCE(max(revision),0)+1 FROM asset_type_details
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND environment_id=$3::uuid AND asset_id=$4::uuid
`, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID, prior.ID).Scan(&detailRevision); err != nil {
			return err
		}
		ids.Asset = prior.ID
		if err := insertPageTypeDetail(ctx, tx, admission, item, facts, acceptedAt, ids, detailRevision); err != nil {
			return err
		}
	}
	restored := !item.Tombstone && prior.Lifecycle == string(assetcatalog.LifecycleStale)
	if !changed && !restored {
		return nil
	}
	requestID := pageAssetRequestID(coordinates, item, "update")
	action := "asset.discovery.updated.v1"
	if restored {
		action = "asset.source.asset.restored.v1"
	}
	asset := assetcatalog.Asset{
		ID: prior.ID, SourceID: admission.Source.ID,
		Scope:     assetcatalog.Scope{TenantID: admission.Run.TenantID, WorkspaceID: admission.Run.WorkspaceID, EnvironmentID: item.EnvironmentID},
		Lifecycle: assetcatalog.Lifecycle(lifecycle), Version: nextVersion,
	}
	return insertPageAssetSideEffects(
		ctx, tx, admission, ids.Audit, ids.Outbox, requestID, action, facts.ProviderFactDigest, asset,
	)
}

func pageRunObjectExists(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	item assetdiscovery.NormalizedItem,
) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS (
 SELECT 1 FROM asset_observations
 WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
   AND run_id=$4::uuid AND provider_kind=$5 AND external_id=$6
)
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
		admission.Run.ID, item.ProviderKind, item.ExternalID).Scan(&exists)
	return exists, err
}

func lockPageFingerprintCandidate(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	item assetdiscovery.NormalizedItem,
	fingerprintDigest string,
) (pageFingerprintCandidate, bool, error) {
	if item.Tombstone || len(item.Fingerprints) == 0 {
		return pageFingerprintCandidate{}, false, nil
	}
	var candidate pageFingerprintCandidate
	err := tx.QueryRow(ctx, `
SELECT candidate.id::text,candidate.lifecycle,candidate.mapping_status,candidate.version
FROM assets AS candidate
JOIN asset_observations AS observation
  ON observation.tenant_id=candidate.tenant_id
 AND observation.workspace_id=candidate.workspace_id
 AND observation.environment_id=candidate.environment_id
 AND observation.source_id=candidate.source_id
 AND observation.id=candidate.last_observation_id
WHERE candidate.tenant_id=$1::uuid AND candidate.workspace_id=$2::uuid
  AND candidate.environment_id=$3::uuid AND candidate.source_id<>$4::uuid
  AND observation.fingerprint_sha256=$5
ORDER BY candidate.source_id,candidate.provider_kind,candidate.external_id,candidate.id
LIMIT 1
FOR UPDATE OF candidate
`, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID,
		admission.Source.ID, fingerprintDigest).Scan(
		&candidate.ID, &candidate.Lifecycle, &candidate.MappingStatus, &candidate.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return pageFingerprintCandidate{}, false, nil
	}
	if err != nil {
		return pageFingerprintCandidate{}, false, err
	}
	return candidate, true, nil
}

func insertPageFingerprintConflict(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	item assetdiscovery.NormalizedItem,
	ids pageItemIDs,
	candidate pageFingerprintCandidate,
	fingerprintDigest string,
) error {
	if _, err := tx.Exec(ctx, `
INSERT INTO asset_conflicts (
 id,tenant_id,workspace_id,environment_id,asset_id,source_id,observation_id,
 conflict_type,field_name,existing_value_sha256,candidate_value_sha256,status
) VALUES (
 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7::uuid,
 'FINGERPRINT_COLLISION','fingerprint_sha256',$8,$8,'OPEN'
)
`, ids.Conflict, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID,
		candidate.ID, admission.Source.ID, ids.Observation, fingerprintDigest); err != nil {
		return err
	}
	if candidate.MappingStatus == "AMBIGUOUS" {
		return nil
	}
	var nextVersion int64
	if err := tx.QueryRow(ctx, `
UPDATE assets
SET mapping_status='AMBIGUOUS',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND environment_id=$3::uuid
  AND id=$4::uuid AND version=$5
RETURNING version
`, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID,
		candidate.ID, candidate.Version).Scan(&nextVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return discoverysource.ErrPageCommitConflict
		}
		return err
	}
	asset := assetcatalog.Asset{
		ID: candidate.ID, Scope: assetcatalog.Scope{
			TenantID: admission.Run.TenantID, WorkspaceID: admission.Run.WorkspaceID,
			EnvironmentID: item.EnvironmentID,
		}, Lifecycle: assetcatalog.Lifecycle(candidate.Lifecycle), MappingStatus: "AMBIGUOUS",
		Version: nextVersion,
	}
	return insertPageAssetSideEffects(
		ctx, tx, admission, ids.Audit, ids.Outbox,
		"source-asset-mapping:"+ids.Observation, pageAssetMappingAmbiguousAction,
		fingerprintDigest, asset,
	)
}

func insertPageTypeDetail(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	item assetdiscovery.NormalizedItem,
	facts pageItemFacts,
	acceptedAt time.Time,
	ids pageItemIDs,
	revision int64,
) error {
	_, err := tx.Exec(ctx, `
INSERT INTO asset_type_details (
 id,tenant_id,workspace_id,environment_id,asset_id,source_id,provider_kind,external_id,
 source_revision,source_observed_at,source_observation_chain_sha256,revision,schema_version,
 source_observation_id,details_document,details_sha256,actor_id
) VALUES (
 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7,$8,$9,$10,$11,$12,$13,
 $14::uuid,$15,$16,$17
)
`, ids.Detail, admission.Run.TenantID, admission.Run.WorkspaceID, item.EnvironmentID,
		ids.Asset, admission.Source.ID, item.ProviderKind, item.ExternalID,
		admission.Revision.Revision, acceptedAt, facts.ObservationChainDigest, revision,
		item.SchemaVersion, ids.Observation, item.Document, item.DocumentSHA256, admission.Run.LeaseOwner)
	return err
}

func insertPageAssetSideEffects(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	auditID, outboxID, requestID, action, payloadHash string,
	asset assetcatalog.Asset,
) error {
	detailValues := map[string]any{
		"environment_id": asset.Scope.EnvironmentID, "lifecycle": asset.Lifecycle,
		"result_version": asset.Version,
	}
	if asset.MappingStatus != "" {
		detailValues["mapping_status"] = asset.MappingStatus
	}
	details, err := canonicalJSON(detailValues)
	if err != nil {
		return discoverysource.ErrPageCommitUnavailable
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_records (
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
 request_id,trace_id,payload_hash,details
) VALUES ($1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,$5,'ASSET',$6,$7,NULL,$8,$9::jsonb)
`, auditID, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Run.LeaseOwner,
		action, asset.ID, requestID, payloadHash, string(details)); err != nil {
		return err
	}
	return insertAssetOutboxRecord(ctx, tx, outboxID, requestID, action, asset)
}

func lockPagePriorAsset(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	item assetdiscovery.NormalizedItem,
) (pagePriorAsset, bool, error) {
	var prior pagePriorAsset
	var freshnessTime *time.Time
	err := tx.QueryRow(ctx, `
SELECT asset.id::text,asset.environment_id::text,asset.kind,asset.display_name,asset.lifecycle,
       asset.last_observation_id::text,asset.last_observation_chain_sha256,
       asset.last_observed_at,asset.last_source_revision,asset.version,
       observation.run_id::text,observation.freshness_kind,observation.freshness_order_time,
       observation.freshness_order_sequence,observation.provider_version_sha256,
	       observation.provider_fact_sha256,COALESCE(observation.document_sha256,''),observation.schema_version
FROM assets AS asset
JOIN asset_observations AS observation ON observation.id=asset.last_observation_id
WHERE asset.tenant_id=$1::uuid AND asset.workspace_id=$2::uuid
  AND asset.source_id=$3::uuid AND asset.provider_kind=$4 AND asset.external_id=$5
FOR UPDATE OF asset
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
		item.ProviderKind, item.ExternalID).Scan(
		&prior.ID, &prior.EnvironmentID, &prior.Kind, &prior.DisplayName, &prior.Lifecycle,
		&prior.LastObservationID, &prior.LastChain, &prior.LastObservedAt,
		&prior.LastSourceRevision, &prior.Version, &prior.PriorRunID,
		&prior.PriorFreshnessKind, &freshnessTime, &prior.PriorFreshnessSequence,
		&prior.PriorProviderVersion, &prior.PriorProviderFact,
		&prior.PriorDocumentSHA256, &prior.PriorSchemaVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return pagePriorAsset{}, false, nil
	}
	if err != nil {
		return pagePriorAsset{}, false, err
	}
	prior.LastObservedAt = canonicalDatabaseTime(prior.LastObservedAt)
	if freshnessTime != nil {
		value := canonicalDatabaseTime(*freshnessTime)
		prior.PriorFreshnessTime = &value
	}
	return prior, true, nil
}

func pageFreshnessAccepts(
	revision int64,
	candidate assetdiscovery.FreshnessCandidate,
	providerFact string,
	prior pagePriorAsset,
) bool {
	if revision < prior.LastSourceRevision || revision == prior.LastSourceRevision && candidate.Kind != prior.PriorFreshnessKind {
		return false
	}
	if revision > prior.LastSourceRevision {
		return true
	}
	comparison := 0
	if candidate.Kind == assetcatalog.FreshnessObjectTimeSequence {
		if candidate.OrderTime == nil || prior.PriorFreshnessTime == nil {
			return false
		}
		left, right := candidate.OrderTime.UTC(), prior.PriorFreshnessTime.UTC()
		switch {
		case left.Before(right):
			comparison = -1
		case left.After(right):
			comparison = 1
		case candidate.OrderSequence < prior.PriorFreshnessSequence:
			comparison = -1
		case candidate.OrderSequence > prior.PriorFreshnessSequence:
			comparison = 1
		}
	} else {
		switch {
		case candidate.OrderSequence < prior.PriorFreshnessSequence:
			comparison = -1
		case candidate.OrderSequence > prior.PriorFreshnessSequence:
			comparison = 1
		}
	}
	if comparison < 0 {
		return false
	}
	return comparison > 0 || candidate.ProviderVersionSHA256 == prior.PriorProviderVersion && providerFact == prior.PriorProviderFact
}

func buildPageRelationFacts(
	admission pageAdmission,
	relations []assetdiscovery.ObservedRelation,
) ([]pageRelationFact, string, error) {
	facts := make([]pageRelationFact, len(relations))
	for index, relation := range relations {
		digest := framedDigest(
			[]byte("asset-relation-fact.v1"), []byte(admission.Run.TenantID),
			[]byte(admission.Run.WorkspaceID), []byte(admission.Source.ID),
			[]byte(strconv.FormatInt(admission.Revision.Revision, 10)),
			mustDigestBytes(admission.Revision.CanonicalRevisionDigest),
			[]byte(relation.SourceEnvironmentID), []byte(relation.TargetEnvironmentID),
			[]byte(relation.FromExternalID), []byte(relation.ToExternalID), []byte(relation.Type),
			[]byte(relation.ProviderPathCode), []byte(strconv.Itoa(relation.Confidence)),
		)
		facts[index] = pageRelationFact{Relation: relation, Digest: digest}
	}
	sort.Slice(facts, func(left, right int) bool {
		return relationIdentityLess(facts[left].Relation, facts[right].Relation)
	})
	frames := []manualFrame{
		{value: []byte("asset-relation-page.v1")}, {value: []byte(strconv.Itoa(len(facts)))},
	}
	for _, fact := range facts {
		freshnessTime := manualFrame{null: true}
		if fact.Relation.Freshness.OrderTime != nil {
			freshnessTime = manualFrame{value: []byte(pageTimeText(*fact.Relation.Freshness.OrderTime))}
		}
		frames = append(frames,
			manualFrame{value: []byte(fact.Relation.SourceEnvironmentID)},
			manualFrame{value: []byte(fact.Relation.TargetEnvironmentID)},
			manualFrame{value: []byte(fact.Relation.FromExternalID)},
			manualFrame{value: []byte(fact.Relation.ToExternalID)},
			manualFrame{value: []byte(fact.Relation.Type)},
			manualFrame{value: []byte(fact.Relation.ProviderPathCode)},
			manualFrame{value: []byte(fact.Relation.Freshness.Kind)}, freshnessTime,
			manualFrame{value: []byte(strconv.FormatInt(fact.Relation.Freshness.OrderSequence, 10))},
			manualFrame{digest: fact.Relation.Freshness.ProviderVersionSHA256},
			manualFrame{digest: fact.Digest},
		)
	}
	digest, err := framedDigestWithNamedHashes(frames)
	if err != nil {
		return nil, "", discoverysource.ErrPageCommitInvalid
	}
	return facts, digest, nil
}

func projectPageRelation(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	fact pageRelationFact,
	relationPageDigest string,
	ids pageRelationIDs,
) error {
	relation := fact.Relation
	var sourceAssetID, targetAssetID string
	if err := tx.QueryRow(ctx, `
SELECT source_asset.id::text,target_asset.id::text
FROM assets AS source_asset
JOIN assets AS target_asset
  ON target_asset.tenant_id=source_asset.tenant_id
 AND target_asset.workspace_id=source_asset.workspace_id
 AND target_asset.source_id=source_asset.source_id
WHERE source_asset.tenant_id=$1::uuid AND source_asset.workspace_id=$2::uuid
  AND source_asset.source_id=$3::uuid
  AND source_asset.environment_id=$4::uuid AND source_asset.external_id=$5
  AND target_asset.environment_id=$6::uuid AND target_asset.external_id=$7
FOR UPDATE OF source_asset,target_asset
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
		relation.SourceEnvironmentID, relation.FromExternalID,
		relation.TargetEnvironmentID, relation.ToExternalID).Scan(&sourceAssetID, &targetAssetID); err != nil {
		return err
	}
	var (
		existingID, existingStatus, existingRun, existingPolicy string
		existingRevision, existingSequence, existingVersion     int64
		existingFreshnessKind                                   assetcatalog.FreshnessKind
		existingFreshnessTime                                   *time.Time
		existingFreshnessSequence                               int64
		existingProviderVersion, existingFact                   string
	)
	err := tx.QueryRow(ctx, `
SELECT id::text,status,last_run_id::text,COALESCE(cross_environment_policy_reference_id,''),
       source_revision,last_page_sequence,version,freshness_kind,freshness_order_time,
       freshness_order_sequence,provider_version_sha256,relation_fact_sha256
FROM asset_relationships
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND source_environment_id=$4::uuid AND target_environment_id=$5::uuid
  AND from_external_id=$6 AND to_external_id=$7
  AND relationship_type=$8 AND provider_path_code=$9
ORDER BY updated_at DESC,id
LIMIT 1
FOR UPDATE
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
		relation.SourceEnvironmentID, relation.TargetEnvironmentID,
		relation.FromExternalID, relation.ToExternalID, relation.Type, relation.ProviderPathCode).Scan(
		&existingID, &existingStatus, &existingRun, &existingPolicy, &existingRevision,
		&existingSequence, &existingVersion, &existingFreshnessKind, &existingFreshnessTime,
		&existingFreshnessSequence, &existingProviderVersion, &existingFact,
	)
	policyReference := string(relation.CrossEnvironmentPolicyReferenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		var collisionID string
		collisionErr := tx.QueryRow(ctx, `
SELECT id::text FROM asset_relationships
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_asset_id=$3::uuid AND target_asset_id=$4::uuid
  AND relationship_type=$5 AND status='ACTIVE'
FOR UPDATE
`, admission.Run.TenantID, admission.Run.WorkspaceID, sourceAssetID, targetAssetID, relation.Type).Scan(&collisionID)
		if collisionErr == nil {
			return discoverysource.ErrPageCommitConflict
		}
		if !errors.Is(collisionErr, pgx.ErrNoRows) {
			return collisionErr
		}
		requestID := "source-relation:" + fact.Digest
		_, err = tx.Exec(ctx, `
INSERT INTO asset_relationships (
 id,tenant_id,workspace_id,source_id,source_revision,canonical_revision_digest,
 last_run_id,last_page_sequence,accepted_checkpoint_version,run_fence_epoch,relation_page_sha256,
 source_environment_id,target_environment_id,source_asset_id,target_asset_id,
 from_external_id,to_external_id,relationship_type,provider_path_code,confidence,
 freshness_kind,freshness_order_time,freshness_order_sequence,provider_version_sha256,
 relation_fact_sha256,provenance,provenance_source_id,cross_environment_policy_reference_id,
 status,idempotency_key,request_hash,version
) VALUES (
 $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7::uuid,$8,$9,$10,$11,
 $12::uuid,$13::uuid,$14::uuid,$15::uuid,$16,$17,$18,$19,$20,
 $21,$22,$23,$24,$25,'DISCOVERED',$4::uuid,$26,'ACTIVE',$27,$25,1
)
`, ids.Relationship, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
			admission.Revision.Revision, admission.Revision.CanonicalRevisionDigest,
			admission.Run.ID, coordinates.PageSequence, admission.Run.CheckpointVersion+1,
			admission.Run.FenceEpoch, relationPageDigest,
			relation.SourceEnvironmentID, relation.TargetEnvironmentID, sourceAssetID, targetAssetID,
			relation.FromExternalID, relation.ToExternalID, relation.Type, relation.ProviderPathCode,
			relation.Confidence, relation.Freshness.Kind, relation.Freshness.OrderTime,
			relation.Freshness.OrderSequence, relation.Freshness.ProviderVersionSHA256,
			fact.Digest, nullablePageString(policyReference), requestID)
		if err != nil {
			return err
		}
		return insertPageRelationshipSideEffects(
			ctx, tx, admission, ids, requestID, fact.Digest,
			pageRelationshipProjectedAction, "ACTIVE", 1,
		)
	}
	if err != nil {
		return err
	}
	var activeCollisionID string
	activeCollisionErr := tx.QueryRow(ctx, `
SELECT id::text FROM asset_relationships
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid
  AND source_asset_id=$3::uuid AND target_asset_id=$4::uuid
  AND relationship_type=$5 AND status='ACTIVE' AND id<>$6::uuid
ORDER BY id
LIMIT 1
FOR UPDATE
`, admission.Run.TenantID, admission.Run.WorkspaceID, sourceAssetID, targetAssetID,
		relation.Type, existingID).Scan(&activeCollisionID)
	if activeCollisionErr == nil {
		return discoverysource.ErrPageCommitConflict
	}
	if !errors.Is(activeCollisionErr, pgx.ErrNoRows) {
		return activeCollisionErr
	}
	if existingRun == admission.Run.ID || existingPolicy != policyReference ||
		existingRevision > admission.Revision.Revision ||
		existingRevision == admission.Revision.Revision && !relationFreshnessAccepts(
			relation.Freshness, fact.Digest, existingFreshnessKind, existingFreshnessTime,
			existingFreshnessSequence, existingProviderVersion, existingFact,
		) {
		return discoverysource.ErrPageCommitConflict
	}
	var nextVersion int64
	if err := tx.QueryRow(ctx, `
UPDATE asset_relationships
SET source_revision=$4,canonical_revision_digest=$5,last_run_id=$6::uuid,
    last_page_sequence=$7,accepted_checkpoint_version=$8,run_fence_epoch=$9,
    relation_page_sha256=$10,confidence=$11,freshness_kind=$12,freshness_order_time=$13,
    freshness_order_sequence=$14,provider_version_sha256=$15,relation_fact_sha256=$16,
    status='ACTIVE',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND id=$3::uuid AND version=$17
RETURNING version
`, admission.Run.TenantID, admission.Run.WorkspaceID, existingID,
		admission.Revision.Revision, admission.Revision.CanonicalRevisionDigest,
		admission.Run.ID, coordinates.PageSequence, admission.Run.CheckpointVersion+1,
		admission.Run.FenceEpoch, relationPageDigest, relation.Confidence,
		relation.Freshness.Kind, relation.Freshness.OrderTime, relation.Freshness.OrderSequence,
		relation.Freshness.ProviderVersionSHA256, fact.Digest, existingVersion).Scan(&nextVersion); err != nil {
		return err
	}
	requestID := "source-relation-update:" + fact.Digest + ":" + strconv.FormatInt(coordinates.PageSequence, 10)
	ids.Relationship = existingID
	return insertPageRelationshipSideEffects(
		ctx, tx, admission, ids, requestID, fact.Digest,
		pageRelationshipProjectedAction, "ACTIVE", nextVersion,
	)
}

func insertPageRelationshipSideEffects(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	ids pageRelationIDs,
	requestID, payloadHash, action, status string,
	version int64,
) error {
	details, err := canonicalJSON(map[string]any{"result_version": version, "status": status})
	if err != nil {
		return discoverysource.ErrPageCommitUnavailable
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO audit_records (
 id,tenant_id,workspace_id,actor_type,actor_id,action,resource_type,resource_id,
 request_id,trace_id,payload_hash,details
) VALUES ($1::uuid,$2::uuid,$3::uuid,'SYSTEM',$4,$5,
 'ASSET_RELATIONSHIP',$6,$7,NULL,$8,$9::jsonb)
`, ids.Audit, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Run.LeaseOwner,
		action, ids.Relationship, requestID, payloadHash, string(details)); err != nil {
		return err
	}
	payload, err := canonicalJSON(map[string]any{
		"relationship_id": ids.Relationship, "status": status, "version": version,
	})
	if err != nil {
		return discoverysource.ErrPageCommitUnavailable
	}
	_, err = tx.Exec(ctx, `
INSERT INTO outbox_events (
 id,tenant_id,workspace_id,aggregate_type,aggregate_id,aggregate_version,event_type,payload
) VALUES ($1::uuid,$2::uuid,$3::uuid,'ASSET_RELATIONSHIP',$4::uuid,$5,$6,$7::jsonb)
`, ids.Outbox, admission.Run.TenantID, admission.Run.WorkspaceID,
		ids.Relationship, version, action, string(payload))
	return err
}

func relationFreshnessAccepts(
	candidate assetdiscovery.FreshnessCandidate,
	fact string,
	priorKind assetcatalog.FreshnessKind,
	priorTime *time.Time,
	priorSequence int64,
	priorVersion, priorFact string,
) bool {
	if candidate.Kind != priorKind {
		return false
	}
	comparison := 0
	if candidate.Kind == assetcatalog.FreshnessObjectTimeSequence {
		if candidate.OrderTime == nil || priorTime == nil {
			return false
		}
		switch {
		case candidate.OrderTime.Before(*priorTime):
			comparison = -1
		case candidate.OrderTime.After(*priorTime):
			comparison = 1
		case candidate.OrderSequence < priorSequence:
			comparison = -1
		case candidate.OrderSequence > priorSequence:
			comparison = 1
		}
	} else if candidate.OrderSequence < priorSequence {
		comparison = -1
	} else if candidate.OrderSequence > priorSequence {
		comparison = 1
	}
	return comparison > 0 || comparison == 0 && candidate.ProviderVersionSHA256 == priorVersion && fact == priorFact
}

func closeMissingPageAssets(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	newID func() string,
) (int64, int64, error) {
	var missing int64
	if err := tx.QueryRow(ctx, `
SELECT count(*) FROM assets AS asset
WHERE asset.tenant_id=$1::uuid AND asset.workspace_id=$2::uuid AND asset.source_id=$3::uuid
  AND asset.lifecycle<>'RETIRED'
  AND NOT EXISTS (
    SELECT 1 FROM asset_observations AS observation
    WHERE observation.tenant_id=asset.tenant_id AND observation.workspace_id=asset.workspace_id
      AND observation.source_id=asset.source_id AND observation.run_id=$4::uuid
      AND observation.provider_kind=asset.provider_kind AND observation.external_id=asset.external_id
  )
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID, admission.Run.ID).Scan(&missing); err != nil {
		return 0, 0, err
	}
	rows, err := tx.Query(ctx, `
UPDATE assets AS asset
SET lifecycle='STALE',version=version+1
WHERE asset.tenant_id=$1::uuid AND asset.workspace_id=$2::uuid AND asset.source_id=$3::uuid
  AND asset.lifecycle='ACTIVE'
  AND NOT EXISTS (
    SELECT 1 FROM asset_observations AS observation
    WHERE observation.tenant_id=asset.tenant_id AND observation.workspace_id=asset.workspace_id
      AND observation.source_id=asset.source_id AND observation.run_id=$4::uuid
      AND observation.provider_kind=asset.provider_kind AND observation.external_id=asset.external_id
  )
RETURNING asset.id::text,asset.environment_id::text,asset.version
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID, admission.Run.ID)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	staleAssets := make([]assetcatalog.Asset, 0)
	for rows.Next() {
		asset := assetcatalog.Asset{
			SourceID: admission.Source.ID, Lifecycle: assetcatalog.LifecycleStale,
			Scope: assetcatalog.Scope{
				TenantID: admission.Run.TenantID, WorkspaceID: admission.Run.WorkspaceID,
			},
		}
		if err := rows.Scan(&asset.ID, &asset.Scope.EnvironmentID, &asset.Version); err != nil {
			return 0, 0, err
		}
		staleAssets = append(staleAssets, asset)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}
	rows.Close()
	sort.Slice(staleAssets, func(left, right int) bool { return staleAssets[left].ID < staleAssets[right].ID })
	for _, asset := range staleAssets {
		auditID, outboxID, err := allocatePageSideEffectIDs(newID)
		if err != nil {
			return 0, 0, err
		}
		requestID := "source-asset-stale:" + admission.Run.ID + ":" + asset.ID
		payloadHash := framedDigest(
			[]byte("asset-source-stale.v1"), []byte(admission.Run.ID), []byte(asset.ID),
			[]byte(strconv.FormatInt(coordinates.PageSequence, 10)),
			[]byte(strconv.FormatInt(asset.Version, 10)),
		)
		if err := insertPageAssetSideEffects(
			ctx, tx, admission, auditID, outboxID, requestID,
			pageAssetStaleAction, payloadHash, asset,
		); err != nil {
			return 0, 0, err
		}
	}
	return missing, int64(len(staleAssets)), nil
}

func inactivatePageRelationships(
	ctx context.Context,
	tx pgx.Tx,
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	relationPageDigest, assetID string,
	missingClosure bool,
	newID func() string,
) error {
	if !missingClosure {
		var currentRunEdge bool
		if err := tx.QueryRow(ctx, `
SELECT EXISTS (
 SELECT 1 FROM asset_relationships
 WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
   AND status='ACTIVE' AND last_run_id=$4::uuid
   AND (source_asset_id=$5::uuid OR target_asset_id=$5::uuid)
)
`, admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
			admission.Run.ID, assetID).Scan(&currentRunEdge); err != nil {
			return err
		}
		if currentRunEdge {
			return discoverysource.ErrPageCommitConflict
		}
	}
	query := `
UPDATE asset_relationships
SET source_revision=$4,canonical_revision_digest=$5,last_run_id=$6::uuid,
    last_page_sequence=$7,accepted_checkpoint_version=$8,run_fence_epoch=$9,
    relation_page_sha256=$10,status='INACTIVE',version=version+1
WHERE tenant_id=$1::uuid AND workspace_id=$2::uuid AND source_id=$3::uuid
  AND status='ACTIVE' AND provenance='DISCOVERED' AND provenance_source_id=source_id
  AND last_run_id<>$6::uuid`
	arguments := []any{
		admission.Run.TenantID, admission.Run.WorkspaceID, admission.Source.ID,
		admission.Revision.Revision, admission.Revision.CanonicalRevisionDigest,
		admission.Run.ID, coordinates.PageSequence, admission.Run.CheckpointVersion + 1,
		admission.Run.FenceEpoch, relationPageDigest,
	}
	if !missingClosure {
		query += ` AND (source_asset_id=$11::uuid OR target_asset_id=$11::uuid)`
		arguments = append(arguments, assetID)
	}
	query += ` RETURNING id::text,version`
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return err
	}
	defer rows.Close()
	type inactiveRelationship struct {
		ID      string
		Version int64
	}
	inactive := make([]inactiveRelationship, 0)
	for rows.Next() {
		var relationship inactiveRelationship
		if err := rows.Scan(&relationship.ID, &relationship.Version); err != nil {
			return err
		}
		inactive = append(inactive, relationship)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	sort.Slice(inactive, func(left, right int) bool { return inactive[left].ID < inactive[right].ID })
	for _, relationship := range inactive {
		auditID, outboxID, err := allocatePageSideEffectIDs(newID)
		if err != nil {
			return err
		}
		requestID := "source-relation-inactive:" + admission.Run.ID + ":" + relationship.ID
		payloadHash := framedDigest(
			[]byte("asset-source-relationship-inactive.v1"), []byte(admission.Run.ID),
			[]byte(relationship.ID), []byte(strconv.FormatInt(coordinates.PageSequence, 10)),
			[]byte(relationPageDigest), []byte(strconv.FormatInt(relationship.Version, 10)),
		)
		if err := insertPageRelationshipSideEffects(
			ctx, tx, admission, pageRelationIDs{
				Relationship: relationship.ID, Audit: auditID, Outbox: outboxID,
			}, requestID, payloadHash, pageRelationshipInactiveAction, "INACTIVE", relationship.Version,
		); err != nil {
			return err
		}
	}
	return nil
}

func allocatePageSideEffectIDs(newID func() string) (string, string, error) {
	if newID == nil {
		return "", "", discoverysource.ErrPageCommitUnavailable
	}
	auditID, outboxID := newID(), newID()
	if !validUUID(auditID) || !validUUID(outboxID) || auditID == outboxID {
		return "", "", discoverysource.ErrPageCommitUnavailable
	}
	return auditID, outboxID, nil
}

func pageSemanticIdentity(
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
	replay discoverycheckpoint.ReplayIdentity,
) (string, error) {
	items := append([]assetdiscovery.NormalizedItem{}, page.Items...)
	sort.Slice(items, func(left, right int) bool { return itemIdentityLess(items[left], items[right]) })
	relations := append([]assetdiscovery.ObservedRelation{}, page.Relations...)
	sort.Slice(relations, func(left, right int) bool { return relationIdentityLess(relations[left], relations[right]) })
	frames := []manualFrame{
		{value: []byte("asset-source-page-semantic.v1")},
		{value: []byte(coordinates.Locator.Scope.TenantID)},
		{value: []byte(coordinates.Locator.Scope.WorkspaceID)},
		{value: []byte(coordinates.Locator.SourceID)}, {value: []byte(coordinates.RunID)},
		{value: []byte(strconv.FormatInt(coordinates.PageSequence, 10))},
		{value: []byte(page.NextCheckpoint.ProfileCode())},
		{value: []byte(strconv.Itoa(len(items)))},
	}
	for _, item := range items {
		fingerprints := make([]string, 0, len(item.Fingerprints))
		for key := range item.Fingerprints {
			fingerprints = append(fingerprints, key)
		}
		sort.Strings(fingerprints)
		provenance := append([]assetdiscovery.FieldProvenance{}, item.FieldProvenance...)
		sort.Slice(provenance, func(left, right int) bool { return provenance[left].FieldCode < provenance[right].FieldCode })
		freshnessTime := manualFrame{null: true}
		if item.Freshness.OrderTime != nil {
			freshnessTime = manualFrame{value: []byte(pageTimeText(*item.Freshness.OrderTime))}
		}
		frames = append(frames,
			manualFrame{value: []byte(item.EnvironmentID)}, manualFrame{value: []byte(item.ProviderKind)},
			manualFrame{value: []byte(item.ExternalID)}, manualFrame{value: []byte(item.Kind)},
			manualFrame{value: []byte(item.DisplayName)}, manualFrame{value: []byte(item.SchemaVersion)},
			manualFrame{digest: item.DocumentSHA256}, manualFrame{digest: sha256Hex(item.Document)},
			manualFrame{value: []byte(item.Freshness.Kind)},
			freshnessTime, manualFrame{value: []byte(strconv.FormatInt(item.Freshness.OrderSequence, 10))},
			manualFrame{digest: item.Freshness.ProviderVersionSHA256}, manualFrame{value: boolFrame(item.Tombstone)},
			manualFrame{value: []byte(item.TombstoneReason)}, manualFrame{value: []byte(strconv.Itoa(len(provenance)))},
		)
		for _, value := range provenance {
			frames = append(frames,
				manualFrame{value: []byte(value.FieldCode)}, manualFrame{value: []byte(value.ProviderPathCode)},
				manualFrame{value: []byte(value.Ownership)}, manualFrame{value: []byte(strconv.Itoa(value.Confidence))},
			)
		}
		frames = append(frames, manualFrame{value: []byte(strconv.Itoa(len(fingerprints)))})
		for _, key := range fingerprints {
			frames = append(frames, manualFrame{value: []byte(key)}, manualFrame{value: []byte(item.Fingerprints[key])})
		}
	}
	frames = append(frames, manualFrame{value: []byte(strconv.Itoa(len(relations)))})
	for _, relation := range relations {
		freshnessTime := manualFrame{null: true}
		if relation.Freshness.OrderTime != nil {
			freshnessTime = manualFrame{value: []byte(pageTimeText(*relation.Freshness.OrderTime))}
		}
		frames = append(frames,
			manualFrame{value: []byte(relation.SourceEnvironmentID)},
			manualFrame{value: []byte(relation.TargetEnvironmentID)},
			manualFrame{value: []byte(relation.FromExternalID)}, manualFrame{value: []byte(relation.ToExternalID)},
			manualFrame{value: []byte(relation.Type)}, manualFrame{value: []byte(relation.ProviderPathCode)},
			manualFrame{value: []byte(relation.CrossEnvironmentPolicyReferenceID)},
			manualFrame{value: []byte(strconv.Itoa(relation.Confidence))},
			manualFrame{value: []byte(relation.Freshness.Kind)}, freshnessTime,
			manualFrame{value: []byte(strconv.FormatInt(relation.Freshness.OrderSequence, 10))},
			manualFrame{digest: relation.Freshness.ProviderVersionSHA256},
		)
	}
	frames = append(frames,
		manualFrame{value: boolFrame(page.FinalPage)}, manualFrame{value: boolFrame(page.CompleteSnapshot)},
		manualFrame{value: []byte(replay.CheckpointKeyID)}, manualFrame{digest: replay.DigestSHA256},
	)
	return framedDigestWithNamedHashes(frames)
}

func committedPageDigest(
	admission pageAdmission,
	coordinates discoverysource.PageCommitCoordinates,
	page discoverysource.Page,
	acceptedAt time.Time,
	sealed discoverycheckpoint.SealedCheckpoint,
	projection pageProjectionResult,
	semanticIdentity string,
) string {
	value, err := framedDigestWithNamedHashes([]manualFrame{
		{value: []byte("asset-source-page.v2")},
		{value: []byte(admission.Run.TenantID)}, {value: []byte(admission.Run.WorkspaceID)},
		{value: []byte(admission.Source.ID)}, {value: []byte(admission.Run.ID)},
		{value: []byte(strconv.FormatInt(coordinates.PageSequence, 10))},
		{value: []byte(strconv.FormatInt(admission.Revision.Revision, 10))},
		{digest: admission.Revision.CanonicalRevisionDigest}, {value: []byte(admission.Revision.ProfileCode)},
		{value: []byte(strconv.FormatInt(admission.Run.GateRevision, 10))},
		{value: []byte(strconv.FormatInt(admission.Run.FenceEpoch, 10))},
		{value: []byte(pageTimeText(acceptedAt))}, {digest: sealed.CheckpointSHA256},
		{value: []byte(strconv.FormatInt(sealed.CheckpointVersion, 10))},
		{digest: projection.ItemPageDigest}, {digest: projection.RelationPageDigest},
		{value: []byte(strconv.FormatInt(projection.Counts.Observed, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Created, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Changed, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Unchanged, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Conflict, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Missing, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Stale, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Restored, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Tombstoned, 10))},
		{value: []byte(strconv.FormatInt(projection.Counts.Rejected, 10))},
		{value: boolFrame(page.FinalPage)}, {value: boolFrame(page.CompleteSnapshot)},
		{digest: semanticIdentity},
	})
	if err != nil {
		return ""
	}
	return value
}

func aggregatePageItemDigest(items []assetdiscovery.NormalizedItem, digests []string) (string, error) {
	if len(items) != len(digests) {
		return "", discoverysource.ErrPageCommitUnavailable
	}
	frames := []manualFrame{
		{value: []byte("asset-item-page.v1")}, {value: []byte(strconv.Itoa(len(items)))},
	}
	for index, item := range items {
		frames = append(frames,
			manualFrame{value: []byte(item.EnvironmentID)}, manualFrame{value: []byte(item.ProviderKind)},
			manualFrame{value: []byte(item.ExternalID)}, manualFrame{value: []byte(item.Freshness.Kind)},
			pageOptionalTime(item.Freshness.OrderTime),
			manualFrame{value: []byte(strconv.FormatInt(item.Freshness.OrderSequence, 10))},
			manualFrame{digest: item.Freshness.ProviderVersionSHA256}, manualFrame{digest: digests[index]},
		)
	}
	return framedDigestWithNamedHashes(frames)
}

func pageAssetRequestID(
	coordinates discoverysource.PageCommitCoordinates,
	item assetdiscovery.NormalizedItem,
	action string,
) string {
	identity := framedDigest(
		[]byte("asset-page-request.v1"), []byte(coordinates.RunID),
		[]byte(strconv.FormatInt(coordinates.PageSequence, 10)), []byte(item.EnvironmentID),
		[]byte(item.ProviderKind), []byte(item.ExternalID), []byte(action),
	)
	return "source-asset:" + identity
}

func itemIdentityLess(left, right assetdiscovery.NormalizedItem) bool {
	return strings.Join([]string{left.EnvironmentID, left.ProviderKind, left.ExternalID}, "\x00") <
		strings.Join([]string{right.EnvironmentID, right.ProviderKind, right.ExternalID}, "\x00")
}

func relationIdentityLess(left, right assetdiscovery.ObservedRelation) bool {
	leftIdentity := strings.Join([]string{
		left.SourceEnvironmentID, left.TargetEnvironmentID, left.FromExternalID,
		left.ToExternalID, string(left.Type), left.ProviderPathCode,
	}, "\x00")
	rightIdentity := strings.Join([]string{
		right.SourceEnvironmentID, right.TargetEnvironmentID, right.FromExternalID,
		right.ToExternalID, string(right.Type), right.ProviderPathCode,
	}, "\x00")
	return leftIdentity < rightIdentity
}

func pageTimeText(value time.Time) string {
	return value.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
}

func pageOptionalTime(value *time.Time) manualFrame {
	if value == nil {
		return manualFrame{null: true}
	}
	return manualFrame{value: []byte(pageTimeText(*value))}
}

func boolFrame(value bool) []byte {
	if value {
		return []byte("1")
	}
	return []byte("0")
}

func mustDigestBytes(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
