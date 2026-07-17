package externalcmdb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	cmdbCheckpointDomain    = "cmdb-catalog-checkpoint.v1"
	cmdbCheckpointRedaction = "[REDACTED_EXTERNAL_CMDB_CHECKPOINT]"
	cmdbCheckpointFields    = 13
)

type cmdbPhase string

const (
	cmdbPhaseCapabilities cmdbPhase = "CAPABILITIES"
	cmdbPhaseAssets       cmdbPhase = "ASSETS"
	cmdbPhaseRelations    cmdbPhase = "RELATIONS"
	cmdbPhaseComplete     cmdbPhase = "COMPLETE"
)

type cmdbOrderPosition struct {
	updatedAt  time.Time
	externalID string
	replaySHA  string
	present    bool
}

type cmdbCheckpoint struct {
	phase          cmdbPhase
	authorityID    string
	snapshotEpoch  string
	environmentID  string
	assetCursor    string
	relationCursor string
	assetLast      cmdbOrderPosition
	relationLast   cmdbOrderPosition
	assetsComplete bool
}

func (checkpoint cmdbCheckpoint) MarshalJSON() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*cmdbCheckpoint) UnmarshalJSON([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (cmdbCheckpoint) MarshalText() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*cmdbCheckpoint) UnmarshalText([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (cmdbCheckpoint) MarshalBinary() ([]byte, error) {
	return nil, discoverysource.ErrSensitiveSerialization
}
func (*cmdbCheckpoint) UnmarshalBinary([]byte) error {
	return discoverysource.ErrSensitiveSerialization
}
func (cmdbCheckpoint) String() string       { return cmdbCheckpointRedaction }
func (cmdbCheckpoint) GoString() string     { return cmdbCheckpointRedaction }
func (cmdbCheckpoint) LogValue() slog.Value { return slog.StringValue(cmdbCheckpointRedaction) }
func (cmdbCheckpoint) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, cmdbCheckpointRedaction)
}

func (value *provider) Discover(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	if value == nil || ctx == nil {
		return nil, providerError("DISCOVER_REQUEST_REJECTED")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if request.Checkpoint.ProfileCode() != profileCode ||
		!discoverRequestMatchesBinding(request, value.factory.binding) {
		return nil, providerError("DISCOVER_BINDING_REJECTED")
	}
	checkpoint, err := decodeCMDBCheckpoint(request.Checkpoint)
	if err != nil {
		return nil, providerError("CHECKPOINT_REJECTED")
	}

	session, err := value.factory.open(runtime)
	if err != nil {
		return nil, err
	}
	defer session.close()
	if checkpoint.phase != cmdbPhaseCapabilities &&
		(checkpoint.authorityID != session.expectedAuthorityID ||
			checkpoint.environmentID != session.environmentID) {
		return nil, providerError("CHECKPOINT_AUTHORITY_REJECTED")
	}

	switch checkpoint.phase {
	case cmdbPhaseCapabilities:
		capabilities, err := session.client.capabilities(ctx)
		if err != nil {
			return discoverFailureOrDelay(ctx, request, err, "CAPABILITIES_FAILED")
		}
		validation := validateCapabilities(
			capabilities,
			session.expectedAuthorityID,
			value.factory.now().UTC(),
		)
		if !validation.Passed {
			return nil, providerError("CAPABILITIES_REJECTED")
		}
		checkpoint = cmdbCheckpoint{
			phase:         cmdbPhaseAssets,
			authorityID:   capabilities.AuthorityID,
			snapshotEpoch: capabilities.SnapshotEpoch,
			environmentID: session.environmentID,
		}
		return discoverAssetPage(ctx, session, request, checkpoint)
	case cmdbPhaseAssets:
		return discoverAssetPage(ctx, session, request, checkpoint)
	case cmdbPhaseRelations:
		return discoverRelationPage(ctx, session, request, checkpoint)
	case cmdbPhaseComplete:
		return nil, providerError("DISCOVERY_ALREADY_COMPLETE")
	default:
		return nil, providerError("CHECKPOINT_PHASE_REJECTED")
	}
}

func discoverRequestMatchesBinding(
	request discoverysource.DiscoverRequest,
	binding discoverysource.RuntimeBinding,
) bool {
	return binding.RevisionStatus == assetcatalog.SourceRevisionPublished &&
		request.Locator == binding.Locator &&
		request.SourceRevision == binding.SourceRevision &&
		request.SourceRevisionDigest == binding.SourceRevisionDigest &&
		binding.ProviderKind == providerKind &&
		binding.ProfileCode == profileCode
}

func discoverAssetPage(
	ctx context.Context,
	session runtimeSession,
	request discoverysource.DiscoverRequest,
	checkpoint cmdbCheckpoint,
) (discoverysource.DiscoverOutcome, error) {
	cursor, err := newCatalogCursor(checkpoint.assetCursor)
	if err != nil {
		return nil, providerError("ASSET_CURSOR_REJECTED")
	}
	page, err := session.client.assets(ctx, cursor, min(maxPageBodyBytes, request.Limits.MaxPageBytes))
	if err != nil {
		return discoverFailureOrDelay(ctx, request, err, "ASSET_PAGE_FAILED")
	}
	if err := validateCatalogPageEnvelope(
		page.SnapshotEpoch,
		checkpoint.snapshotEpoch,
		checkpoint.assetCursor,
		page.NextCursor,
		page.FinalPage,
		page.CompleteSnapshot,
	); err != nil {
		return nil, err
	}

	items := make([]assetdiscovery.NormalizedItem, 0, len(page.Items))
	last := checkpoint.assetLast
	for index, raw := range page.Items {
		if code := validateCatalogAssetSchema(raw, request.Limits.MaxDocumentBytes); code != "" {
			return nil, providerError(code)
		}
		position, err := assetOrderPosition(raw)
		if err != nil {
			return nil, err
		}
		if err := validateOrderPosition(last, position, index == 0 && checkpoint.assetLast.present); err != nil {
			return nil, err
		}
		item, err := normalizeAsset(session.environmentID, raw)
		if err != nil {
			return nil, providerError("ASSET_NORMALIZATION_REJECTED")
		}
		items = append(items, item)
		last = position
	}
	if len(items) == 0 && !page.FinalPage {
		return nil, providerError("EMPTY_ASSET_PAGE_REJECTED")
	}

	checkpoint.assetLast = last
	if page.FinalPage {
		checkpoint.phase = cmdbPhaseRelations
		checkpoint.assetCursor = ""
		checkpoint.assetsComplete = page.CompleteSnapshot
		if len(items) == 0 {
			return discoverRelationPage(ctx, session, request, checkpoint)
		}
	} else {
		checkpoint.phase = cmdbPhaseAssets
		checkpoint.assetCursor = page.NextCursor
	}
	next, err := newCMDBCheckpoint(checkpoint)
	if err != nil {
		return nil, err
	}
	return validateDiscoverPage(request, session.environmentID, discoverysource.Page{
		Items:          items,
		NextCheckpoint: next,
	})
}

func discoverRelationPage(
	ctx context.Context,
	session runtimeSession,
	request discoverysource.DiscoverRequest,
	checkpoint cmdbCheckpoint,
) (discoverysource.DiscoverOutcome, error) {
	cursor, err := newCatalogCursor(checkpoint.relationCursor)
	if err != nil {
		return nil, providerError("RELATION_CURSOR_REJECTED")
	}
	page, err := session.client.relations(ctx, cursor, min(maxPageBodyBytes, request.Limits.MaxPageBytes))
	if err != nil {
		return discoverFailureOrDelay(ctx, request, err, "RELATION_PAGE_FAILED")
	}
	if err := validateCatalogPageEnvelope(
		page.SnapshotEpoch,
		checkpoint.snapshotEpoch,
		checkpoint.relationCursor,
		page.NextCursor,
		page.FinalPage,
		page.CompleteSnapshot,
	); err != nil {
		return nil, err
	}
	if page.FinalPage && page.CompleteSnapshot != checkpoint.assetsComplete {
		return nil, providerError("SNAPSHOT_COMPLETION_REJECTED")
	}

	relations := make([]assetdiscovery.ObservedRelation, 0, len(page.Items))
	last := checkpoint.relationLast
	for index, raw := range page.Items {
		position, err := relationOrderPosition(raw)
		if err != nil {
			return nil, err
		}
		if err := validateOrderPosition(last, position, index == 0 && checkpoint.relationLast.present); err != nil {
			return nil, err
		}
		relation, err := normalizeRelation(session.environmentID, raw)
		if err != nil {
			return nil, providerError("RELATION_NORMALIZATION_REJECTED")
		}
		relations = append(relations, relation)
		last = position
	}
	if len(relations) == 0 && !page.FinalPage {
		return nil, providerError("EMPTY_RELATION_PAGE_REJECTED")
	}
	if len(relations) == 0 && page.FinalPage && !page.CompleteSnapshot {
		return nil, providerError("EMPTY_INCREMENTAL_FINAL_REJECTED")
	}

	checkpoint.relationLast = last
	if page.FinalPage {
		checkpoint.phase = cmdbPhaseComplete
		checkpoint.relationCursor = ""
	} else {
		checkpoint.phase = cmdbPhaseRelations
		checkpoint.relationCursor = page.NextCursor
	}
	next, err := newCMDBCheckpoint(checkpoint)
	if err != nil {
		return nil, err
	}
	return validateDiscoverPage(request, session.environmentID, discoverysource.Page{
		Relations:        relations,
		NextCheckpoint:   next,
		FinalPage:        page.FinalPage,
		CompleteSnapshot: page.FinalPage && page.CompleteSnapshot,
	})
}

func discoverFailureOrDelay(
	ctx context.Context,
	request discoverysource.DiscoverRequest,
	err error,
	failureCode string,
) (discoverysource.DiscoverOutcome, error) {
	if contextErr := callerContextError(ctx); contextErr != nil {
		return nil, contextErr
	}
	delay, retryable := providerRetryAfter(err)
	if !retryable {
		return nil, providerError(failureCode)
	}
	if delay <= 0 || delay > maxProviderRetryAfter {
		return nil, providerError("PROVIDER_RETRY_AFTER_REJECTED")
	}
	outcome := discoverysource.Delay{
		Reason:     discoverysource.DelayReasonProviderRetryAfter,
		RetryAfter: delay,
	}
	if err := discoverysource.ValidateDiscoverResult(
		request,
		assetdiscovery.FactPolicy{},
		outcome,
		nil,
	); err != nil {
		return nil, err
	}
	return outcome, nil
}

func validateCatalogPageEnvelope(
	snapshotEpoch string,
	expectedSnapshotEpoch string,
	currentCursor string,
	nextCursor string,
	finalPage bool,
	completeSnapshot bool,
) error {
	if !safeIdentifier(snapshotEpoch) || snapshotEpoch != expectedSnapshotEpoch ||
		completeSnapshot && !finalPage ||
		finalPage != (nextCursor == "") ||
		!finalPage && nextCursor == currentCursor {
		return providerError("PAGE_ENVELOPE_REJECTED")
	}
	if _, err := newCatalogCursor(nextCursor); err != nil {
		return providerError("PAGE_CURSOR_REJECTED")
	}
	return nil
}

func assetOrderPosition(value catalogAsset) (cmdbOrderPosition, error) {
	updatedAt, err := normalizedFreshnessTime(value.UpdatedAt)
	if err != nil {
		return cmdbOrderPosition{}, providerError("ASSET_ORDER_REJECTED")
	}
	fields := []string{
		"cmdb-asset-replay.v1",
		value.ExternalID,
		value.TypeCode,
		value.DisplayName,
		strconv.FormatInt(value.ObjectRevision, 10),
		updatedAt.Format(time.RFC3339Nano),
		strconv.FormatBool(value.Deleted),
		value.TombstoneReason,
	}
	keys := make([]string, 0, len(value.Attributes))
	for key := range value.Attributes {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		fields = append(fields, key, value.Attributes[key])
	}
	return cmdbOrderPosition{
		updatedAt:  updatedAt,
		externalID: value.ExternalID,
		replaySHA:  digestFramedTuple(fields...),
		present:    true,
	}, nil
}

func relationOrderPosition(value catalogRelation) (cmdbOrderPosition, error) {
	if !safeText(value.ExternalID, 1, 512) ||
		unsafeCatalogText(value.ExternalID) ||
		value.ObjectRevision <= 0 ||
		value.Deleted {
		return cmdbOrderPosition{}, providerError("RELATION_SCHEMA_REJECTED")
	}
	updatedAt, err := normalizedFreshnessTime(value.UpdatedAt)
	if err != nil {
		return cmdbOrderPosition{}, providerError("RELATION_ORDER_REJECTED")
	}
	return cmdbOrderPosition{
		updatedAt:  updatedAt,
		externalID: value.ExternalID,
		replaySHA: digestFramedTuple(
			"cmdb-relation-replay.v1",
			value.ExternalID,
			value.FromExternalID,
			value.ToExternalID,
			value.TypeCode,
			strconv.FormatInt(value.ObjectRevision, 10),
			updatedAt.Format(time.RFC3339Nano),
			strconv.FormatBool(value.Deleted),
		),
		present: true,
	}, nil
}

func validateOrderPosition(
	previous cmdbOrderPosition,
	current cmdbOrderPosition,
	boundaryReplay bool,
) error {
	if !current.present {
		return providerError("PAGE_ORDER_REJECTED")
	}
	if !previous.present {
		return nil
	}
	order := current.updatedAt.Compare(previous.updatedAt)
	if order == 0 {
		order = strings.Compare(current.externalID, previous.externalID)
	}
	switch {
	case order < 0:
		return providerError("PAGE_ORDER_REGRESSION")
	case order > 0:
		return nil
	case current.replaySHA != previous.replaySHA:
		return providerError("PAGE_REPLAY_CHANGED")
	case !boundaryReplay:
		return providerError("PAGE_DUPLICATE_REJECTED")
	default:
		return nil
	}
}

func validateDiscoverPage(
	request discoverysource.DiscoverRequest,
	environmentID string,
	page discoverysource.Page,
) (discoverysource.DiscoverOutcome, error) {
	policy, err := discoverPagePolicy(page, environmentID)
	if err != nil {
		page.NextCheckpoint.Clear()
		return nil, err
	}
	if err := discoverysource.ValidateDiscoverResult(request, policy, page, nil); err != nil {
		page.NextCheckpoint.Clear()
		return nil, err
	}
	return page, nil
}

func discoverPagePolicy(
	page discoverysource.Page,
	environmentID string,
) (assetdiscovery.FactPolicy, error) {
	if !canonicalUUIDPattern.MatchString(environmentID) {
		return assetdiscovery.FactPolicy{}, providerError("PAGE_POLICY_AUTHORITY_REJECTED")
	}
	if len(page.Items) > 0 {
		if page.Items[0].EnvironmentID != environmentID {
			return assetdiscovery.FactPolicy{}, providerError("PAGE_POLICY_AUTHORITY_REJECTED")
		}
	} else if len(page.Relations) > 0 {
		if page.Relations[0].SourceEnvironmentID != environmentID {
			return assetdiscovery.FactPolicy{}, providerError("PAGE_POLICY_AUTHORITY_REJECTED")
		}
	}
	policy := normalizedFactPolicy(environmentID, nil)

	fieldsByKind := make(map[assetcatalog.Kind]map[string]struct{})
	for _, item := range page.Items {
		if item.Tombstone {
			continue
		}
		var document map[string]json.RawMessage
		if err := json.Unmarshal(item.Document, &document); err != nil {
			return assetdiscovery.FactPolicy{}, providerError("PAGE_POLICY_REJECTED")
		}
		fields := fieldsByKind[item.Kind]
		if fields == nil {
			fields = make(map[string]struct{})
			fieldsByKind[item.Kind] = fields
		}
		for field := range document {
			fields[field] = struct{}{}
		}
	}
	for kind, fieldSet := range fieldsByKind {
		fields := make([]string, 0, len(fieldSet))
		for field := range fieldSet {
			fields = append(fields, field)
		}
		slices.Sort(fields)
		policy.AllowedDocumentFields[kind] = fields
	}

	relationTypes := make([]assetcatalog.RelationshipType, 0, len(page.Relations))
	for _, relation := range page.Relations {
		if !slices.Contains(relationTypes, relation.Type) {
			relationTypes = append(relationTypes, relation.Type)
		}
	}
	slices.SortFunc(relationTypes, func(left, right assetcatalog.RelationshipType) int {
		return strings.Compare(string(left), string(right))
	})
	policy.RelationshipTypes = relationTypes
	return policy, nil
}

func decodeCMDBCheckpoint(checkpoint discoverysource.Checkpoint) (cmdbCheckpoint, error) {
	var decoded cmdbCheckpoint
	err := discoverysource.WithCheckpointBytes(checkpoint, profileCode, func(canonical []byte) error {
		value, err := decodeCMDBCanonical(canonical)
		if err != nil {
			return err
		}
		decoded = value
		return nil
	})
	if err != nil {
		return cmdbCheckpoint{}, err
	}
	return decoded, nil
}

func decodeCMDBCanonical(canonical []byte) (cmdbCheckpoint, error) {
	if len(canonical) == 0 {
		return cmdbCheckpoint{phase: cmdbPhaseCapabilities}, nil
	}
	if len(canonical) <= sha256.Size {
		return cmdbCheckpoint{}, providerError("CHECKPOINT_CANONICAL_REJECTED")
	}
	payload := canonical[:len(canonical)-sha256.Size]
	checksum := sha256.Sum256(payload)
	if subtle.ConstantTimeCompare(checksum[:], canonical[len(canonical)-sha256.Size:]) != 1 {
		return cmdbCheckpoint{}, providerError("CHECKPOINT_DIGEST_REJECTED")
	}
	reader := bytes.NewReader(payload)
	domain := make([]byte, len(cmdbCheckpointDomain))
	if _, err := io.ReadFull(reader, domain); err != nil ||
		string(domain) != cmdbCheckpointDomain {
		return cmdbCheckpoint{}, providerError("CHECKPOINT_DOMAIN_REJECTED")
	}
	fields := make([]string, cmdbCheckpointFields)
	for index := range fields {
		value, err := readCMDBCheckpointFrame(reader)
		if err != nil {
			return cmdbCheckpoint{}, err
		}
		fields[index] = value
	}
	if reader.Len() != 0 {
		return cmdbCheckpoint{}, providerError("CHECKPOINT_TRAILING_BYTES")
	}

	assetsComplete, err := parseCheckpointBool(fields[12])
	if err != nil {
		return cmdbCheckpoint{}, err
	}
	assetLast, err := decodeOrderPosition(fields[6], fields[7], fields[8])
	if err != nil {
		return cmdbCheckpoint{}, err
	}
	relationLast, err := decodeOrderPosition(fields[9], fields[10], fields[11])
	if err != nil {
		return cmdbCheckpoint{}, err
	}
	checkpoint := cmdbCheckpoint{
		phase:          cmdbPhase(fields[0]),
		authorityID:    fields[1],
		snapshotEpoch:  fields[2],
		environmentID:  fields[3],
		assetCursor:    fields[4],
		relationCursor: fields[5],
		assetLast:      assetLast,
		relationLast:   relationLast,
		assetsComplete: assetsComplete,
	}
	if err := validateCMDBCheckpoint(checkpoint); err != nil {
		return cmdbCheckpoint{}, err
	}
	reencoded, err := encodeCMDBCheckpoint(checkpoint)
	if err != nil {
		return cmdbCheckpoint{}, err
	}
	defer clear(reencoded)
	if subtle.ConstantTimeCompare(reencoded, canonical) != 1 {
		return cmdbCheckpoint{}, providerError("CHECKPOINT_NONCANONICAL")
	}
	return checkpoint, nil
}

func newCMDBCheckpoint(checkpoint cmdbCheckpoint) (discoverysource.Checkpoint, error) {
	if err := validateCMDBCheckpoint(checkpoint); err != nil {
		return discoverysource.Checkpoint{}, err
	}
	canonical, err := encodeCMDBCheckpoint(checkpoint)
	if err != nil {
		return discoverysource.Checkpoint{}, err
	}
	defer clear(canonical)
	return discoverysource.NewCheckpoint(profileCode, canonical)
}

func encodeCMDBCheckpoint(checkpoint cmdbCheckpoint) ([]byte, error) {
	fields := []string{
		string(checkpoint.phase),
		checkpoint.authorityID,
		checkpoint.snapshotEpoch,
		checkpoint.environmentID,
		checkpoint.assetCursor,
		checkpoint.relationCursor,
		encodeOrderTime(checkpoint.assetLast),
		checkpoint.assetLast.externalID,
		checkpoint.assetLast.replaySHA,
		encodeOrderTime(checkpoint.relationLast),
		checkpoint.relationLast.externalID,
		checkpoint.relationLast.replaySHA,
		strconv.FormatBool(checkpoint.assetsComplete),
	}
	var output bytes.Buffer
	_, _ = output.WriteString(cmdbCheckpointDomain)
	for _, field := range fields {
		if len(field) > int(^uint32(0)) {
			return nil, providerError("CHECKPOINT_FIELD_LIMIT")
		}
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = output.Write(length[:])
		_, _ = output.WriteString(field)
	}
	checksum := sha256.Sum256(output.Bytes())
	_, _ = output.Write(checksum[:])
	if output.Len() > discoverysource.MaxCheckpointCanonicalBytes {
		return nil, providerError("CHECKPOINT_LIMIT_REJECTED")
	}
	return output.Bytes(), nil
}

func readCMDBCheckpointFrame(reader *bytes.Reader) (string, error) {
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return "", providerError("CHECKPOINT_FRAME_REJECTED")
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if uint64(length) > uint64(reader.Len()) {
		return "", providerError("CHECKPOINT_FRAME_REJECTED")
	}
	value := make([]byte, int(length))
	if _, err := io.ReadFull(reader, value); err != nil || !utf8.Valid(value) {
		clear(value)
		return "", providerError("CHECKPOINT_FRAME_REJECTED")
	}
	result := string(value)
	clear(value)
	return result, nil
}

func validateCMDBCheckpoint(checkpoint cmdbCheckpoint) error {
	if !safeIdentifier(checkpoint.authorityID) ||
		!safeIdentifier(checkpoint.snapshotEpoch) ||
		!canonicalUUIDPattern.MatchString(checkpoint.environmentID) {
		return providerError("CHECKPOINT_IDENTITY_REJECTED")
	}
	if _, err := newCatalogCursor(checkpoint.assetCursor); err != nil {
		return providerError("CHECKPOINT_ASSET_CURSOR_REJECTED")
	}
	if _, err := newCatalogCursor(checkpoint.relationCursor); err != nil {
		return providerError("CHECKPOINT_RELATION_CURSOR_REJECTED")
	}
	switch checkpoint.phase {
	case cmdbPhaseAssets:
		if checkpoint.assetCursor == "" || !checkpoint.assetLast.present ||
			checkpoint.relationCursor != "" || checkpoint.relationLast.present ||
			checkpoint.assetsComplete {
			return providerError("CHECKPOINT_ASSET_PHASE_REJECTED")
		}
	case cmdbPhaseRelations:
		if checkpoint.assetCursor != "" ||
			checkpoint.relationCursor == "" && checkpoint.relationLast.present ||
			checkpoint.relationCursor != "" && !checkpoint.relationLast.present {
			return providerError("CHECKPOINT_RELATION_PHASE_REJECTED")
		}
	case cmdbPhaseComplete:
		if checkpoint.assetCursor != "" || checkpoint.relationCursor != "" {
			return providerError("CHECKPOINT_COMPLETE_PHASE_REJECTED")
		}
	default:
		return providerError("CHECKPOINT_PHASE_REJECTED")
	}
	return nil
}

func decodeOrderPosition(
	encodedTime string,
	externalID string,
	replaySHA string,
) (cmdbOrderPosition, error) {
	if encodedTime == "" && externalID == "" && replaySHA == "" {
		return cmdbOrderPosition{}, nil
	}
	if !wireTimestampPattern.MatchString(encodedTime) ||
		!safeText(externalID, 1, 512) ||
		unsafeCatalogText(externalID) ||
		!validLowercaseSHA256(replaySHA) {
		return cmdbOrderPosition{}, providerError("CHECKPOINT_ORDER_REJECTED")
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, encodedTime)
	if err != nil {
		return cmdbOrderPosition{}, providerError("CHECKPOINT_ORDER_REJECTED")
	}
	updatedAt, err = normalizedFreshnessTime(updatedAt)
	if err != nil {
		return cmdbOrderPosition{}, providerError("CHECKPOINT_ORDER_REJECTED")
	}
	return cmdbOrderPosition{
		updatedAt:  updatedAt,
		externalID: externalID,
		replaySHA:  replaySHA,
		present:    true,
	}, nil
}

func encodeOrderTime(position cmdbOrderPosition) string {
	if !position.present {
		return ""
	}
	return position.updatedAt.Format(time.RFC3339Nano)
}

func parseCheckpointBool(value string) (bool, error) {
	switch value {
	case "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, providerError("CHECKPOINT_BOOL_REJECTED")
	}
}

func validLowercaseSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return false
	}
	clear(decoded)
	return true
}
