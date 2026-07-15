package assetdiscovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

const (
	maxFactItems         = 10_000
	maxFactRelations     = 50_000
	maxFactDocumentBytes = 64 << 10
	maxFactFingerprints  = 64
)

var (
	ErrFactContractViolation = errors.New("asset discovery fact contract violation")

	canonicalUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	lowercaseDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	providerKindPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	providerPathPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@+\-]{0,127}$`)
	documentFieldPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$`)
	stableReasonPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	credentialValuePattern = regexp.MustCompile(`(?i)(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`)
)

type NormalizedItem struct {
	EnvironmentID   string
	ProviderKind    string
	ExternalID      string
	Kind            assetcatalog.Kind
	DisplayName     string
	SchemaVersion   string
	Document        json.RawMessage
	DocumentSHA256  string
	Freshness       FreshnessCandidate
	FieldProvenance []FieldProvenance
	Tombstone       bool
	TombstoneReason string
	Fingerprints    map[string]string
}

type FreshnessCandidate struct {
	Kind                  assetcatalog.FreshnessKind
	OrderTime             *time.Time
	OrderSequence         int64
	ProviderVersionSHA256 string
}

type FieldProvenance struct {
	FieldCode        string
	ProviderPathCode string
	Ownership        assetcatalog.FieldOwnership
	Confidence       int
}

type ObservedRelation struct {
	SourceEnvironmentID               string
	TargetEnvironmentID               string
	FromExternalID                    string
	ToExternalID                      string
	Type                              assetcatalog.RelationshipType
	ProviderPathCode                  string
	CrossEnvironmentPolicyReferenceID assetcatalog.PolicyReferenceID
	Confidence                        int
	Freshness                         FreshnessCandidate
}

type FactPolicy struct {
	ProviderKind            string
	FreshnessKind           assetcatalog.FreshnessKind
	EnvironmentMapping      assetcatalog.EnvironmentMappingMode
	AuthorityEnvironmentIDs []string
	TrustedPathCodes        []string
	RelationshipTypes       []assetcatalog.RelationshipType
	AllowedDocumentFields   map[assetcatalog.Kind][]string
}

func (policy FactPolicy) Clone() FactPolicy {
	policy.AuthorityEnvironmentIDs = slices.Clone(policy.AuthorityEnvironmentIDs)
	policy.TrustedPathCodes = slices.Clone(policy.TrustedPathCodes)
	policy.RelationshipTypes = slices.Clone(policy.RelationshipTypes)
	policy.AllowedDocumentFields = maps.Clone(policy.AllowedDocumentFields)
	for kind, fields := range policy.AllowedDocumentFields {
		policy.AllowedDocumentFields[kind] = slices.Clone(fields)
	}
	return policy
}

func ValidateFacts(items []NormalizedItem, relations []ObservedRelation, policy FactPolicy) error {
	policy = policy.Clone()
	if err := validateFactPolicy(policy); err != nil {
		return err
	}
	if len(items) > maxFactItems {
		return factContractError("ITEM_LIMIT_EXCEEDED")
	}
	if len(relations) > maxFactRelations {
		return factContractError("RELATION_LIMIT_EXCEEDED")
	}

	itemIdentities := make(map[string]struct{}, len(items))
	for _, item := range items {
		if err := validateNormalizedItem(item, policy); err != nil {
			return err
		}
		identity := item.ProviderKind + "\x00" + item.ExternalID
		if _, duplicate := itemIdentities[identity]; duplicate {
			return factContractError("DUPLICATE_ITEM_IDENTITY")
		}
		itemIdentities[identity] = struct{}{}
	}

	relationIdentities := make(map[string]struct{}, len(relations))
	for _, relation := range relations {
		if err := validateObservedRelation(relation, policy); err != nil {
			return err
		}
		identity := strings.Join([]string{
			relation.SourceEnvironmentID,
			relation.TargetEnvironmentID,
			relation.FromExternalID,
			relation.ToExternalID,
			string(relation.Type),
			relation.ProviderPathCode,
		}, "\x00")
		if _, duplicate := relationIdentities[identity]; duplicate {
			return factContractError("DUPLICATE_RELATION_IDENTITY")
		}
		relationIdentities[identity] = struct{}{}
	}
	return nil
}

func validateFactPolicy(policy FactPolicy) error {
	if !providerKindPattern.MatchString(policy.ProviderKind) || !policy.FreshnessKind.Valid() ||
		!policy.EnvironmentMapping.Valid() {
		return factContractError("INVALID_POLICY")
	}
	if !validSortedUniqueStrings(policy.AuthorityEnvironmentIDs, 1, 100, canonicalUUIDPattern.MatchString) {
		return factContractError("INVALID_POLICY_AUTHORITY")
	}
	if policy.EnvironmentMapping == assetcatalog.EnvironmentMappingSingle && len(policy.AuthorityEnvironmentIDs) != 1 {
		return factContractError("INVALID_POLICY_AUTHORITY")
	}
	if !validSortedUniqueStrings(policy.TrustedPathCodes, 1, 128, validTrustedPathCode) {
		return factContractError("INVALID_POLICY_PATHS")
	}
	if len(policy.RelationshipTypes) > 128 || !slices.IsSortedFunc(policy.RelationshipTypes, compareRelationshipType) {
		return factContractError("INVALID_POLICY_RELATIONSHIPS")
	}
	for index, relationType := range policy.RelationshipTypes {
		if !relationType.Valid() || index > 0 && policy.RelationshipTypes[index-1] == relationType {
			return factContractError("INVALID_POLICY_RELATIONSHIPS")
		}
	}
	if len(policy.AllowedDocumentFields) > 128 {
		return factContractError("INVALID_POLICY_DOCUMENT_FIELDS")
	}
	for kind, fields := range policy.AllowedDocumentFields {
		if !kind.Valid() || !validSortedUniqueStrings(fields, 0, 128, validDocumentField) {
			return factContractError("INVALID_POLICY_DOCUMENT_FIELDS")
		}
	}
	return nil
}

func validateNormalizedItem(item NormalizedItem, policy FactPolicy) error {
	if !canonicalUUIDPattern.MatchString(item.EnvironmentID) || !environmentAllowed(policy, item.EnvironmentID) {
		return factContractError("ITEM_AUTHORITY_MISMATCH")
	}
	if item.ProviderKind != policy.ProviderKind || !providerKindPattern.MatchString(item.ProviderKind) {
		return factContractError("ITEM_PROVIDER_MISMATCH")
	}
	if !validSafeText(item.ExternalID, 1, 512) || sensitiveValue(item.ExternalID) {
		return factContractError("INVALID_ITEM_IDENTITY")
	}
	if err := validateFreshness(item.Freshness, policy.FreshnessKind); err != nil {
		return err
	}

	if item.Tombstone {
		if item.Kind != "" || item.DisplayName != "" || len(item.Document) != 0 || item.DocumentSHA256 != "" ||
			len(item.Fingerprints) != 0 || !stableReasonPattern.MatchString(item.TombstoneReason) {
			return factContractError("INVALID_TOMBSTONE")
		}
		if item.SchemaVersion != "" && !validTrustedPathCode(item.SchemaVersion) {
			return factContractError("INVALID_TOMBSTONE")
		}
		return validateFieldProvenance(item.FieldProvenance, policy, tombstoneProvenanceFields)
	}

	if !item.Kind.Valid() || !validSafeText(item.DisplayName, 1, 256) || sensitiveValue(item.DisplayName) ||
		!validTrustedPathCode(item.SchemaVersion) || item.TombstoneReason != "" {
		return factContractError("INVALID_ITEM_SHAPE")
	}
	allowedFields, found := policy.AllowedDocumentFields[item.Kind]
	if !found {
		return factContractError("ITEM_KIND_NOT_ALLOWED")
	}
	if err := validateDocument(item.Document, item.DocumentSHA256, allowedFields); err != nil {
		return err
	}
	if err := validateFingerprints(item.Fingerprints); err != nil {
		return err
	}
	return validateFieldProvenance(item.FieldProvenance, policy, itemProvenanceFields)
}

func validateObservedRelation(relation ObservedRelation, policy FactPolicy) error {
	if !canonicalUUIDPattern.MatchString(relation.SourceEnvironmentID) ||
		!canonicalUUIDPattern.MatchString(relation.TargetEnvironmentID) ||
		!environmentAllowed(policy, relation.SourceEnvironmentID) ||
		!environmentAllowed(policy, relation.TargetEnvironmentID) {
		return factContractError("RELATION_AUTHORITY_MISMATCH")
	}
	if !validSafeText(relation.FromExternalID, 1, 512) || !validSafeText(relation.ToExternalID, 1, 512) ||
		sensitiveValue(relation.FromExternalID) || sensitiveValue(relation.ToExternalID) ||
		relation.SourceEnvironmentID == relation.TargetEnvironmentID && relation.FromExternalID == relation.ToExternalID {
		return factContractError("INVALID_RELATION_IDENTITY")
	}
	crossEnvironment := relation.SourceEnvironmentID != relation.TargetEnvironmentID
	if crossEnvironment != (relation.CrossEnvironmentPolicyReferenceID != "") ||
		relation.CrossEnvironmentPolicyReferenceID != "" && !relation.CrossEnvironmentPolicyReferenceID.Valid() {
		return factContractError("INVALID_RELATION_POLICY_REFERENCE")
	}
	if !relation.Type.Valid() || !slices.Contains(policy.RelationshipTypes, relation.Type) {
		return factContractError("RELATION_TYPE_NOT_ALLOWED")
	}
	if !validTrustedPathCode(relation.ProviderPathCode) ||
		!slices.Contains(policy.TrustedPathCodes, relation.ProviderPathCode) ||
		relation.Confidence < 0 || relation.Confidence > 100 {
		return factContractError("INVALID_RELATION_PROVENANCE")
	}
	return validateFreshness(relation.Freshness, policy.FreshnessKind)
}

func validateFreshness(candidate FreshnessCandidate, expected assetcatalog.FreshnessKind) error {
	if candidate.Kind != expected || !candidate.Kind.Valid() || candidate.OrderSequence <= 0 ||
		!lowercaseDigestPattern.MatchString(candidate.ProviderVersionSHA256) {
		return factContractError("INVALID_FRESHNESS")
	}
	if candidate.Kind == assetcatalog.FreshnessObjectTimeSequence {
		if candidate.OrderTime == nil || !validStoredTime(*candidate.OrderTime) {
			return factContractError("INVALID_FRESHNESS")
		}
		return nil
	}
	if candidate.OrderTime != nil {
		return factContractError("INVALID_FRESHNESS")
	}
	return nil
}

var catalogFieldCodes = map[string]struct{}{
	"provider_kind":       {},
	"external_id":         {},
	"kind":                {},
	"display_name":        {},
	"owner_group":         {},
	"criticality":         {},
	"data_classification": {},
	"labels":              {},
	"environment_id":      {},
	"lifecycle":           {},
	"mapping_status":      {},
	"type_details":        {},
}

var itemProvenanceFields = []string{
	"display_name",
	"environment_id",
	"external_id",
	"kind",
	"provider_kind",
	"type_details",
}

var tombstoneProvenanceFields = []string{
	"environment_id",
	"external_id",
	"provider_kind",
}

func validateFieldProvenance(values []FieldProvenance, policy FactPolicy, required []string) error {
	if len(values) < len(required) || len(values) > len(catalogFieldCodes) {
		return factContractError("INVALID_FIELD_PROVENANCE")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, allowed := catalogFieldCodes[value.FieldCode]; !allowed || sensitiveName(value.FieldCode) ||
			!validTrustedPathCode(value.ProviderPathCode) ||
			!slices.Contains(policy.TrustedPathCodes, value.ProviderPathCode) ||
			value.Ownership != assetcatalog.FieldOwnershipSource || value.Confidence < 0 || value.Confidence > 100 {
			return factContractError("INVALID_FIELD_PROVENANCE")
		}
		if _, duplicate := seen[value.FieldCode]; duplicate {
			return factContractError("INVALID_FIELD_PROVENANCE")
		}
		seen[value.FieldCode] = struct{}{}
	}
	for _, field := range required {
		if _, present := seen[field]; !present {
			return factContractError("INVALID_FIELD_PROVENANCE")
		}
	}
	return nil
}

func validateDocument(document []byte, encodedDigest string, allowedFields []string) error {
	if len(document) < 2 || len(document) > maxFactDocumentBytes || !utf8.Valid(document) ||
		!lowercaseDigestPattern.MatchString(encodedDigest) || !strictCanonicalJSONObject(document) {
		return factContractError("INVALID_DOCUMENT")
	}
	digest := sha256.Sum256(document)
	if hex.EncodeToString(digest[:]) != encodedDigest {
		return factContractError("INVALID_DOCUMENT_DIGEST")
	}

	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return factContractError("INVALID_DOCUMENT")
	}
	for key := range object {
		if !slices.Contains(allowedFields, key) {
			return factContractError("DOCUMENT_FIELD_NOT_ALLOWED")
		}
	}
	if sensitiveJSON(object) {
		return factContractError("SENSITIVE_DOCUMENT")
	}
	return nil
}

func validateFingerprints(values map[string]string) error {
	if len(values) > maxFactFingerprints {
		return factContractError("INVALID_FINGERPRINTS")
	}
	for key, value := range values {
		if !validSafeText(key, 1, 128) || !providerPathPattern.MatchString(key) || sensitiveName(key) ||
			!validSafeText(value, 1, 512) || sensitiveValue(value) {
			return factContractError("INVALID_FINGERPRINTS")
		}
	}
	return nil
}

func strictCanonicalJSONObject(value []byte) bool {
	if len(value) == 0 || value[0] != '{' || !strictJSONValue(value) {
		return false
	}
	canonical, err := jsoncanonicalizer.Transform(value)
	return err == nil && bytes.Equal(canonical, value)
}

func strictJSONValue(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || !consumeStrictJSONToken(decoder, token, 1) {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeStrictJSONToken(decoder *json.Decoder, token json.Token, depth int) bool {
	if depth > 64 {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			child, err := decoder.Token()
			if err != nil || !consumeStrictJSONToken(decoder, child, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			child, err := decoder.Token()
			if err != nil || !consumeStrictJSONToken(decoder, child, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	}
	return false
}

func sensitiveJSON(value any) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if sensitiveName(key) || sensitiveJSON(child) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if sensitiveJSON(child) {
				return true
			}
		}
	case string:
		return sensitiveValue(item)
	}
	return false
}

func sensitiveName(value string) bool {
	normalized := normalizeSecurityName(value)
	for _, marker := range []string{
		"authorization", "authentication", "apikey", "credential", "secret", "token", "password",
		"passwd", "privatekey", "clientkey", "accesskey", "sessionkey", "cookie", "endpoint", "header", "dsn", "pem",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return normalized == "url" || normalized == "uri" || strings.HasSuffix(normalized, "url") || strings.HasSuffix(normalized, "uri")
}

func sensitiveValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if credentialValuePattern.MatchString(value) {
		return true
	}
	for _, marker := range []string{
		"://", "bearer ", "authorization:", "set-cookie", "private key", "private-key", "private_key", "-----begin",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for index, character := range value {
		if character != ':' && character != '=' {
			continue
		}
		if sensitiveName(value[:index]) {
			return true
		}
	}
	return false
}

func normalizeSecurityName(value string) string {
	var normalized strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(unicode.ToLower(character))
		}
	}
	return normalized.String()
}

func validSortedUniqueStrings(values []string, minimum, maximum int, valid func(string) bool) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validTrustedPathCode(value string) bool {
	return providerPathPattern.MatchString(value) && !sensitiveName(value)
}

func validDocumentField(value string) bool {
	return documentFieldPattern.MatchString(value) && !sensitiveName(value)
}

func validSafeText(value string, minimum, maximum int) bool {
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

func validStoredTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 2000 && value.Year() <= 9999 &&
		value.Nanosecond()%1000 == 0 && value == value.Round(0)
}

func environmentAllowed(policy FactPolicy, environmentID string) bool {
	if policy.EnvironmentMapping == assetcatalog.EnvironmentMappingSingle {
		return len(policy.AuthorityEnvironmentIDs) == 1 && policy.AuthorityEnvironmentIDs[0] == environmentID
	}
	_, found := slices.BinarySearch(policy.AuthorityEnvironmentIDs, environmentID)
	return found
}

func compareRelationshipType(left, right assetcatalog.RelationshipType) int {
	return strings.Compare(string(left), string(right))
}

func factContractError(code string) error {
	return fmt.Errorf("%w: %s", ErrFactContractViolation, code)
}
