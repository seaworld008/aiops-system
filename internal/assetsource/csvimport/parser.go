package csvimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

func Parse(reader io.Reader, limits Limits) (Page, error) {
	return parse(reader, Checkpoint{}, false, limits)
}

func Resume(reader io.Reader, checkpoint Checkpoint, limits Limits) (Page, error) {
	return parse(reader, checkpoint, true, limits)
}

func parse(reader io.Reader, checkpoint Checkpoint, resume bool, limits Limits) (Page, error) {
	effective, authority, err := normalizeLimits(limits)
	if err != nil {
		return Page{}, err
	}
	if reader == nil {
		return Page{}, ErrReadFailure
	}
	if resume && (!lowercaseSHA256.MatchString(checkpoint.FileSHA256) ||
		checkpoint.SchemaVersion != SchemaVersion || checkpoint.RowNumber < 1 ||
		checkpoint.RowNumber > MaxRows+1) {
		return Page{}, ErrCheckpointMismatch
	}

	payload, err := io.ReadAll(io.LimitReader(reader, effective.MaxBytes+1))
	if err != nil {
		return Page{}, ErrReadFailure
	}
	if int64(len(payload)) > effective.MaxBytes {
		return Page{}, ErrLimitExceeded
	}
	if !utf8.Valid(payload) {
		return Page{}, ErrInvalidEncoding
	}
	fileDigest := sha256.Sum256(payload)
	fileSHA256 := hex.EncodeToString(fileDigest[:])
	if resume && checkpoint.FileSHA256 != fileSHA256 {
		return Page{}, ErrCheckpointMismatch
	}

	csvPayload := payload
	if bytes.HasPrefix(csvPayload, []byte(utf8BOM)) {
		csvPayload = csvPayload[len(utf8BOM):]
	}
	if bytes.Contains(csvPayload, []byte(utf8BOM)) {
		return Page{}, ErrInvalidEncoding
	}

	csvReader := csv.NewReader(bytes.NewReader(csvPayload))
	csvReader.FieldsPerRecord = 11
	csvReader.ReuseRecord = false
	header, err := csvReader.Read()
	if err != nil || !slices.Equal(header, strings.Split(Header, ",")) {
		return Page{}, ErrInvalidSchema
	}

	startRow := 1
	if resume {
		startRow = checkpoint.RowNumber
	}
	page := Page{
		Items:     make([]assetdiscovery.NormalizedItem, 0, effective.MaxRowsPerPage),
		Relations: make([]assetdiscovery.ObservedRelation, 0),
	}
	seen := make(map[string]struct{})
	totalRows := 0
	for {
		record, readErr := csvReader.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return Page{}, ErrInvalidSchema
		}
		totalRows++
		if totalRows > MaxRows {
			return Page{}, ErrLimitExceeded
		}
		if err := validateRecordFields(record); err != nil {
			return Page{}, err
		}
		parsed, err := parseRecord(record, authority)
		if err != nil {
			return Page{}, err
		}
		identity := parsed.item.ProviderKind + "\x00" + parsed.item.ExternalID
		if _, duplicate := seen[identity]; duplicate {
			return Page{}, ErrDuplicateObject
		}
		seen[identity] = struct{}{}

		if totalRows < startRow || totalRows >= startRow+effective.MaxRowsPerPage {
			continue
		}
		page.Items = append(page.Items, parsed.item)
		if parsed.relation != nil {
			page.Relations = append(page.Relations, *parsed.relation)
		}
	}
	if resume && !validCheckpointRow(startRow, totalRows, effective.MaxRowsPerPage) {
		return Page{}, ErrCheckpointMismatch
	}

	nextRow := startRow + len(page.Items)
	page.Next = Checkpoint{
		FileSHA256:    fileSHA256,
		SchemaVersion: SchemaVersion,
		RowNumber:     nextRow,
	}
	page.FinalPage = nextRow > totalRows
	return page, nil
}

type parsedRecord struct {
	item     assetdiscovery.NormalizedItem
	relation *assetdiscovery.ObservedRelation
}

func parseRecord(record []string, authority map[string]struct{}) (parsedRecord, error) {
	environmentID := record[0]
	providerKind := record[1]
	externalID := record[2]
	kind := assetcatalog.Kind(record[3])
	displayName := record[4]
	versionText := record[5]
	deletedText := record[6]
	tombstoneReason := record[7]
	relationType := assetcatalog.RelationshipType(record[8])
	targetEnvironmentID := record[9]
	targetExternalID := record[10]

	if !canonicalUUIDPattern.MatchString(environmentID) {
		return parsedRecord{}, ErrInvalidField
	}
	if _, allowed := authority[environmentID]; !allowed {
		return parsedRecord{}, ErrAuthorityMismatch
	}
	if !providerKindPattern.MatchString(providerKind) || providerKind != SchemaVersion ||
		!validSafeText(externalID, 1, MaxFieldBytes) ||
		!canonicalVersion.MatchString(versionText) {
		return parsedRecord{}, ErrInvalidField
	}
	objectVersion, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || objectVersion <= 0 {
		return parsedRecord{}, ErrInvalidField
	}
	if deletedText != "true" && deletedText != "false" {
		return parsedRecord{}, ErrInvalidField
	}

	freshness := assetdiscovery.FreshnessCandidate{
		Kind:                  assetcatalog.FreshnessObjectSequence,
		OrderSequence:         objectVersion,
		ProviderVersionSHA256: framedDigestV1("csv-object-version.v1", versionText),
	}
	item := assetdiscovery.NormalizedItem{
		EnvironmentID: environmentID,
		ProviderKind:  providerKind,
		ExternalID:    externalID,
		SchemaVersion: SchemaVersion,
		Freshness:     freshness,
	}

	if deletedText == "true" {
		if displayName != "" || relationType != "" || targetEnvironmentID != "" || targetExternalID != "" {
			return parsedRecord{}, ErrInvalidTombstone
		}
		if kind != "" && !kind.Valid() {
			return parsedRecord{}, ErrInvalidField
		}
		if !validTombstoneReason(tombstoneReason) {
			return parsedRecord{}, ErrInvalidTombstone
		}
		item.Tombstone = true
		item.TombstoneReason = tombstoneReason
		item.FieldProvenance = tombstoneProvenance()
		return parsedRecord{item: item}, nil
	}

	if !kind.Valid() || !validSafeText(displayName, 1, 256) || tombstoneReason != "" {
		return parsedRecord{}, ErrInvalidField
	}
	item.Kind = kind
	item.DisplayName = displayName
	item.Document = []byte("{}")
	emptyDocumentDigest := sha256.Sum256(item.Document)
	item.DocumentSHA256 = hex.EncodeToString(emptyDocumentDigest[:])
	item.FieldProvenance = itemProvenance()

	relationFields := 0
	for _, value := range []string{string(relationType), targetEnvironmentID, targetExternalID} {
		if value != "" {
			relationFields++
		}
	}
	if relationFields == 0 {
		return parsedRecord{item: item}, nil
	}
	if relationFields != 3 || !relationType.Valid() ||
		!canonicalUUIDPattern.MatchString(targetEnvironmentID) ||
		!validSafeText(targetExternalID, 1, MaxFieldBytes) {
		return parsedRecord{}, ErrInvalidRelation
	}
	if _, allowed := authority[targetEnvironmentID]; !allowed {
		return parsedRecord{}, ErrAuthorityMismatch
	}
	// The 11-column schema has no cross-environment policy reference. Emitting
	// one would invent authorization, so only same-environment relations are
	// valid in this parser slice.
	if targetEnvironmentID != environmentID || targetExternalID == externalID {
		return parsedRecord{}, ErrInvalidRelation
	}
	relation := assetdiscovery.ObservedRelation{
		SourceEnvironmentID: environmentID,
		TargetEnvironmentID: targetEnvironmentID,
		FromExternalID:      externalID,
		ToExternalID:        targetExternalID,
		Type:                relationType,
		ProviderPathCode:    pathRelation,
		Confidence:          100,
		Freshness: assetdiscovery.FreshnessCandidate{
			Kind:          assetcatalog.FreshnessObjectSequence,
			OrderSequence: objectVersion,
			ProviderVersionSHA256: framedDigestV1(
				"csv-relation-version.v1",
				versionText,
				string(relationType),
				targetEnvironmentID,
				targetExternalID,
			),
		},
	}
	return parsedRecord{item: item, relation: &relation}, nil
}

func validCheckpointRow(rowNumber, totalRows, pageSize int) bool {
	if rowNumber < 1 || rowNumber > totalRows+1 {
		return false
	}
	if totalRows == 0 {
		return rowNumber == 1
	}
	if rowNumber == 1 {
		return false
	}
	return rowNumber == totalRows+1 || (rowNumber-1)%pageSize == 0
}

func normalizeLimits(limits Limits) (Limits, map[string]struct{}, error) {
	effective := Limits{
		MaxRowsPerPage:          limits.MaxRowsPerPage,
		MaxBytes:                limits.MaxBytes,
		AuthorityEnvironmentIDs: slices.Clone(limits.AuthorityEnvironmentIDs),
	}
	if effective.MaxRowsPerPage == 0 {
		effective.MaxRowsPerPage = MaxRowsPerPage
	}
	if effective.MaxBytes == 0 {
		effective.MaxBytes = MaxFileBytes
	}
	if effective.MaxRowsPerPage < 1 || effective.MaxRowsPerPage > MaxRowsPerPage ||
		effective.MaxBytes < 1 || effective.MaxBytes > MaxFileBytes ||
		len(effective.AuthorityEnvironmentIDs) < 1 || len(effective.AuthorityEnvironmentIDs) > 100 {
		return Limits{}, nil, ErrLimitExceeded
	}
	if !slices.IsSorted(effective.AuthorityEnvironmentIDs) {
		return Limits{}, nil, ErrAuthorityMismatch
	}
	authority := make(map[string]struct{}, len(effective.AuthorityEnvironmentIDs))
	for _, environmentID := range effective.AuthorityEnvironmentIDs {
		if !canonicalUUIDPattern.MatchString(environmentID) {
			return Limits{}, nil, ErrAuthorityMismatch
		}
		if _, duplicate := authority[environmentID]; duplicate {
			return Limits{}, nil, ErrAuthorityMismatch
		}
		authority[environmentID] = struct{}{}
	}
	return effective, authority, nil
}

func validateRecordFields(record []string) error {
	if len(record) != 11 {
		return ErrInvalidSchema
	}
	for _, field := range record {
		if len(field) > MaxFieldBytes {
			return ErrLimitExceeded
		}
		if !utf8.ValidString(field) {
			return ErrInvalidEncoding
		}
		if unsafeField(field) {
			return ErrUnsafeField
		}
	}
	return nil
}

func unsafeField(value string) bool {
	if strings.ContainsAny(value, "\x00\r\n") {
		return true
	}
	trimmed := strings.TrimSpace(value)
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return true
	}
	lower := strings.ToLower(trimmed)
	if credentialPattern.MatchString(value) {
		return true
	}
	for _, marker := range []string{
		"://",
		"bearer ",
		"authorization:",
		"set-cookie",
		"private key",
		"private-key",
		"private_key",
		"-----begin",
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

func sensitiveName(value string) bool {
	var normalized strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(unicode.ToLower(character))
		}
	}
	name := normalized.String()
	for _, marker := range []string{
		"authorization", "authentication", "apikey", "credential", "secret", "token",
		"password", "passwd", "privatekey", "clientkey", "accesskey", "sessionkey",
		"cookie", "endpoint", "header", "dsn", "pem",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return name == "url" || name == "uri" || strings.HasSuffix(name, "url") || strings.HasSuffix(name, "uri")
}

func validSafeText(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
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

func itemProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		provenance("display_name", pathDisplayName),
		provenance("environment_id", pathEnvironment),
		provenance("external_id", pathExternalID),
		provenance("kind", pathKind),
		provenance("provider_kind", pathProviderKind),
		provenance("type_details", pathTypeDetails),
	}
}

func tombstoneProvenance() []assetdiscovery.FieldProvenance {
	return []assetdiscovery.FieldProvenance{
		provenance("environment_id", pathEnvironment),
		provenance("external_id", pathExternalID),
		provenance("provider_kind", pathProviderKind),
	}
}

func provenance(fieldCode, pathCode string) assetdiscovery.FieldProvenance {
	return assetdiscovery.FieldProvenance{
		FieldCode:        fieldCode,
		ProviderPathCode: pathCode,
		Ownership:        assetcatalog.FieldOwnershipSource,
		Confidence:       100,
	}
}

func framedDigestV1(fields ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, field := range fields {
		_, _ = hash.Write([]byte{1})
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(field))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
