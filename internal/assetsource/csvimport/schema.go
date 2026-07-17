package csvimport

import (
	"errors"
	"regexp"

	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

const (
	SchemaVersion = "CSV_RFC4180_V1"

	MaxFileBytes   int64 = 32 << 20
	MaxRows              = 100_000
	MaxFieldBytes        = 512
	MaxRowsPerPage       = 2_000

	Header  = "environment_id,provider_kind,external_id,kind,display_name,object_version,deleted,tombstone_reason,relation_type,relation_target_environment_id,relation_target_external_id"
	utf8BOM = "\ufeff"

	pathDisplayName  = "CSV_V1_DISPLAY_NAME_COLUMN"
	pathEnvironment  = "CSV_V1_ENVIRONMENT_ID_COLUMN"
	pathExternalID   = "CSV_V1_EXTERNAL_ID_COLUMN"
	pathKind         = "CSV_V1_KIND_COLUMN"
	pathProviderKind = "CSV_V1_PROVIDER_KIND_COLUMN"
	pathRelation     = "CSV_V1_RELATION_COLUMNS"
	pathTypeDetails  = "CSV_V1_TYPE_DETAILS_EMPTY"
)

var (
	ErrInvalidSchema      = errors.New("CSV_SCHEMA_INVALID")
	ErrInvalidEncoding    = errors.New("CSV_ENCODING_INVALID")
	ErrLimitExceeded      = errors.New("CSV_LIMIT_EXCEEDED")
	ErrUnsafeField        = errors.New("CSV_UNSAFE_FIELD")
	ErrInvalidField       = errors.New("CSV_FIELD_INVALID")
	ErrDuplicateObject    = errors.New("CSV_DUPLICATE_OBJECT")
	ErrAuthorityMismatch  = errors.New("CSV_AUTHORITY_MISMATCH")
	ErrInvalidRelation    = errors.New("CSV_RELATION_INVALID")
	ErrInvalidTombstone   = errors.New("CSV_TOMBSTONE_INVALID")
	ErrCheckpointMismatch = errors.New("CSV_CHECKPOINT_MISMATCH")
	ErrReadFailure        = errors.New("CSV_READ_FAILED")

	canonicalUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	providerKindPattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	canonicalVersion     = regexp.MustCompile(`^[1-9][0-9]*$`)
	lowercaseSHA256      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	credentialPattern    = regexp.MustCompile(`(?i)(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`)
)

type Limits struct {
	MaxRowsPerPage          int      `json:"max_rows_per_page"`
	MaxBytes                int64    `json:"max_bytes"`
	AuthorityEnvironmentIDs []string `json:"authority_environment_ids"`
}

type Checkpoint struct {
	FileSHA256    string `json:"file_sha256"`
	SchemaVersion string `json:"schema_version"`
	RowNumber     int    `json:"row_number"`
}

type Page struct {
	Items     []assetdiscovery.NormalizedItem   `json:"items"`
	Relations []assetdiscovery.ObservedRelation `json:"relations"`
	Next      Checkpoint                        `json:"next"`
	FinalPage bool                              `json:"final_page"`
}

func validTombstoneReason(value string) bool {
	switch value {
	case "PROVIDER_DELETED", "PROVIDER_REMOVED", "SOURCE_DELETED":
		return true
	}
	return false
}
